#ifndef PI_RACE_H
#define PI_RACE_H

#include "memory/payload_builder.h"
#include "route/route_status.h"
#include "support/native_resource.hpp"

#include <pthread.h>
#include <atomic>
#include <cstdint>

namespace ghostlock::race {
    /* Owns one PI race attempt: the two PI futexes the waiter walks, the three
     * worker threads and the route outcome. The atomics stay public because the
     * route operations read and write them from their hot loops; this class owns
     * the lifecycle that used to be spread across main.cpp helpers: creation
     * order (consumer -> owner -> waiter), the stop signal and the join order
     * (waiter -> owner -> consumer). */
    class PiRace final {
    public:
        PiRace() noexcept = default;

        PiRace(const PiRace &) = delete;

        PiRace &operator=(const PiRace &) = delete;

        ~PiRace() noexcept = default;

        /* All state returns to its reset value. The fast_repair latch is owned by
         * the caller (reset_main_route_state preserves it across resets). */
        [[nodiscard]] bool reset(uint32_t initial_delay_usec, int32_t main_cpu,
                                 int32_t consumer_cpu) noexcept;

        /* consumer -> owner -> waiter, matching the original creation order. On a
         * partial failure every already-started worker is asked to stop and joined
         * before the pthread_create error is returned. */
        [[nodiscard]] int32_t start_threads(void *(*waiter_entry)(void *),
                                        void *(*owner_entry)(void *),
                                        void *(*consumer_entry)(void *),
                                        const ghostlock::memory::WriteRequest *route_request) noexcept;

        /* Waits for the route to finish and returns its outcome. A route that
         * reports Ok without a consumer call and success has not won the race, so
         * the returned outcome degrades to Retryable, matching the bool the
         * previous free function returned. The wait itself is unbounded today:
         * see TODO(pi-timeout-01). */
        [[nodiscard]] ghostlock::route::RouteStatus run() noexcept;

        /* Business stop signal for the three workers; idempotent. */
        void request_stop() noexcept;

        /* waiter -> owner -> consumer join order; idempotent. */
        [[nodiscard]] int32_t join() noexcept;

        /* Testable counter merge used by run(): Ok with zero calls or zero
         * successes is not a routed attempt. */
        [[nodiscard]] static ghostlock::route::RouteStatus outcome_with_counters(
            const ghostlock::route::RouteStatus &outcome, int32_t calls, int32_t success) noexcept;

        /* C atomics cannot carry initializers in C++; static instances are
         * zero-initialized and every dynamic path calls reset() first.
         * Memory order: the hot-path stores/loads keep the original default
         * (sequentially consistent) semantics and reset() keeps the previous
         * relaxed stores. Do not relax either without a dedicated race gate. */
        uint32_t wait_futex = 0;
        uint32_t target_futex = 0;
        uint32_t chain_futex = 0;
        std::atomic<int32_t> waiter_ready;
        std::atomic<int32_t> waiter_waiting;
        std::atomic<int32_t> owner_started;
        std::atomic<int32_t> owner_chain_done;
        std::atomic<int32_t> owner_stop;
        std::atomic<int32_t> route_done;
        std::atomic<int32_t> waiter_tid;
        std::atomic<int32_t> consumer_go;
        std::atomic<int32_t> consumer_stop;
        std::atomic<int32_t> consumer_calls;
        std::atomic<int32_t> consumer_success;
        std::atomic<int32_t> consumer_inflight;
        std::atomic<uint32_t> route_delay_usec;
        std::atomic<int32_t> fast_repair;

        /* LOCAL DIAGNOSTIC (run-18, item 47 follow-up) -- remove with the other
         * LOCAL DIAGNOSTIC blocks before any PR.
         *
         * What it answers: `consumer_calls`/`consumer_success` say how many calls
         * the consumer made and how many returned 0, but nothing about *which
         * syscall a lost call went into*. Run-17's w3c failure (the consumer made
         * one call and then nothing for three attempts) cannot be told apart from
         * a thread that exited, a sleep, or a syscall that never returned. So the
         * consumer writes one record per call -- state 1 (in flight, with the
         * phase it is in) before the first syscall, state 2 (returned, with both
         * returns and errnos) after the last -- and the route thread prints the
         * records once the window has closed. A record still at state 1 there is
         * a call that had not returned: the failure, named.
         *
         * Cost: gated on `consumer_diag_on`, which only the route under
         * measurement sets, so every other route (the select incumbent included)
         * executes exactly one relaxed load more per call and nothing else. */
        struct ConsumerCallDiag {
            std::atomic<int32_t> state;    /* 0 empty, 1 in flight, 2 returned */
            std::atomic<int32_t> phase;    /* 1 sched_setattr, 2 FUTEX_LOCK_PI, 3 FUTEX_UNLOCK_PI */
            std::atomic<int32_t> seq;      /* the consumer_go sequence it belongs to */
            std::atomic<int32_t> index;    /* call index within that sequence */
            std::atomic<int32_t> nice;     /* the nice the call asked for */
            std::atomic<int32_t> sched_ret;
            std::atomic<int32_t> sched_errno;
            std::atomic<int32_t> futex_used; /* the sched_setattr-failure fallback ran */
            std::atomic<int32_t> futex_ret;
            std::atomic<int32_t> futex_errno;
            std::atomic<int64_t> t0_us;    /* before the first syscall */
            std::atomic<int64_t> t1_us;    /* after the last; 0 while in flight */
        };
        static constexpr int32_t kConsumerDiagSlots = 16;
        ConsumerCallDiag consumer_call_diag[kConsumerDiagSlots];
        std::atomic<int32_t> consumer_diag_next; /* monotonic slot allocator */
        std::atomic<int32_t> consumer_diag_on;
        std::atomic<int32_t> consumer_seq_seen; /* last consumer_go the consumer picked up */

        int32_t main_cpu = 0;
        int32_t consumer_cpu = 0;
        ghostlock::support::PthreadOwner waiter_owner;
        ghostlock::support::PthreadOwner owner_owner;
        ghostlock::support::PthreadOwner consumer_owner;
        const ghostlock::memory::WriteRequest *request = nullptr;
        ghostlock::route::RouteStatus route_status{};

    private:
        [[nodiscard]] int32_t abort_startup() noexcept;
    };
} // namespace ghostlock::race

#endif
