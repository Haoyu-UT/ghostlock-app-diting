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

        /* How long a route gives the consumer's call to come back before it
         * treats the walk as wedged. The measured call is 100-230 ms on the
         * device (era-rate/run-3 records `dur_us=226661`) against a 30 ms stamp
         * window, so this is ~4x the worst measurement; a route that times out
         * stops retrying, and the lifecycle's 2 s disarm still runs afterwards
         * as the last-resort check. */
        static constexpr uint32_t kConsumerDrainMs = 1000;

        /* Close this handshake sequence and wait for the consumer's call to
         * return: the elapsed milliseconds (0 when nothing was in flight), or
         * -1 when the deadline passed with the call still in the kernel.
         *
         * The attempt protocols call this after every stamp window, before they
         * touch this thread's kernel stack again -- the disarm, the post-stamp
         * print and the next attempt's respray all write over the region the
         * in-flight walk reads its fake waiter from
         * (docs/analysis/consumer-stuck-attempt-protocol-plan.md).
         *
         * Userspace only, on purpose: `usleep`/`nanosleep` nests through
         * schedule() -> __switch_to, i.e. exactly the depth that overwrites that
         * region. Closing the sequence is part of the primitive rather than the
         * caller's job: the consumer's `go != seq` tests then stop it from
         * starting a new call, so "inflight == 0" is a settled state and not a
         * gap between two calls. */
        [[nodiscard]] int32_t wait_consumer_idle(uint32_t deadline_ms) noexcept;

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
