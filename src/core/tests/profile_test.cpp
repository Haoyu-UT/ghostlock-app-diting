#include "profile/model.h"

#include <cstdio>

using namespace ghostlock;

int32_t main(void) {
    profile::kernel_offsets decoded = {
        .route = ghostlock::profile::kRouteMulticastWaiter,
        .meta = {.kernel_major = 5},
        .misc = {.compact_waiter = 1},
        .geometry = {
            .pselect_waiter_shift = 16,
            .mcast_waiter_off = 32,
            .mcast_buffer_size = 128,
            .mcast_task_offset = 40,
            .mcast_lock_offset = 48,
            /* Synthetic vector: the multicast layout reuses the shared anchor
             * storage, so all three travel even though only this route's
             * section stated them. */
            .select_lock_anchor_image = 0x400000,
            .select_lock_anchor_bytes = 0x600,
            .select_lock_anchor_stride = 0x20,
        },
        .execution = {
            .recommended_main_cpu = 2,
            .recommended_consumer_cpu = 3,
            .heap_prepare_max_attempts = 7,
        },
    };
    ghostlock::profile::TargetProfile profile = ghostlock::profile::TargetProfile::from(&decoded);
    decoded.meta.kernel_major = 6;
    decoded.execution.heap_prepare_max_attempts = 99;

    ghostlock::profile::MulticastWaiterLayout multicast =
            profile.multicast_layout();
    ghostlock::profile::SelectStackLayout select = profile.select_stack_layout();
    ghostlock::profile::TcpZerocopyLayout tcp = profile.tcp_zerocopy_layout();
    const profile::execution_settings *execution =
            profile.execution();

    if (!profile.supports(ghostlock::profile::RouteKind::MulticastWaiter) ||
        profile.supports(ghostlock::profile::RouteKind::TcpZerocopy) ||
        profile.supports(ghostlock::profile::RouteKind::SelectStack) ||
        multicast.buffer_size.value_or(0) != 128 ||
        multicast.waiter_offset.value_or(0) != 32 ||
        multicast.lock_anchor_image.value_or(0) != 0x400000 ||
        multicast.lock_anchor_bytes.value_or(0) != 0x600 ||
        multicast.lock_anchor_stride.value_or(0) != 0x20 ||
        select.waiter_shift.value_or(0) != 16 ||
        select.compact_waiter.value_or(0) == 0 ||
        tcp.compact_waiter.value_or(0) == 0 ||
        !execution || execution->heap_prepare_max_attempts != 7) {
        fputs("target profile snapshot/accessor test failed\n", stderr);
        return 1;
    }

    /* The declared route decides, and kRouteAuto selects no chain at all. */
    decoded.route = ghostlock::profile::kRouteTcpZerocopy;
    ghostlock::profile::TargetProfile explicit_tcp = ghostlock::profile::TargetProfile::from(&decoded);
    decoded.route = ghostlock::profile::kRouteSelectStack;
    ghostlock::profile::TargetProfile explicit_select = ghostlock::profile::TargetProfile::from(&decoded);
    decoded.route = ghostlock::profile::kRouteAuto;
    ghostlock::profile::TargetProfile unresolved = ghostlock::profile::TargetProfile::from(&decoded);
    if (!explicit_tcp.supports(ghostlock::profile::RouteKind::TcpZerocopy) ||
        explicit_tcp.supports(ghostlock::profile::RouteKind::MulticastWaiter) ||
        !explicit_select.supports(ghostlock::profile::RouteKind::SelectStack) ||
        explicit_select.supports(ghostlock::profile::RouteKind::TcpZerocopy) ||
        unresolved.supports(ghostlock::profile::RouteKind::MulticastWaiter) ||
        unresolved.supports(ghostlock::profile::RouteKind::TcpZerocopy) ||
        unresolved.supports(ghostlock::profile::RouteKind::SelectStack)) {
        fputs("explicit route selection test failed\n", stderr);
        return 1;
    }

    puts("target profile snapshot/accessor test passed");
    return 0;
}
