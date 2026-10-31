/*
 * GhostLock — middleware route entry (Batch 4, D1=B slice 3b).
 *
 * Single route write, moved out of the retired procedure; behavior is
 * unchanged (the route policy and race still run inside run_main_route_threads).
 */

#include "route/route_middleware.hpp"

#include "race/threads.hpp"
#include "route/compat_carrier.h"

namespace ghostlock::route::middleware {
    Status run_middleware_route(session::ExploitSession &session,
                                const memory::WriteRequest &request) {
        (void) session;
#if defined(__ANDROID__)
        /* A profile that asks for the AArch32 carrier runs the same dance in
         * the armv7 helper: the kernel write and every kernel address stay on
         * this side of the boundary. See compat_carrier.h. */
        if (compat::carrier_requested()) {
            return compat::run_compat_carrier(request);
        }
#endif
        return race::run_main_route_threads(request);
    }
} // namespace ghostlock::route::middleware
