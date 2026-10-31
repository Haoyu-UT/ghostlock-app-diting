#ifndef GHOSTLOCK_COMPAT_CARRIER_H
#define GHOSTLOCK_COMPAT_CARRIER_H

/*
 * The AArch32 compat carrier driver (native side).
 *
 * The 64-bit native owns every kernel address, the anchor allocator and the
 * profile; the armv7 helper (libghostlock32.so, exec'd from the same
 * nativeLibraryDir) owns only the race threads and the _newselect park. This
 * header is the middleware-facing seam; see route/compat_bitmap.h for the
 * bitmap and docs/analysis/compat-select-carrier-plan.md for the design.
 */

#include "memory/payload_builder.h"

namespace ghostlock::route::compat {
    /* True when the resolved profile asked for the compat carrier. */
    [[nodiscard]] bool carrier_requested() noexcept;

    /* Deliver one write through the helper. Same contract as
     * race::run_main_route_threads(): true means a clean attempt whose write
     * the caller then verifies (a clean return is not success). */
    [[nodiscard]] bool run_compat_carrier(const memory::WriteRequest &request);
} // namespace ghostlock::route::compat

#endif
