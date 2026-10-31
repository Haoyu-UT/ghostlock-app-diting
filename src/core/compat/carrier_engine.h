#ifndef GHOSTLOCK_COMPAT_CARRIER_ENGINE_H
#define GHOSTLOCK_COMPAT_CARRIER_ENGINE_H

/*
 * The compat carrier's run mode inside the armv7 helper.
 *
 * One command is one attempt: the engine runs the waiter/owner/consumer dance
 * with the native-packed bitmap, parks the waiter in `_newselect`, drains and
 * disarms, and fills the result counters. It never interprets the bitmap's
 * kernel words and never sees a profile.
 */

#include "compat/carrier_protocol.h"

namespace ghostlock::compat {
    /* Diagnostics go to this fd; the helper duplicates its stdout above the
     * route's parked 0..319 range and installs it here. */
    void set_log_fd(int fd);

    /* Blocking. Fills result->status/step/error_number/select_result/
     * select_errno/calls/successes/drain_ms/userspace_clean/kernel_disarmed.
     * A dirty outcome (status 3) leaves the process safe to exit; the caller
     * writes the result and exits 70 to mirror the native's dirty stop. */
    void run_carrier_attempt(const CarrierCommand &command, CarrierResult *result);
} // namespace ghostlock::compat

#endif
