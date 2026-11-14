package com.ghostlock.app.ui

/**
 * Route-picker presentation. An option is pinned by exactly two fields: the
 * route and its carrier. Everything else (the waiter shape, the anchor plan,
 * the derived geometry) is detail — it stays in the generation log, not in a
 * row that must also stay readable on a phone.
 *
 * The carrier is the superset's own field: `native` is the 64-bit in-process
 * carrier, `compat` the armv7 helper's 32-bit one. Grades are a route-level
 * mechanism hint, never a per-kernel or per-carrier claim: the kernel build
 * decides feasibility and geometry (the verdict covers both), and does not
 * change a route's delivery mechanism.
 */
object RouteDisplay {
    /** Two fields, nothing else: `<route> (<carrier>)`. */
    fun optionLabel(route: String, carrier: String): String =
        "$route (${carrierLabel(carrier)})"

    private fun carrierLabel(carrier: String): String = when (carrier) {
        "native" -> "64-bit native"
        "compat" -> "32-bit compat"
        /* An unknown carrier fails open in display only: the option was already
         * accepted by the superset's feasibility check. */
        else -> carrier
    }

    /**
     * The route-level grade. It is a property of the route's mechanism, not of
     * the kernel build: the build decides whether the route is feasible and
     * what its geometry is, and the verdict handles both. The measured matrix
     * supports the ordering, but is not encoded per kernel here.
     */
    fun grade(route: String): RouteGrade? = when (route) {
        // select (page-free when the profile carries anchor + scratch), tcp
        // (page-based by construction) and multicast all carry device-backed
        // route series.
        "select_stack", "tcp_zerocopy", "multicast_waiter" -> RouteGrade.High
        // The fpsimd delivery reads ~50-60% across the 5.10.236 series
        // (8/15, 5/12, 6/11, and the 2026-10-31 B cell 6/10 with four
        // reboots); the route-level rate is measured and the failures are real.
        "sigreturn" -> RouteGrade.Medium
        else -> null
    }
}
