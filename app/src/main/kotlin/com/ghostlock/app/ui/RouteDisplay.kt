package com.ghostlock.app.ui

/**
 * Route-picker presentation. Two independent axes are shown inline after the
 * route name:
 *
 * - the waiter shape (`compact_waiter`): the flat waiter that fits the select
 *   fd_set table (5.x and android14-6.1) vs the rb_node shape (6.6/6.12);
 * - the ABI (`compat_carrier`): the armv7 helper's 32-bit `_newselect` park.
 *
 * They are not the same thing and a profile carries both keys independently.
 * "compact" is a waiter layout, never 32-bit; "compat" is the 32-bit route.
 *
 * Grades are a route-level mechanism hint, never a per-kernel claim: the
 * kernel build decides feasibility and geometry (the verdict covers both), and
 * does not change a route's delivery mechanism.
 */
object RouteDisplay {
    private const val COMPACT = "compact_waiter"
    private const val COMPAT = "compat_carrier"

    fun label(route: String, geometry: Map<String, Long>, release: String?): String {
        val tags = mutableListOf<String>()
        if ((geometry[COMPAT] ?: 0L) != 0L) tags += "32-bit compat"
        when {
            (geometry[COMPACT] ?: 0L) != 0L -> tags += "compact waiter"
            route == "select_stack" && familyOf(release) in NON_COMPACT_FAMILIES ->
                tags += "rb_node waiter"
        }
        if (route == "sigreturn") tags += "64-bit"
        return if (tags.isEmpty()) route else "$route (${tags.joinToString(", ")})"
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

    private val NON_COMPACT_FAMILIES = setOf("6.6", "6.12")

    private fun familyOf(release: String?): String? {
        val parts = release?.split('.') ?: return null
        return if (parts.size >= 2) "${parts[0]}.${parts[1]}" else null
    }
}
