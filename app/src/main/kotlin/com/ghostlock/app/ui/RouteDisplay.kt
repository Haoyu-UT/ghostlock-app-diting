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
 * Grades are the measured completion rates from the 2026-10-31 release matrix;
 * a build that has not been device-measured is [RouteGrade.Unmeasured].
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

    fun grade(route: String, geometry: Map<String, Long>, release: String?): RouteGrade? {
        val compat = (geometry[COMPAT] ?: 0L) != 0L
        val r = release.orEmpty()
        return when (route) {
            "select_stack" -> when {
                compat -> when {
                    // Cell D: 10/10 on the era 5.10.81 rig.
                    r.startsWith("5.10.81-") -> RouteGrade.High
                    // QEMU-only (no ROM on disk); never claim a measured rate.
                    r.startsWith("5.10.101-") -> RouteGrade.Unmeasured
                    r.startsWith("5.10.43-") -> RouteGrade.Unmeasured
                    else -> RouteGrade.Unmeasured
                }
                // Cell A (10/10), G (10/10), H (10/10); I is postponed.
                r.startsWith("5.10.236-") -> RouteGrade.High
                r.startsWith("6.1.138-") -> RouteGrade.High
                r.startsWith("6.6.66-") -> RouteGrade.High
                // Cell I: 10/10 on the page-free 6.12.23 profile.
                r.startsWith("6.12.23-") -> RouteGrade.High
                else -> RouteGrade.Unmeasured
            }
            // Cell F: 10/10; no other family has a measured tcp layout.
            "tcp_zerocopy" -> if (r.startsWith("6.1.138-")) RouteGrade.High
                else RouteGrade.Unmeasured
            // Cell C: 10/10 on the ksun 5.10.236 kernel, the only
            // multicast-feasible image of that release.
            "multicast_waiter" -> if (r.startsWith("5.10.236-")) RouteGrade.High
                else RouteGrade.Unmeasured
            // Cell B: 6/10 on 5.10.236; the shipped 5.10.81/101 sigreturn
            // profiles have no release-build series.
            "sigreturn" -> if (r.startsWith("5.10.236-")) RouteGrade.Medium
                else RouteGrade.Unmeasured
            else -> null
        }
    }

    private val NON_COMPACT_FAMILIES = setOf("6.6", "6.12")

    private fun familyOf(release: String?): String? {
        val parts = release?.split('.') ?: return null
        return if (parts.size >= 2) "${parts[0]}.${parts[1]}" else null
    }
}
