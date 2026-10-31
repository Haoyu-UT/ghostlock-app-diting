package com.ghostlock.app.ui

import androidx.compose.ui.graphics.Color
import com.ghostlock.app.R

/**
 * The route picker's success-grade chip (operator request 2026-10-31): shown
 * only when several routes are offered. This is route-level UI copy, not an
 * extractor fact; the measured ordering is select/multicast high, tcp medium,
 * sigreturn low.
 */
enum class RouteGrade(val labelRes: Int, val color: Color) {
    High(R.string.parse_route_grade_high, Color(0xFF2E7D32)),
    Medium(R.string.parse_route_grade_medium, Color(0xFFF9A825)),
    Bad(R.string.parse_route_grade_bad, Color(0xFFC62828)),
    ;

    companion object {
        fun of(route: String): RouteGrade? = when (route) {
            "select_stack", "multicast_waiter" -> High
            "tcp_zerocopy" -> Medium
            "sigreturn" -> Bad
            else -> null
        }
    }
}
