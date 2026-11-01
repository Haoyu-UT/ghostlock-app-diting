package com.ghostlock.app.ui

import androidx.compose.ui.graphics.Color
import com.ghostlock.app.R

/**
 * The route picker's success-grade chip. This is route-level UI copy, not an
 * extractor fact and not a per-kernel claim: the grade describes the route's
 * delivery mechanism, while the kernel build only decides feasibility and
 * geometry. A route without a clean route-level series is [Unmeasured].
 */
/** A colored dot + short label rendered above a dialog choice. */
interface DialogChip {
    val labelRes: Int
    val color: Color
}

enum class RouteGrade(
    override val labelRes: Int,
    override val color: Color,
) : DialogChip {
    High(R.string.parse_route_grade_high, Color(0xFF2E7D32)),
    Medium(R.string.parse_route_grade_medium, Color(0xFFF9A825)),
    Bad(R.string.parse_route_grade_bad, Color(0xFFC62828)),
    Unmeasured(R.string.parse_route_grade_unmeasured, Color(0xFF757575)),
}
