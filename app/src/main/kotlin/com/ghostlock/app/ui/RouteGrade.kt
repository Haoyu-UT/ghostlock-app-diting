package com.ghostlock.app.ui

import androidx.compose.ui.graphics.Color
import com.ghostlock.app.R

/**
 * The route picker's success-grade chip. This is route-level UI copy, not an
 * extractor fact; the ordering comes from the 2026-10-31 release matrix
 * (`external/port/release-matrix-2026-10-31/`). A kernel build that has not
 * been device-measured is [Unmeasured], never guessed.
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
