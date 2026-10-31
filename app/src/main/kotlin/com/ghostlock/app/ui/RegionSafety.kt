package com.ghostlock.app.ui

import androidx.compose.ui.graphics.Color
import com.ghostlock.app.R

/**
 * The safety of a kernel region offered as a page-free anchor or scratch.
 *
 * The Samsung serial port array (`s3c24xx_serial_ports`) is the only region
 * whose safety is device-conditional: it is a dead array on devices without
 * Samsung serial hardware, but on a Samsung device the driver may bind and the
 * array may be live — writing there would corrupt live kernel data. Every other
 * offered region is a zeroed/unused area and is safe.
 */
enum class RegionSafety(override val labelRes: Int, override val color: Color) : DialogChip {
    Safe(R.string.parse_region_safe, Color(0xFF2E7D32)),
    Review(R.string.parse_region_review, Color(0xFFF9A825)),
    Unsafe(R.string.parse_region_unsafe, Color(0xFFC62828)),
    ;

    companion object {
        const val SAMSUNG_REGION = "s3c24xx_serial_ports"

        /**
         * [anchorName] and [scratchSource] come from the option plan; a plan can
         * place its scratch in the same region (`in-anchor`) or in a second one.
         * [manufacturer] is the running device's `Build.MANUFACTURER`; only a
         * Samsung device makes the Samsung region outright unsafe.
         */
        fun classify(
            anchorName: String?,
            scratchSource: String?,
            manufacturer: String?,
        ): RegionSafety {
            val regions = listOfNotNull(anchorName, scratchSource)
            if (regions.any { it == SAMSUNG_REGION }) {
                return if (manufacturer?.equals("samsung", ignoreCase = true) == true) {
                    Unsafe
                } else {
                    Review
                }
            }
            return Safe
        }
    }
}
