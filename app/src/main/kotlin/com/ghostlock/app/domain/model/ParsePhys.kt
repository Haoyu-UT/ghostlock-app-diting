package com.ghostlock.app.domain.model

/** Images the parse flow can ask for beyond the mandatory boot image. */
enum class PhysImage { VENDOR_BOOT, XBL, UEFI, DTBO }

internal data class PhysPromptState(
    val mediaTek: Boolean,
    val qualcomm: Boolean,
    val physSource: String?,
    val offsetPresent: Boolean,
    val vendorBootOffered: Boolean,
    val xblOffered: Boolean,
    val uefiOffered: Boolean,
    val dtboOffered: Boolean,
)

/**
 * True when the reported source can be trusted for the kernel physical load:
 * `xbl_config` and `uefi` are the Qualcomm image sources, `--phys` is the
 * user's explicit value. `/proc/iomem` is deliberately not a source.
 */
internal fun sourceSuppliesLoad(source: String?): Boolean {
    val text = source?.lowercase().orEmpty()
    return text.contains("xbl_config") || text.contains("uefi") || text.contains("--phys")
}

/**
 * The next image to offer, or null when the platform cannot supply anything
 * more:
 * - MediaTek: the DRAM base must come from vendor_boot's DTB; when it is still
 *   absent, ask for vendor_boot once, then dtbo.
 * - Qualcomm: the load must come from xbl_config/uefi; ask for xbl once, then
 *   uefi.
 * - Other SoCs: nothing is recommended (the extractor derives what it can).
 */
internal fun nextPhysImage(state: PhysPromptState): PhysImage? {
    if (state.mediaTek) {
        return when {
            state.offsetPresent -> null
            !state.vendorBootOffered -> PhysImage.VENDOR_BOOT
            !state.dtboOffered -> PhysImage.DTBO
            else -> null
        }
    }
    if (state.qualcomm) {
        return when {
            sourceSuppliesLoad(state.physSource) -> null
            !state.xblOffered -> PhysImage.XBL
            !state.uefiOffered -> PhysImage.UEFI
            else -> null
        }
    }
    return null
}

/** Reads the extractor's `info: phys_source=…` marker out of the captured log. */
internal fun physSourceFromLines(lines: List<String>): String? =
    lines.firstOrNull { it.contains("phys_source=") }
        ?.substringAfter("phys_source=")
        ?.trim()
        ?.takeIf { it.isNotEmpty() && it != "unset" }
