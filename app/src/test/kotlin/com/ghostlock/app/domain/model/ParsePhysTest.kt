package com.ghostlock.app.domain.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ParsePhysTest {
    private fun state(
        mediaTek: Boolean = false,
        qualcomm: Boolean = false,
        physSource: String? = null,
        offsetPresent: Boolean = false,
        vendorBootOffered: Boolean = false,
        xblOffered: Boolean = false,
        uefiOffered: Boolean = false,
        dtboOffered: Boolean = false,
    ) = PhysPromptState(
        mediaTek = mediaTek,
        qualcomm = qualcomm,
        physSource = physSource,
        offsetPresent = offsetPresent,
        vendorBootOffered = vendorBootOffered,
        xblOffered = xblOffered,
        uefiOffered = uefiOffered,
        dtboOffered = dtboOffered,
    )

    @Test
    fun `mediatek asks for vendor_boot then dtbo until the offset is present`() {
        assertEquals(PhysImage.VENDOR_BOOT, nextPhysImage(state(mediaTek = true)))
        assertEquals(
            PhysImage.DTBO,
            nextPhysImage(state(mediaTek = true, vendorBootOffered = true)),
        )
        assertNull(
            nextPhysImage(state(mediaTek = true, vendorBootOffered = true, dtboOffered = true)),
        )
        assertNull(nextPhysImage(state(mediaTek = true, offsetPresent = true)))
    }

    @Test
    fun `qualcomm asks for xbl then uefi unless a sidecar supplied the load`() {
        assertEquals(PhysImage.XBL, nextPhysImage(state(qualcomm = true)))
        assertEquals(
            PhysImage.UEFI,
            nextPhysImage(state(qualcomm = true, xblOffered = true)),
        )
        assertNull(
            nextPhysImage(state(qualcomm = true, xblOffered = true, uefiOffered = true)),
        )
        assertNull(nextPhysImage(state(qualcomm = true, physSource = "xbl_config FDT")))
        assertNull(nextPhysImage(state(qualcomm = true, physSource = "uefi memory map")))
        // iomem is no longer a load source: a stale source string must still prompt.
        assertEquals(
            PhysImage.XBL,
            nextPhysImage(state(qualcomm = true, physSource = "iomem")),
        )
    }

    @Test
    fun `other platforms get no image advice`() {
        assertNull(nextPhysImage(state()))
    }

    @Test
    fun `phys_source is read from the extractor line`() {
        assertEquals(
            "xbl_config FDT",
            physSourceFromLines(
                listOf("info: kallsyms", "info: phys_source=xbl_config FDT", "info: x"),
            ),
        )
        assertNull(physSourceFromLines(listOf("info: phys_source=unset")))
        assertNull(physSourceFromLines(listOf("info: no source")))
    }
}
