package com.ghostlock.app.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DirtyfragPreflightTest {
    private fun layout(
        execOffset: Long = 0x1000,
        execFilesz: Long = 0x900,
        hook: Long = 0x1800,
        fileLength: Long = 0x4000,
    ) = DirtyfragPlan.CaveLayout(execOffset, execFilesz, hook, fileLength)

    @Test
    fun `a fitting cave passes`() {
        assertTrue(DirtyfragPlan.checkCave(layout(), 420).isEmpty())
    }

    @Test
    fun `a page remainder smaller than the stub is rejected`() {
        val reasons = DirtyfragPlan.checkCave(layout(execFilesz = 0xf00), 420)
        assertTrue(reasons.any { it.contains("cave page remainder") })
    }

    @Test
    fun `a cave at a page boundary is rejected`() {
        val reasons = DirtyfragPlan.checkCave(layout(execFilesz = 0x1000), 420)
        assertTrue(reasons.any { it.contains("page boundary") })
    }

    @Test
    fun `a cave past the file end is rejected`() {
        val reasons = DirtyfragPlan.checkCave(layout(fileLength = 0x1900), 420)
        assertTrue(reasons.any { it.contains("cave outside the file") })
    }

    @Test
    fun `a branch out of the arm64 range is rejected`() {
        val reasons = DirtyfragPlan.checkCave(
            layout(
                execOffset = 0x2000_0000,
                execFilesz = 0x900,
                hook = 0x1000,
                fileLength = 0x2000_2000,
            ),
            420,
        )
        assertTrue(reasons.any { it.contains("hook branch out of range") })
    }

    @Test
    fun `branch fits the signed 26-bit range with 4-byte alignment`() {
        assertTrue(DirtyfragPlan.branchFits(0, 0x7ff_fffc))
        assertFalse(DirtyfragPlan.branchFits(0, 0x800_0000))
        assertTrue(DirtyfragPlan.branchFits(0x800_0000, 0))
        assertFalse(DirtyfragPlan.branchFits(0x800_0004, 0))
        assertFalse(DirtyfragPlan.branchFits(0, 2))
    }
}
