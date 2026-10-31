package com.ghostlock.app.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class RegionSafetyTest {
    @Test
    fun `the samsung serial array is the only conditional region`() {
        assertEquals(
            RegionSafety.Review,
            RegionSafety.classify("s3c24xx_serial_ports", "in-anchor", "Xiaomi"),
        )
        // A plan can place its scratch in the Samsung region while the anchor
        // is elsewhere; the condition applies to either side.
        assertEquals(
            RegionSafety.Review,
            RegionSafety.classify("__dump_skip.zeroes", "s3c24xx_serial_ports", "OPPO"),
        )
    }

    @Test
    fun `only a samsung device makes that region outright unsafe`() {
        assertEquals(
            RegionSafety.Unsafe,
            RegionSafety.classify("s3c24xx_serial_ports", null, "samsung"),
        )
        assertEquals(
            RegionSafety.Unsafe,
            RegionSafety.classify(null, "s3c24xx_serial_ports", "Samsung"),
        )
    }

    @Test
    fun `every other offered region is safe`() {
        assertEquals(
            RegionSafety.Safe,
            RegionSafety.classify("__dump_skip.zeroes", "in-anchor", "Xiaomi"),
        )
        assertEquals(
            RegionSafety.Safe,
            RegionSafety.classify("bm_pmd", "in-anchor", "samsung"),
        )
        assertEquals(
            RegionSafety.Safe,
            RegionSafety.classify("serial8250_ports", null, "samsung"),
        )
    }
}
