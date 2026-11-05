package com.ghostlock.app.domain.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SupportPolicyTest {
    @Test
    fun `mtk without a resolved pair is not runnable`() {
        assertFalse(physicalPairUsable("Mediatek MT8786", false))
        assertFalse(physicalPairUsable("MT6895", false))
        assertFalse(physicalPairUsable("dimensity 8100", false))
    }

    @Test
    fun `mtk with a resolved pair is runnable`() {
        assertTrue(physicalPairUsable("Mediatek MT8786", true))
    }

    @Test
    fun `qualcomm without a pair keeps the compiled default`() {
        assertTrue(physicalPairUsable("Qualcomm SM8475", false))
        assertTrue(physicalPairUsable("qti sm8750", false))
    }

    @Test
    fun `other families without a pair keep the compiled default`() {
        assertTrue(physicalPairUsable("Google Tensor", false))
        assertTrue(physicalPairUsable("unknown", false))
    }

    @Test
    fun `soc name recognition`() {
        assertTrue(isMediaTekSoc("MediaTek MT8786"))
        assertTrue(isMediaTekSoc("MTK MT6895"))
        assertTrue(isMediaTekSoc("Helio G99"))
        assertFalse(isMediaTekSoc("Qualcomm SM8475"))
        assertFalse(isMediaTekSoc("Google Tensor"))
    }
}
