package com.ghostlock.app.domain.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CpuPairHintTest {
    /* An 8-core device's candidate pairs; 8/9 names no real core. */
    private val devicePairs = listOf(CpuPair(0, 1), CpuPair(4, 5), CpuPair(6, 7))
    private val devicePair = CpuPair(4, 5)

    @Test
    fun `a candidate pair differing from the device pick is kept`() {
        assertEquals(CpuPair(6, 7), customCpuPairHint(6, 7, devicePairs, devicePair))
    }

    @Test
    fun `a pair equal to the device pick is dropped`() {
        assertNull(customCpuPairHint(4, 5, devicePairs, devicePair))
    }

    @Test
    fun `a pair beyond the core count is ignored`() {
        assertNull(customCpuPairHint(8, 9, devicePairs, devicePair))
    }

    @Test
    fun `negative and overflowing values are ignored`() {
        assertNull(customCpuPairHint(-1, 0, devicePairs, devicePair))
        assertNull(customCpuPairHint(Long.MAX_VALUE, 0, devicePairs, devicePair))
        assertNull(customCpuPairHint(0, Int.MAX_VALUE.toLong() + 1, devicePairs, devicePair))
    }

    @Test
    fun `an empty candidate list rejects every pair`() {
        assertNull(customCpuPairHint(0, 1, emptyList(), null))
    }
}
