package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PipelineResolverTest {
    @Test
    fun `the first viable entry wins and earlier rejections are reported`() {
        var dirtyfragCalls = 0
        val decision = PipelineResolver.resolve(
            listOf("dirtyfrag", "ghostlock"),
            ghostlock = { null },
            dirtyfrag = {
                dirtyfragCalls++
                "probe failed"
            },
        )
        assertEquals("ghostlock", decision.pipeline)
        assertEquals(1, dirtyfragCalls)
        assertEquals(listOf("dirtyfrag: probe failed"), decision.rejected)
    }

    @Test
    fun `a viable first entry never evaluates the fallback`() {
        var ghostlockCalls = 0
        val decision = PipelineResolver.resolve(
            listOf("dirtyfrag", "ghostlock"),
            ghostlock = {
                ghostlockCalls++
                null
            },
            dirtyfrag = { null },
        )
        assertEquals("dirtyfrag", decision.pipeline)
        assertEquals(0, ghostlockCalls)
        assertTrue(decision.rejected.isEmpty())
    }

    @Test
    fun `a strict list refuses when its only entry fails`() {
        val decision = PipelineResolver.resolve(
            listOf("dirtyfrag"),
            ghostlock = { error("must not run") },
            dirtyfrag = { "measured DB says the primitive does not land" },
        )
        assertNull(decision.pipeline)
        assertEquals(
            listOf("dirtyfrag: measured DB says the primitive does not land"),
            decision.rejected,
        )
    }

    @Test
    fun `an empty order refuses with no rejection list`() {
        val decision = PipelineResolver.resolve(
            emptyList(),
            ghostlock = { error("must not run") },
            dirtyfrag = { error("must not run") },
        )
        assertNull(decision.pipeline)
        assertTrue(decision.rejected.isEmpty())
    }

    @Test
    fun `an unknown entry is rejected, not skipped silently`() {
        val decision = PipelineResolver.resolve(
            listOf("future_pipeline", "ghostlock"),
            ghostlock = { null },
            dirtyfrag = { null },
        )
        assertEquals("ghostlock", decision.pipeline)
        assertEquals(listOf("future_pipeline: unknown pipeline"), decision.rejected)
    }

    @Test
    fun `the ghostlock-first order keeps ghostlock even when dirtyfrag would pass`() {
        var dirtyfragCalls = 0
        val decision = PipelineResolver.resolve(
            listOf("ghostlock", "dirtyfrag"),
            ghostlock = { null },
            dirtyfrag = {
                dirtyfragCalls++
                null
            },
        )
        assertEquals("ghostlock", decision.pipeline)
        assertEquals(0, dirtyfragCalls)
    }
}
