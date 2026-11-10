package com.ghostlock.app.data

import android.app.Application
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class DirtyfragProbeMarkerTest {
    private val context: Application = RuntimeEnvironment.getApplication()

    @Test
    fun `a leftover marker is reported as crashed and cleared`() {
        val dir = context.filesDir
        val marker = File(dir, ".df-probe-in-progress")
        marker.writeText("stale")
        val result = DirtyfragProbe.run(context, dir)
        assertEquals(DirtyfragProbe.Outcome.Crashed, result.outcome)
        assertTrue(result.evidence.contains("marker="))
        assertFalse(marker.exists())
    }
}
