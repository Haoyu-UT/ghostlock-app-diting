package com.ghostlock.app.data.profile

import com.ghostlock.app.data.valueMapOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Stage-5 foreign-image fixture: the merge may not stamp the device's uname
 * over a document that names another image before comparing them. The identity
 * is checked on the input layers, before the stamp.
 */
class ProfileMergerTest {
    private val device = "6.12.23-android16-5-g5a0e85dd9db0-ab14499855-4k"
    private val foreign = "6.6.66-android15-8-g29d86c5fc9dd-abogki428889875-4k"

    @Test
    fun `a foreign imported profile is wrong_image, not a value dispute`() {
        val imported = valueMapOf(
            "release" to foreign,
            "kernel_major" to 6,
            "execution" to valueMapOf(),
        )
        val error = assertThrows(IllegalArgumentException::class.java) {
            ProfileMerger.resolveMerged(
                deviceRelease = device,
                builtin = null,
                imported = imported,
                overrides = null,
                tuningExecution = null,
                pair = CpuPairView(0, 1),
                routePresets = emptyMap(),
            )
        }
        assertTrue(error.message!!.contains("wrong_image"))
        assertTrue(error.message!!.contains(foreign))
        assertTrue(error.message!!.contains(device))
    }

    @Test
    fun `the page-free stage-1 blocks survive the merge`() {
        val imported = valueMapOf(
            "release" to device,
            "kernel_major" to 6,
            "selinux" to valueMapOf("enforcing" to 0L, "initialized" to 1L),
            "w1_scratch" to valueMapOf("image" to 44279296L),
            "execution" to valueMapOf(),
        )
        val resolved = ProfileMerger.resolveMerged(
            deviceRelease = device,
            builtin = null,
            imported = imported,
            overrides = null,
            tuningExecution = null,
            pair = CpuPairView(0, 1),
            routePresets = emptyMap(),
        )
        assertEquals(valueMapOf("image" to 44279296L), resolved["w1_scratch"])
        assertEquals(valueMapOf("enforcing" to 0L, "initialized" to 1L), resolved["selinux"])
    }

    @Test
    fun `a matching imported profile still merges`() {
        val imported = valueMapOf(
            "release" to device,
            "kernel_major" to 6,
            "execution" to valueMapOf(),
        )
        val resolved = ProfileMerger.resolveMerged(
            deviceRelease = device,
            builtin = null,
            imported = imported,
            overrides = null,
            tuningExecution = null,
            pair = CpuPairView(0, 1),
            routePresets = emptyMap(),
        )
        assertEquals(device, resolved["release"])
    }
}
