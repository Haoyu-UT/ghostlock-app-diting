package com.ghostlock.app.data.profile

import com.ghostlock.app.data.ValueMap
import com.ghostlock.app.data.asValueMap
import com.ghostlock.app.data.valueMapOf
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The exporter resolves a whole index in one process and hands every profile the
 * same tuning/preset maps. `deepMergeValues` writes into the maps it is given, so
 * aliasing a caller's map used to leak the first profile's values into every
 * later one -- measured 2026-10-14 (the diting profile listed first made an
 * unrelated 6.x profile report the diting `route_wait_ms`). These tests pin the
 * contract: resolving never mutates what the caller passed in.
 */
class ProfileMergerSharedInputTest {
    private val tuning: ValueMap = valueMapOf(
        "execution" to valueMapOf("race" to valueMapOf("route_wait_ms" to 1000L)),
    )
    private val presets: Map<String, ValueMap> = mapOf(
        "select_stack" to valueMapOf("enter_delay_us" to 50_000L),
    )

    private fun profile(release: String, routeWaitMs: Long?): ValueMap = valueMapOf(
        "release" to release,
        "kernel_major" to 5L,
        "route" to valueMapOf("select_stack" to valueMapOf("waiter_shift" to 1L)),
        "execution" to (routeWaitMs?.let { valueMapOf("race" to valueMapOf("route_wait_ms" to it)) }
            ?: valueMapOf()),
    )

    private fun ValueMap.routeWaitMs(): Long? =
        this["execution"].asValueMap()?.get("race").asValueMap()?.get("route_wait_ms") as? Long

    @Test
    fun `a profile that sets route_wait_ms does not leak it into the next one`() {
        val diting = profile("diting", routeWaitMs = 30L)
        val other = profile("other", routeWaitMs = null)

        val first = ProfileMerger.resolveMerged(
            deviceRelease = "diting", builtin = diting, imported = null, overrides = null,
            tuningExecution = tuning["execution"].asValueMap(), pair = CpuPairView(0, 1),
            routePresets = presets,
        )
        val second = ProfileMerger.resolveMerged(
            deviceRelease = "other", builtin = other, imported = null, overrides = null,
            tuningExecution = tuning["execution"].asValueMap(), pair = CpuPairView(0, 1),
            routePresets = presets,
        )

        assertEquals(30L, first.routeWaitMs())
        assertEquals(1000L, second.routeWaitMs())
    }

    @Test
    fun `resolving leaves the caller's tuning and presets untouched`() {
        ProfileMerger.resolveMerged(
            deviceRelease = "diting", builtin = profile("diting", routeWaitMs = 30L),
            imported = null, overrides = null,
            tuningExecution = tuning["execution"].asValueMap(), pair = CpuPairView(0, 1),
            routePresets = presets,
        )

        assertEquals(1000L, tuning.routeWaitMs())
        assertEquals(
            50_000L,
            presets.getValue("select_stack").getValue("enter_delay_us"),
        )
    }
}
