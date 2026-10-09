package com.ghostlock.app.data

import com.ghostlock.app.data.profile.CpuPairView
import com.ghostlock.app.data.profile.ProfileMerger
import com.ghostlock.app.data.profile.ProfileResolver
import com.ghostlock.app.data.route.RouteKind
import com.ghostlock.app.data.route.SelectConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Guards the `route.select_stack.lock_anchor_*` keys across the whole Kotlin
 * half of the profile pipeline: merged value map -> `ProfileResolver` ->
 * `Profile` -> GLK1 bytes -> decode.
 *
 * These keys have three places where they can vanish silently, and the offset
 * did in the first cut of the feature: `ProfileResolver.nativeValue`
 * (branch-relative lookup), `SelectConfig.from` (merged map -> config) and
 * `SelectConfig.entries` (config -> wire). A drop at any of them leaves a
 * profile that validates, imports and runs, but quietly falls back to the
 * reclaimed payload page -- or, for the geometry keys, to a bound that does not
 * match the region the offset names.
 */
class SelectStackAnchorRoundTripTest {
    private val release = "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284"
    private val anchor = 44279184L // dump_skip.zeroes, image +0x2a3a590
    private val anchorBytes = 0x1000L // one page: the array, not the symbol extent
    private val anchorStride = 0x20L // sizeof(struct rt_mutex), lock debug off

    /** Document as the import delivers it (the batch-D device profile shape). */
    private fun document(withAnchor: Boolean): ValueMap {
        val branch = valueMapOf(
            "waiter_shift" to -2L,
            "compact_waiter" to 1L,
        )
        if (withAnchor) {
            branch["lock_anchor_image"] = anchor
            branch["lock_anchor_bytes"] = anchorBytes
            branch["lock_anchor_stride"] = anchorStride
        }
        return valueMapOf(
            "release" to release,
            "schema_version" to 1L,
            "kernel_major" to 5L,
            "route" to valueMapOf("select_stack" to branch),
            "fallback" to valueMapOf("to" to "none"),
        )
    }

    /** The advanced-override body the device stores; it carries the same branch. */
    private val overrides = valueMapOf(
        "execution" to valueMapOf("selected_cpus" to valueMapOf("main" to 4L, "consumer" to 5L)),
        "route" to valueMapOf("select_stack" to valueMapOf("waiter_shift" to null)),
        "fallback" to valueMapOf("to" to "none"),
    )

    /** Runs the real resolution chain and returns the resolved native document. */
    private fun nativeProfile(document: ValueMap): Profile {
        val merged = ProfileMerger.resolveMerged(
            deviceRelease = release,
            builtin = null,
            imported = document,
            overrides = overrides,
            tuningExecution = null,
            pair = CpuPairView(4, 5),
            routePresets = emptyMap(),
        )
        val route = "select_stack"
        val profile = Profile.fromValueMap(
            release = release,
            route = RouteKind.fromToken(route),
            fallbackTo = RouteKind.fromToken("none"),
        ) { path -> ProfileResolver.nativeValue(merged, route, "none", path) }
        assertNotNull("resolution must produce a document", profile)
        return profile!!
    }

    @Test
    fun `anchor reaches the native document and survives the wire`() {
        val profile = nativeProfile(document(withAnchor = true))

        assertEquals(
            "resolved value must land in the document",
            anchor.toULong(),
            (profile.document.routeConfig as SelectConfig).lockAnchorImage,
        )

        val decoded = NativeProfileDocument.fromBinary(profile.toBinary())
        assertNotNull("wire must decode", decoded)
        val config = decoded!!.routeConfig as SelectConfig
        assertEquals("anchor must survive encode+decode", anchor.toULong(), config.lockAnchorImage)
        assertEquals("geometry length must survive", anchorBytes.toULong(), config.lockAnchorBytes)
        assertEquals("geometry stride must survive", anchorStride.toULong(), config.lockAnchorStride)
        /* The neighbours must be untouched by the new key. */
        assertEquals(-2, config.waiterShift)
        assertEquals(1u.toUByte(), config.compactWaiter)
    }

    @Test
    fun `absence keeps the previous behaviour`() {
        val profile = nativeProfile(document(withAnchor = false))
        assertEquals(
            "omitted anchor must stay absent, not become 0",
            null,
            (profile.document.routeConfig as SelectConfig).lockAnchorImage,
        )
        val decoded = NativeProfileDocument.fromBinary(profile.toBinary())!!
        val config = decoded.routeConfig as SelectConfig
        /* Absent geometry keys must stay absent too: native treats them as "use
         * this build's default grid", and a 0 smuggled through here would be a
         * zero-length region. */
        assertEquals(null, config.lockAnchorImage)
        assertEquals(null, config.lockAnchorBytes)
        assertEquals(null, config.lockAnchorStride)
    }

    @Test
    fun `geometry without an offset is carried but unused`() {
        /* A profile may pin the grid while leaving the anchor to the extractor.
         * The pipeline must not drop either half on the way through. */
        val branch = valueMapOf(
            "waiter_shift" to -2L,
            "lock_anchor_bytes" to anchorBytes,
            "lock_anchor_stride" to anchorStride,
        )
        val doc = valueMapOf(
            "release" to release,
            "schema_version" to 1L,
            "kernel_major" to 5L,
            "route" to valueMapOf("select_stack" to branch),
            "fallback" to valueMapOf("to" to "none"),
        )
        val config = NativeProfileDocument.fromBinary(nativeProfile(doc).toBinary())!!
            .routeConfig as SelectConfig
        assertEquals(null, config.lockAnchorImage)
        assertEquals(anchorBytes.toULong(), config.lockAnchorBytes)
        assertEquals(anchorStride.toULong(), config.lockAnchorStride)
    }
}
