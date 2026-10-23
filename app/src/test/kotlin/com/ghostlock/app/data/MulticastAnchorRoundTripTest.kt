package com.ghostlock.app.data

import com.ghostlock.app.data.profile.CpuPairView
import com.ghostlock.app.data.profile.ProfileMerger
import com.ghostlock.app.data.profile.ProfileResolver
import com.ghostlock.app.data.route.MulticastConfig
import com.ghostlock.app.data.route.RouteConfig
import com.ghostlock.app.data.route.RouteKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Guards `route.multicast_waiter.lock_anchor_*` across the whole Kotlin half of
 * the profile pipeline: merged value map -> `ProfileResolver` -> `Profile` ->
 * GLK1 bytes -> decode. The multicast section carries its own copies of the
 * three keys for the same reason the sigreturn section does -- the decoder
 * never merges across routes, so a multicast profile that borrowed
 * `route.select_stack.lock_anchor_*` would not round-trip.
 *
 * The values below are a synthetic transport vector, not any device's approved
 * anchor: the real trio is per-build profile data and is always stated by the
 * profile, never by code or a test.
 */
class MulticastAnchorRoundTripTest {
    private val release = "5.10.synthetic-anchor-vector"
    private val anchor = 0x400000L
    private val anchorBytes = 0x600L
    private val anchorStride = 0x20L

    /** A document as an imported profile delivers it. */
    private fun document(withAnchor: Boolean): ValueMap {
        val branch = valueMapOf(
            "waiter_off" to 48L,
            "buffer_size" to 264L,
            "task_offset" to 48L,
            "lock_offset" to 56L,
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
            "route" to valueMapOf("multicast_waiter" to branch),
            "fallback" to valueMapOf("to" to "none"),
        )
    }

    /** The advanced-override body the device stores; it carries the same branch. */
    private val overrides = valueMapOf(
        "execution" to valueMapOf("selected_cpus" to valueMapOf("main" to 4L, "consumer" to 5L)),
        "route" to valueMapOf("multicast_waiter" to valueMapOf("waiter_off" to null)),
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
        val route = "multicast_waiter"
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
        val config = profile.document.routeConfig as MulticastConfig

        assertEquals(
            "resolved value must land in the document",
            anchor.toULong(),
            config.geometry.lockAnchorImage,
        )

        val decoded = NativeProfileDocument.fromBinary(profile.toBinary())
        assertNotNull("wire must decode", decoded)
        val wire = (decoded!!.routeConfig as MulticastConfig).geometry
        assertEquals("anchor must survive encode+decode", anchor.toULong(), wire.lockAnchorImage)
        assertEquals("geometry length must survive", anchorBytes.toULong(), wire.lockAnchorBytes)
        assertEquals("geometry stride must survive", anchorStride.toULong(), wire.lockAnchorStride)
        /* The neighbours must be untouched by the new keys. */
        assertEquals(48, wire.waiterOff)
        assertEquals(264u, wire.bufferSize)
        assertEquals(48u, wire.taskOffset)
        assertEquals(56u, wire.lockOffset)
    }

    @Test
    fun `absence keeps the previous behaviour`() {
        val profile = nativeProfile(document(withAnchor = false))
        val config = profile.document.routeConfig as MulticastConfig
        assertEquals(
            "omitted anchor must stay absent, not become 0",
            null,
            config.geometry.lockAnchorImage,
        )
        val decoded = NativeProfileDocument.fromBinary(profile.toBinary())!!
        val wire = (decoded.routeConfig as MulticastConfig).geometry
        /* Absent keys must stay absent: native reads presence as "the anchored
         * route", and a 0 smuggled through here would name a zero-length
         * region (or, for the image, the kernel's own base). */
        assertEquals(null, wire.lockAnchorImage)
        assertEquals(null, wire.lockAnchorBytes)
        assertEquals(null, wire.lockAnchorStride)
    }

    /**
     * The golden profile shape as HOCON text, not a hand-built map: parse ->
     * merge -> resolver -> wire. A key that vanishes in any of those links
     * leaves a profile that validates and runs with the page behaviour.
     */
    @Test
    fun `a golden HOCON profile carries the trio`() {
        val text = """
            release = "$release"
            schema_version = 1
            kernel_major = 5
            route {
              multicast_waiter {
                waiter_off = 48
                buffer_size = 264
                task_offset = 48
                lock_offset = 56
                lock_anchor_image = $anchor
                lock_anchor_bytes = $anchorBytes
                lock_anchor_stride = $anchorStride
              }
            }
            fallback { to = "none" }
        """.trimIndent()
        val parsed = HoconSupport.parseValue(text).asValueMap()
        assertNotNull("the golden profile must parse", parsed)

        val profile = nativeProfile(parsed!!)
        val config = profile.document.routeConfig as MulticastConfig
        assertEquals(anchor.toULong(), config.geometry.lockAnchorImage)
        assertEquals(anchorBytes.toULong(), config.geometry.lockAnchorBytes)
        assertEquals(anchorStride.toULong(), config.geometry.lockAnchorStride)

        val wire = (NativeProfileDocument.fromBinary(profile.toBinary())!!.routeConfig as MulticastConfig)
            .geometry
        assertEquals(anchor.toULong(), wire.lockAnchorImage)
        assertEquals(anchorBytes.toULong(), wire.lockAnchorBytes)
        assertEquals(anchorStride.toULong(), wire.lockAnchorStride)
    }

    @Test
    fun `entries and apply are the same round trip`() {
        val values = mapOf(
            "mcast.waiter_off" to 48L,
            "mcast.buffer_size" to 264L,
            "mcast.task_offset" to 48L,
            "mcast.lock_offset" to 56L,
            "lock_anchor_image" to anchor,
            "lock_anchor_bytes" to anchorBytes,
            "lock_anchor_stride" to anchorStride,
        )
        val config = MulticastConfig.from { values[it] }
        assertEquals(
            "the wire schema must declare exactly the seven keys",
            setOf(
                "waiter_off", "buffer_size", "task_offset", "lock_offset",
                "lock_anchor_image", "lock_anchor_bytes", "lock_anchor_stride",
            ),
            config.keys().toSet(),
        )
        val entries = config.entries().toMap()
        assertEquals(anchor.toULong(), entries["lock_anchor_image"])
        assertEquals(anchorBytes.toULong(), entries["lock_anchor_bytes"])
        assertEquals(anchorStride.toULong(), entries["lock_anchor_stride"])

        var reapplied: RouteConfig = MulticastConfig.EMPTY
        for ((key, value) in config.entries()) reapplied = reapplied.apply(key, value)
        assertEquals("apply must rebuild what entries emitted", config, reapplied)
    }
}
