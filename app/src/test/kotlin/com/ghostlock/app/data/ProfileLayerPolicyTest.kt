package com.ghostlock.app.data

import android.app.Application
import android.content.SharedPreferences
import androidx.core.content.edit
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ProfileConfig
import com.ghostlock.app.domain.repository.ProfileConfigController
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * The measured-db source policy as behaviour: external > builtin > bundled, an
 * unreadable external selection is an error rather than a silent fallback, and
 * a selection only applies to its own release.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ProfileLayerPolicyTest {
    private val context: Application = RuntimeEnvironment.getApplication()
    private val bundledRelease = "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284"

    /** A kernel no profile ships for: an external document is the only source. */
    private val foreignRelease = "6.1.999-android14-11-gdeadbeefcafe-ab99999999"
    private val pair = CpuPair(primary = 0, consumer = 1)
    private val routeWaitPath = "execution.race.route_wait_ms"

    /** The bundled value, i.e. what a run gets when nothing overrides it. */
    private val bundledRouteWaitMs = 30L

    private lateinit var preferences: SharedPreferences
    private lateinit var external: FakeExternalProfileStore
    private lateinit var controller: AndroidProfileConfigController

    @Before
    fun setUp() {
        preferences = context.getSharedPreferences("layer-policy", 0)
            .also { it.edit().clear().commit() }
        external = FakeExternalProfileStore()
        controller = AndroidProfileConfigController(
            context = context,
            externalProfiles = external,
            preferences = preferences,
            buildIdentity = TestBuild,
            /* The bundled 5.10 timing is now a diting default; resolve as the
             * authoring device so the bundled value and the layer assertions
             * stay meaningful. */
            deviceCodename = "diting",
        )
    }

    @Test
    fun `the bundled profile applies by default`() = runBlocking {
        val config = controller.load(bundledRelease, pair)

        assertTrue(config.hasProfile)
        assertEquals(bundledRouteWaitMs, generalValue(config, routeWaitPath))
        val layers = checkNotNull(config.layers)
        assertTrue(layers.bundledAuthoritative)
        assertFalse(layers.builtinSelected)
        assertNull(layers.external)
        assertFalse(layers.hasInactiveLayer)
    }

    @Test
    fun `an external document wins over the bundle for its release`() = runBlocking {
        val uri = external.add(
            "content://profiles/wins.conf",
            document(bundledRelease, routeWaitMs = 4242),
        )
        assertNotNull(controller.selectExternalProfile(uri, bundledRelease, pair))

        val config = controller.load(bundledRelease, pair)

        assertTrue(config.hasProfile)
        assertEquals(4242L, generalValue(config, routeWaitPath))
        val layers = checkNotNull(config.layers)
        assertFalse(layers.bundledAuthoritative)
        assertTrue(layers.externalApplied)
        assertEquals("wins.conf", layers.external)
        assertEquals("wins.conf", controller.activeExternalProfile()?.name)
        assertFalse(layers.hasInactiveLayer)
    }

    @Test
    fun `an external document applies with no bundled profile`() = runBlocking {
        val uri = external.add(
            "content://profiles/foreign.conf",
            document(foreignRelease, routeWaitMs = 4242),
        )
        assertNotNull(controller.selectExternalProfile(uri, foreignRelease, pair))

        val config = controller.load(foreignRelease, pair)

        assertTrue(config.hasProfile)
        assertEquals(4242L, generalValue(config, routeWaitPath))
        val layers = checkNotNull(config.layers)
        assertFalse(layers.bundledAuthoritative)
        assertTrue(layers.externalApplied)
    }

    @Test
    fun `a selected external profile makes its own release supported`() = runBlocking {
        val uri = external.add(
            "content://profiles/foreign.conf",
            document(foreignRelease, routeWaitMs = 4242),
        )
        assertNotNull(controller.selectExternalProfile(uri, foreignRelease, pair))

        val selected = controller.activeExternalProfile()?.release
        assertTrue(releaseSupportedByProfileSources(foreignRelease, emptySet(), selected))
        assertTrue(
            releaseSupportedByProfileSources(
                foreignRelease,
                setOf(bundledRelease),
                selected,
            ),
        )
        assertFalse(releaseSupportedByProfileSources(bundledRelease, emptySet(), selected))
    }

    @Test
    fun `an external selection for another release refuses, not a silent bundle fallback`() = runBlocking {
        val uri = external.add(
            "content://profiles/foreign.conf",
            document(foreignRelease, routeWaitMs = 4242),
        )
        assertNotNull(controller.selectExternalProfile(uri, foreignRelease, pair))

        val config = controller.load(bundledRelease, pair)

        assertFalse(config.hasProfile)
        val layers = checkNotNull(config.layers)
        assertFalse(layers.externalApplied)
        assertNotNull(layers.external)
        assertNotNull(layers.externalError)
        assertTrue(layers.externalError!!.contains("no entry for $bundledRelease"))
        assertTrue(layers.hasInactiveLayer)
    }

    @Test
    fun `an unreadable external selection is an error, not a fallback`() = runBlocking {
        val uri = external.add(
            "content://profiles/wins.conf",
            document(bundledRelease, routeWaitMs = 4242),
        )
        assertNotNull(controller.selectExternalProfile(uri, bundledRelease, pair))
        external.documents.clear()

        val config = controller.load(bundledRelease, pair)

        assertFalse(config.hasProfile)
        val layers = checkNotNull(config.layers)
        assertFalse(layers.externalApplied)
        assertNotNull(layers.externalError)
        assertTrue(layers.hasInactiveLayer)
    }

    @Test
    fun `a hand-picked builtin applies and clears the external selection`() = runBlocking {
        val other = controller.builtinReleases()
            .filterNot { it.endsWith(ProfileConfigController.TemplateSuffix) }
            .first { it != bundledRelease }
        val uri = external.add(
            "content://profiles/wins.conf",
            document(bundledRelease, routeWaitMs = 4242),
        )
        assertNotNull(controller.selectExternalProfile(uri, bundledRelease, pair))

        controller.selectBuiltin(other, bundledRelease, pair)

        assertNull(controller.activeExternalProfile())
        val layers = checkNotNull(controller.load(bundledRelease, pair).layers)
        assertTrue(layers.builtinSelected)
        assertEquals(other, layers.builtinRelease)
    }

    @Test
    fun `nothing resolves for an unknown release`() = runBlocking {
        val config = controller.load("9.9.9-unknown", pair)

        assertFalse(config.hasProfile)
        assertNull(config.layers?.builtinRelease)
        assertNull(config.layers?.external)
    }

    private fun generalValue(config: ProfileConfig, path: String): Long? =
        config.general.firstOrNull { it.path == path }?.value

    /** The bundled profile, re-labelled and edited, as an external file would be. */
    private fun document(release: String, routeWaitMs: Long): String {
        val text = AssetConfigLoader(context).load("kernel_profiles/$bundledRelease.conf")
        check(text.isNotBlank()) { "the bundled profile is missing from the assets" }
        return text
            .replace("release = \"$bundledRelease\"", "release = \"$release\"")
            .replace("route_wait_ms = null", "route_wait_ms = $routeWaitMs")
    }

    @Test
    fun `a compat multicast external profile validates and applies`() = runBlocking {
        val release = "6.1.138-android14-11-g44bda9e8f6e9-ab13792638"
        val uri = external.add("content://profiles/compat.conf", compatMulticastDocument(release))

        assertNotNull(controller.selectExternalProfile(uri, release, pair))
        val config = controller.load(release, pair)

        assertTrue(config.hasProfile)
        assertTrue(config.layers!!.externalApplied)
        /* The 64-bit pair and the 5.x cred reference slots are legitimately
         * absent; the compat geometry replaces them. Nothing may be flagged. */
        assertTrue(config.invalidPaths.toString(), config.invalidPaths.isEmpty())
        assertEquals("multicast_waiter", config.route)
    }

    @Test
    fun `a compat multicast switch without its geometry is refused`() = runBlocking {
        val release = "6.1.138-android14-11-g44bda9e8f6e9-ab13792638"
        val text = compatMulticastDocument(release)
            .replace("compat_waiter_off = 72\n", "")
        val uri = external.add("content://profiles/compat-truncated.conf", text)

        assertNotNull(controller.selectExternalProfile(uri, release, pair))
        val config = controller.load(release, pair)

        assertTrue(config.hasProfile)
        assertTrue(
            "route.multicast_waiter.compat_waiter_off" in config.invalidPaths,
        )
    }

    /**
     * A compat-carrier profile as the extractor renders it: the 64-bit pair
     * absent, the compat geometry present, the 6.x cred template (no 5.x
     * reference slots) and the measured slab stride.
     */
    private fun compatMulticastDocument(release: String): String = """
        include "credential-6_1.conf"
        include "kernelsnitch-6x.conf"
        release = "$release"
        schema_version = 2
        kernel_major = 6
        pipeline = [ "ghostlock" ]
        route {
          multicast_waiter {
            waiter_off = null
            buffer_size = null
            task_offset = 48
            lock_offset = 56
            compact_waiter = 1
            compat_carrier = 1
            compat_futex_abi = 1
            compat_waiter_off = 72
            compat_buffer_size = 260
            lock_anchor_image = 35802320
            lock_anchor_bytes = 4096
            lock_anchor_stride = 32
          }
        }
        fallback {
          to = "none"
        }
        selinux {
          enforcing = 0
          initialized = 2
        }
        w1_scratch {
          image = 35459072
        }
        kernelsnitch {
          mm_struct_sz = 1024
        }
        task_struct {
          prio = 132
          normal_prio = 140
          sched_task_group = 840
          pi_lock = 2340
          pi_waiters = 2360
          pi_top_task = 2376
          pi_blocked_on = 2384
          pid = 1584
          tgid = 1588
          atomic_flags = 1520
          real_cred = 2096
          cred = 2104
          comm = 2120
          tasks = 1360
          seccomp = 2304
        }
        waiter_layout {
          compact = 1
          pi_tree = 24
          task = 48
          lock = 56
          wake_state = 64
        }
        offset {
          init_task = 33486336
          init_cred = 33561192
          empty_zero_page = 35454976
          root_task_group = 35485056
          selinux_enforcing = 35820496
          selinux_blob_sizes = 22768872
          security_hook_heads = 22767064
          slide_nfulnl_logger = 33434056
          slide_loggers_0_1 = 33433880
          slide_boot_id = 35955800
        }
    """.trimIndent()

    private companion object {
        const val TestBuild = "test-build"
    }
}
