package com.ghostlock.app.data

import android.app.Application
import android.content.SharedPreferences
import androidx.core.content.edit
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ProfileConfig
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.nio.file.Files

/**
 * The profile layer policy (PORT-PLAN Phase 8 §B) as behaviour: which layers a
 * run uses, which it deliberately does not, and what survives on disk either
 * way. The cache removal (§F) is here too — it is only observable through the
 * same API.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ProfileLayerPolicyTest {
    private val context: Application = RuntimeEnvironment.getApplication()
    private val bundledRelease = "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284"

    /** A kernel no profile ships for: the imported layer is the only source. */
    private val foreignRelease = "6.1.999-android14-11-gdeadbeefcafe-ab99999999"
    private val pair = CpuPair(primary = 0, consumer = 1)
    private val routeWaitPath = "execution.race.route_wait_ms"

    /** The bundled value, i.e. what a run gets when nothing overrides it. */
    private val bundledRouteWaitMs = 30L

    private lateinit var root: File
    private lateinit var preferences: SharedPreferences
    private lateinit var store: UserProfileStore
    private lateinit var controller: AndroidProfileConfigController

    @Before
    fun setUp() {
        root = Files.createTempDirectory("layer-policy").toFile()
        preferences = context.getSharedPreferences("layer-policy", 0)
            .also { it.edit().clear().commit() }
        store = UserProfileStore(
            directory = root.resolve("user_profiles"),
            assetLoader = AssetConfigLoader(context),
        )
        controller = AndroidProfileConfigController(
            context = context,
            filesDir = root,
            userProfiles = store,
            preferences = preferences,
            buildIdentity = TestBuild,
        )
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    @Test
    fun `a bundled profile supersedes a loaded import`() = runBlocking {
        store.save("foreign.conf", importedDocument(bundledRelease, routeWaitMs = 4242))
        controller.selectUserProfile("foreign.conf", bundledRelease, pair)

        val config = controller.load(bundledRelease, pair)

        assertTrue(config.hasProfile)
        assertEquals(bundledRouteWaitMs, generalValue(config, routeWaitPath))
        val layers = checkNotNull(config.layers)
        assertTrue(layers.bundledAuthoritative)
        assertEquals("foreign.conf", layers.imported)
        assertFalse(layers.importedApplied)
        assertTrue(layers.hasInactiveLayer)
        /* Nothing was deleted: the document is still stored and still listed. */
        assertEquals(listOf("foreign.conf"), store.list().map { it.name })
    }

    @Test
    fun `an import applies when the kernel has no bundled profile`() = runBlocking {
        store.save("foreign.conf", importedDocument(foreignRelease, routeWaitMs = 4242))
        controller.selectUserProfile("foreign.conf", foreignRelease, pair)

        val config = controller.load(foreignRelease, pair)

        assertTrue(config.hasProfile)
        assertEquals(4242L, generalValue(config, routeWaitPath))
        val layers = checkNotNull(config.layers)
        assertFalse(layers.bundledAuthoritative)
        assertTrue(layers.importedApplied)
        assertFalse(layers.hasInactiveLayer)
    }

    @Test
    fun `overrides written by another build are kept but not applied`() = runBlocking {
        seedOverrides(bundledRelease, routeWaitMs = 777, build = "some-older-build")

        val config = controller.load(bundledRelease, pair)

        val layers = checkNotNull(config.layers)
        assertTrue(layers.overridesPresent)
        assertFalse(layers.overridesApplied)
        assertEquals("some-older-build", layers.overridesBuild)
        assertTrue(layers.hasInactiveLayer)
        /* The editor still shows the stored layer, so that saving it re-enables
         * it instead of dropping values the user cannot see. (Execution tuning
         * lives in the general fields, not in the tree.) */
        assertEquals(777L, generalValue(config, routeWaitPath))
        /* What runs is the bundled profile, and the wire is where that shows. */
        val decoded = NativeProfileDocument.fromBinary(
            checkNotNull(controller.nativeDocument(config)),
        )
        assertEquals(bundledRouteWaitMs.toUInt(), decoded?.execution?.raceRouteWaitMs)
        assertTrue(storedOverridesText().contains("777"))
    }

    @Test
    fun `overrides written by this build apply`() = runBlocking {
        seedOverrides(bundledRelease, routeWaitMs = 777, build = TestBuild)

        val config = controller.load(bundledRelease, pair)

        assertEquals(777L, generalValue(config, routeWaitPath))
        assertTrue(checkNotNull(config.layers).overridesApplied)
    }

    /**
     * §C.12b: the start-up notice is raised from the resolution a run uses, so
     * when it is due the layers are **already** inactive on the wire — not
     * scheduled to be. That is what its wording promises, and this is the check
     * that keeps the promise honest.
     */
    @Test
    fun `the start notice is due only when the layers are already off the wire`() = runBlocking {
        seedOverrides(bundledRelease, routeWaitMs = 777, build = "some-older-build")
        store.save("foreign.conf", importedDocument(bundledRelease, routeWaitMs = 4242))
        controller.selectUserProfile("foreign.conf", bundledRelease, pair)

        val config = controller.load(bundledRelease, pair)
        val layers = checkNotNull(config.layers)
        assertTrue(layers.noticeDue(acknowledgedBuild = null))
        /* Both inactive layers are absent from the document native receives:
         * the bundled 30, not the override's 777 nor the import's 4242. */
        val decoded = NativeProfileDocument.fromBinary(
            checkNotNull(controller.nativeDocument(config)),
        )
        assertEquals(bundledRouteWaitMs.toUInt(), decoded?.execution?.raceRouteWaitMs)
        /* And the same object reports it as already acknowledged afterwards. */
        assertFalse(layers.noticeDue(acknowledgedBuild = layers.build))
    }

    @Test
    fun `saving from the editor re-enables a foreign build's overrides`() = runBlocking {
        seedOverrides(bundledRelease, routeWaitMs = 777, build = "some-older-build")

        controller.updateGeneral(bundledRelease, pair, mapOf(routeWaitPath to 123L))
        val config = controller.load(bundledRelease, pair)

        assertEquals(123L, generalValue(config, routeWaitPath))
        val decoded = NativeProfileDocument.fromBinary(
            checkNotNull(controller.nativeDocument(config)),
        )
        assertEquals(123u, decoded?.execution?.raceRouteWaitMs)
        val layers = checkNotNull(config.layers)
        assertTrue(layers.overridesApplied)
        assertFalse(layers.hasInactiveLayer)
        assertEquals(TestBuild, preferences.getString(
            AndroidProfileConfigController.PrefOverridesBuildSha, null,
        ))
    }

    /**
     * The resolved document is rebuilt per call: a cached one was keyed on the
     * release alone while the result also depends on the overrides, the import
     * and the CPU pair (§F).
     */
    @Test
    fun `the native document follows the layers without a reload`() = runBlocking {
        val config = controller.load(bundledRelease, pair)
        val first = checkNotNull(controller.nativeDocument(config))

        controller.updateGeneral(bundledRelease, pair, mapOf(routeWaitPath to 456L))
        val second = checkNotNull(controller.nativeDocument(config))

        assertNotEquals(first.toList(), second.toList())
        val decoded = checkNotNull(NativeProfileDocument.fromBinary(second))
        assertEquals(456u, decoded.execution.raceRouteWaitMs)
        /* Every document the app builds carries the schema digest native checks. */
        assertNotNull(NativeProfileDocument.digestOf(second))
    }

    @Test
    fun `a profile key no wire section declares is reported`() = runBlocking {
        store.save(
            "foreign.conf",
            importedDocument(
                foreignRelease,
                routeWaitMs = 30,
                tail = """
                    route {
                      select_stack {
                        experimental_key = 1
                      }
                    }
                """.trimIndent(),
            ),
        )
        controller.selectUserProfile("foreign.conf", foreignRelease, pair)

        val config = controller.load(foreignRelease, pair)

        assertEquals(listOf("experimental_key"), checkNotNull(config.layers).uncarriedKeys)
    }

    private fun generalValue(config: ProfileConfig, path: String): Long? =
        config.general.firstOrNull { it.path == path }?.value

    /** Writes the sparse override and the build stamp directly, as an older
     * build would have left them (no stamp, or a different one). */
    private fun seedOverrides(release: String, routeWaitMs: Long, build: String?) {
        val override = "{\"$release\": {execution {race {route_wait_ms = $routeWaitMs}}}}"
        preferences.edit {
            putString(AndroidProfileConfigController.PrefDebugProfileOverrides, override)
            if (build == null) {
                remove(AndroidProfileConfigController.PrefOverridesBuildSha)
            } else {
                putString(AndroidProfileConfigController.PrefOverridesBuildSha, build)
            }
        }
    }

    private fun storedOverridesText(): String =
        preferences.getString(AndroidProfileConfigController.PrefDebugProfileOverrides, "").orEmpty()

    /** This fork's bundled profile, re-labelled and edited, as an import would be. */
    private fun importedDocument(release: String, routeWaitMs: Long, tail: String = ""): String {
        val text = AssetConfigLoader(context).load("kernel_profiles/$bundledRelease.conf")
        check(text.isNotBlank()) { "the bundled profile is missing from the assets" }
        return text
            .replace("release = \"$bundledRelease\"", "release = \"$release\"")
            .replace("route_wait_ms = $bundledRouteWaitMs", "route_wait_ms = $routeWaitMs") +
            if (tail.isEmpty()) "" else "\n$tail\n"
    }

    private companion object {
        const val TestBuild = "test-build"
    }
}
