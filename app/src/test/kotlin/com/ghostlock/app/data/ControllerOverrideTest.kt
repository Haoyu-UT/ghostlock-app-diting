package com.ghostlock.app.data

import android.app.Application
import android.content.SharedPreferences
import androidx.core.content.edit
import com.ghostlock.app.domain.model.CpuPair
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
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
 * The editor's in-memory model: edits exist only inside a session, rendering is
 * the export, and the live controller can never write an override layer.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ControllerOverrideTest {
    private val context: Application = RuntimeEnvironment.getApplication()
    private val release = "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284"
    private val pair = CpuPair(primary = 0, consumer = 1)
    private val editPath = "execution.stages.w1_attempts"
    /** `execution-tuning.conf`'s shared default, what the bundle resolves to. */
    private val bundledValue = 15L

    private lateinit var preferences: SharedPreferences
    private lateinit var external: FakeExternalProfileStore
    private lateinit var controller: AndroidProfileConfigController

    @Before
    fun setUp() {
        preferences = context.getSharedPreferences("controller-override", 0)
            .also { it.edit().clear().commit() }
        external = FakeExternalProfileStore()
        controller = sessionController()
    }

    private fun sessionController(): AndroidProfileConfigController =
        AndroidProfileConfigController(
            context = context,
            externalProfiles = external,
            preferences = preferences,
            overrideStore = MemoryOverrideStore(),
            forcedSelection = ProfileSelection.Bundled(release),
        )

    @Test
    fun `session edits resolve and stay out of preferences`() = runBlocking {
        assertEquals(bundledValue, generalValue(controller.load(release, pair), editPath))

        controller.updateGeneral(release, pair, mapOf(editPath to 42L))
        assertEquals(42L, generalValue(controller.load(release, pair), editPath))

        assertNull(
            preferences.getString(AndroidProfileConfigController.PrefDebugProfileOverrides, null),
        )
        assertNull(preferences.getString(AndroidProfileConfigController.PrefOverridesBuildSha, null))

        /* A fresh live controller with the same preferences starts from the
         * document: the session's map does not survive it. */
        val live = AndroidProfileConfigController(
            context = context,
            externalProfiles = external,
            preferences = preferences,
        )
        assertEquals(bundledValue, generalValue(live.load(release, pair), editPath))
    }

    @Test
    fun `the live controller has no persisted edit layer`() = runBlocking {
        val live = AndroidProfileConfigController(
            context = context,
            externalProfiles = external,
            preferences = preferences,
        )
        live.updateGeneral(release, pair, mapOf(editPath to 42L))
        assertEquals(bundledValue, generalValue(live.load(release, pair), editPath))
        assertTrue(live.overrideSnapshot(release).isEmpty())
    }

    @Test
    fun `renderResolved carries the edits as the exported document`() = runBlocking {
        controller.updateGeneral(release, pair, mapOf(editPath to 42L))

        val text = requireNotNull(controller.renderResolved(release, pair))
        val parsed = checkNotNull(HoconSupport.parseValue(text).asValueMap())
        val execution = checkNotNull(parsed["execution"].asValueMap())
        val stages = checkNotNull(execution["stages"].asValueMap())
        assertEquals(42L, (stages["w1_attempts"] as Number).toLong())
        assertNotNull(parsed["release"])
    }

    @Test
    fun `reset drops the edits`() = runBlocking {
        controller.updateGeneral(release, pair, mapOf(editPath to 42L))
        controller.resetGeneral(release, pair)
        assertEquals(bundledValue, generalValue(controller.load(release, pair), editPath))
        assertTrue(controller.overrideSnapshot(release).isEmpty())
    }

    @Test
    fun `advanced edits keep only values that differ from the base`() = runBlocking {
        controller.updateAdvanced(
            release,
            pair,
            mapOf(
                editPath to 42L,
                "task_struct.prio" to 132L,
            ),
        )
        val snapshot = controller.overrideSnapshot(release)
        assertEquals(42L, snapshot.getLongAt(editPath))
        assertNull(snapshot.getLongAt("task_struct.prio"))
    }

    @Test
    fun `diff against the bundle reports the edited field`() = runBlocking {
        controller.updateGeneral(release, pair, mapOf(editPath to 42L))

        val row = controller.diffAgainstBundle(release, pair).firstOrNull { it.path == editPath }

        assertNotNull(row)
        assertEquals(42L, row?.current)
        assertEquals(bundledValue, row?.bundled)
    }

    @Test
    fun `rebase keeps the edits on the bundled base`() = runBlocking {
        controller.updateGeneral(release, pair, mapOf(editPath to 42L))

        controller.rebaseToBundle(release, pair)

        assertEquals(release, controller.currentSelectionLabel(release))
        assertEquals(42L, generalValue(controller.load(release, pair), editPath))
        assertNotNull(
            controller.diffAgainstBundle(release, pair).firstOrNull { it.path == editPath },
        )
    }

    @Test
    fun `renderMerged applies a measured fact and refuses an implausible one`() = runBlocking {
        val text = requireNotNull(
            controller.renderMerged(release, pair, mapOf("kernelsnitch.mm_struct_sz" to 960L)),
        )
        val parsed = checkNotNull(HoconSupport.parseValue(text).asValueMap())
        val snitch = checkNotNull(parsed["kernelsnitch"].asValueMap())
        assertEquals(960L, (snitch["mm_struct_sz"] as Number).toLong())

        assertNull(
            controller.renderMerged(release, pair, mapOf("kernelsnitch.mm_struct_sz" to 7L)),
        )
    }

    @Test
    fun `the cpu pair reaches the native document`() = runBlocking {
        val pair = CpuPair(primary = 2, consumer = 3)
        val config = controller.load(release, pair)
        val decoded = checkNotNull(
            NativeProfileDocument.fromBinary(checkNotNull(controller.nativeDocument(config))),
        )
        assertEquals(2u, decoded.execution.recommendedMainCpu)
        assertEquals(3u, decoded.execution.recommendedConsumerCpu)
    }

    private fun generalValue(
        config: com.ghostlock.app.domain.model.ProfileConfig,
        path: String,
    ): Long? = config.general.firstOrNull { it.path == path }?.value
}
