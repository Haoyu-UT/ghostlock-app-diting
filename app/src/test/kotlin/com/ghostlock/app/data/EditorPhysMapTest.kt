package com.ghostlock.app.data

import android.app.Application
import androidx.core.content.edit
import com.ghostlock.app.data.profile.PerDevicePhys
import com.ghostlock.app.domain.model.CpuPair
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * The editor export must keep a schema-v2 physical map: the running device's
 * entry takes the edited value, every other device entry survives, and a
 * load-only source (the diting `uefi` case) keeps its `null` offset.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class EditorPhysMapTest {
    private val context: Application = RuntimeEnvironment.getApplication()

    private fun entry(text: String): ValueMap =
        HoconSupport.parseValue(text).asValueMap() ?: error("not a document")

    private fun controller(release: String, device: String): AndroidProfileConfigController =
        AndroidProfileConfigController(
            context = context,
            externalProfiles = FakeExternalProfileStore(),
            preferences = context.getSharedPreferences("editor-phys-$release", 0)
                .also { it.edit().clear().commit() },
            deviceCodename = device,
            overrideStore = MemoryOverrideStore(),
            forcedSelection = ProfileSelection.Bundled(release),
        )

    @Test
    fun `editing the physical load keeps the other devices and exports v2`() = runBlocking {
        val release = "5.10.198-android12-9-00085-g226a9632f13d-ab11136126"
        val pair = CpuPair(4, 5)
        val controller = controller(release, "diting")
        controller.updateAdvanced(release, pair, mapOf("kernel_phys_load" to 0x11223344L))

        val document = entry(controller.renderResolved(release, pair) ?: error("no render"))
        assertEquals(2, (document["schema_version"] as Number).toInt())

        val diting = PerDevicePhys.resolveFor(document, listOf("diting")).document
        assertEquals(0x11223344L, diting["kernel_phys_load"])
        assertEquals(0x80000000L, diting["kernel_phys_offset"])
        val yunluo = PerDevicePhys.resolveFor(document, listOf("yunluo")).document
        assertEquals(0x40000000L, yunluo["kernel_phys_load"])
        assertEquals(0x40000000L, yunluo["kernel_phys_offset"])
        val rubens = PerDevicePhys.resolveFor(document, listOf("rubens")).document
        assertEquals(0x40000000L, rubens["kernel_phys_load"])
        assertEquals(0x40000000L, rubens["kernel_phys_offset"])
    }

    @Test
    fun `editing a device absent from the map adds both entries`() = runBlocking {
        val release = "5.10.101-android12-9-00001-gf4c0e37dbcde-ab8596533"
        val pair = CpuPair(0, 1)
        val controller = controller(release, "diting")
        controller.updateAdvanced(
            release,
            pair,
            mapOf(
                "kernel_phys_load" to 0x55667788L,
                "kernel_phys_offset" to 0x99aabbccL,
            ),
        )

        val document = entry(controller.renderResolved(release, pair) ?: error("no render"))
        assertEquals(2, (document["schema_version"] as Number).toInt())
        val diting = PerDevicePhys.resolveFor(document, listOf("diting")).document
        assertEquals(0x55667788L, diting["kernel_phys_load"])
        assertEquals(0x99aabbccL, diting["kernel_phys_offset"])
        val yunluo = PerDevicePhys.resolveFor(document, listOf("yunluo")).document
        assertEquals(0x40000000L, yunluo["kernel_phys_load"])
        assertEquals(0x40000000L, yunluo["kernel_phys_offset"])
    }

    @Test
    fun `the editor export preserves a load-only physical map`() {
        val release = "5.10.198-android12-9-00085-g226a9632f13d-ab11136126"
        val asset = AssetConfigLoader(context).load("kernel_profiles/$release.conf")
        val raw = HoconSupport.parseValue(asset).asValueMap() ?: error("no bundle")
        raw["kernel_phys_offset"] = null
        val externalText = HoconSupport.render(raw)
        val uri = "content://test/diting-load-only"
        val external = FakeExternalProfileStore().also { it.add(uri, externalText) }
        val controller = AndroidProfileConfigController(
            context = context,
            externalProfiles = external,
            preferences = context.getSharedPreferences("editor-phys-load-only", 0)
                .also { it.edit().clear().commit() },
            deviceCodename = "diting",
            overrideStore = MemoryOverrideStore(),
            forcedSelection = ProfileSelection.External(uri, "load-only.conf", release, "sha"),
        )

        val document = entry(controller.renderResolved(release, CpuPair(4, 5)) ?: error("no render"))
        assertEquals(2, (document["schema_version"] as Number).toInt())
        assertTrue(document["kernel_phys_load"] is Map<*, *>)
        assertNull(document["kernel_phys_offset"])
        val diting = PerDevicePhys.resolveFor(document, listOf("diting")).document
        assertEquals(2818572288L, diting["kernel_phys_load"])
        assertNull(diting["kernel_phys_offset"])
    }
}
