package com.ghostlock.app.data

import android.app.Application
import androidx.core.content.edit
import com.ghostlock.app.data.profile.PerDevicePhys
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ProfileConfig
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * Every bundled profile must survive the external-document path in every
 * schema the app still accepts:
 *
 *  - native: the asset exactly as it ships (schema 1 or 2);
 *  - v1: schema 2 scalarised through the running device, which is what the
 *    exporter writes;
 *  - v0: the `remote/main`-era flat JSON, for the 6.x tcp/select kernels that
 *    format can express.
 *
 * The native and v1 legs are lossless: the same document through the bundle
 * and through an external selection must resolve to the same values and the
 * same native bytes. The v0 leg is a projection: it asserts the fields the
 * old format carries (offsets, task struct, mm_struct_sz, physical scalars,
 * compact/pselect geometry) and nothing it cannot express (anchors, cred,
 * execution, selinux, ...).
 *
 * `tools/ship_golden_profiles.py --check` owns the store-to-bundle coverage
 * rule; [BuiltinProfilesTest] owns the bundle's own validity.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ProfileMigrationEquivalenceTest {
    private val context: Application = RuntimeEnvironment.getApplication()
    private val pair = CpuPair(primary = 0, consumer = 1)
    private val loader = AssetConfigLoader(context)

    private data class Entry(val release: String, val file: String)

    @Test
    fun `every bundled profile resolves in its native, v1 and v0 forms`() = runBlocking {
        val entries = bundledEntries()
        assertTrue("index.conf lists no profiles", entries.isNotEmpty())

        for (entry in entries) {
            val nativeText = loader.load("kernel_profiles/${entry.file}")
            val native = checkNotNull(HoconSupport.parseValue(nativeText).asValueMap()) {
                "${entry.release}: bundled profile is not an object"
            }
            val schema = (native["schema_version"] as? Number)?.toInt()
            val device = deviceKey(native) ?: TestDevice
            val baseline = controller("baseline", device)
            val external = FakeExternalProfileStore()
            val imported = controller("imported", device, external)
            val baselineModel = baseline.load(entry.release, pair)

            /* Native schema: the asset exactly as it ships. */
            assertMatchesBundle(
                "${entry.release} (native)", entry.release, nativeText,
                baseline, baselineModel, imported, external,
            )

            /* v1: scalarise the per-device maps exactly as the exporter does. */
            val v1 = if (schema == 2) {
                PerDevicePhys.resolveFor(
                    native.copyValue().asValueMap()!!, listOf(device),
                ).document.also { it["schema_version"] = 1L }
            } else {
                native
            }
            if (schema == 2) {
                assertMatchesBundle(
                    "${entry.release} (v1)", entry.release, HoconSupport.render(v1),
                    baseline, baselineModel, imported, external,
                )
            }

            /* v0: the flat format, only where that format can express it. */
            val route = v1["route"].asValueMap()?.keys?.firstOrNull()
            if ((v1.getLongAt("kernel_major") ?: 0L) == 6L &&
                (route == "select_stack" || route == "tcp_zerocopy")
            ) {
                val v0 = v0Document(v1) ?: continue
                val uri = external.add("content://${entry.release}-v0", HoconSupport.render(v0))
                assertNotNull(
                    "${entry.release} (v0): could not select the document",
                    imported.selectExternalProfile(uri, entry.release, pair),
                )
                val model = imported.load(entry.release, pair)
                assertTrue("${entry.release} (v0): profile did not resolve", model.hasProfile)
                assertEquals(
                    "${entry.release} (v0): invalid fields ${model.invalidPaths}",
                    emptySet<String>(),
                    model.invalidPaths,
                )
                assertEquals("${entry.release} (v0): route", baselineModel.route, model.route)
                assertV0Values(entry.release, v0, model, imported)
            }
        }
    }

    /** The same document through the bundle and through an external selection. */
    private suspend fun assertMatchesBundle(
        label: String,
        release: String,
        text: String,
        baseline: AndroidProfileConfigController,
        baselineModel: ProfileConfig,
        imported: AndroidProfileConfigController,
        external: FakeExternalProfileStore,
    ) {
        val uri = external.add("content://$label", text)
        assertNotNull(
            "$label: could not select the document",
            imported.selectExternalProfile(uri, release, pair),
        )
        val model = imported.load(release, pair)
        assertTrue("$label: profile did not resolve", model.hasProfile)
        assertEquals(
            "$label: invalid fields ${model.invalidPaths}",
            emptySet<String>(),
            model.invalidPaths,
        )
        assertEquals("$label: route", baselineModel.route, model.route)
        assertEquals("$label: fallback", baselineModel.fallbackTo, model.fallbackTo)
        assertEquals(
            "$label: resolved values",
            baseline.resolvedNumbers(release, pair),
            imported.resolvedNumbers(release, pair),
        )
        val baselineNative = checkNotNull(baseline.nativeDocument(baselineModel)) {
            "$label: no bundled native document"
        }
        val importedNative = checkNotNull(imported.nativeDocument(model)) {
            "$label: no external native document"
        }
        assertArrayEquals("$label: native bytes", baselineNative, importedNative)
        val decoded = checkNotNull(Profile.fromBinary(importedNative)) {
            "$label: native document did not decode"
        }
        assertEquals("$label: native release", release, decoded.release)
        assertEquals("$label: native route", baselineModel.route, decoded.route.token)
    }

    /**
     * Projects a v1 document onto the `remote/main` flat format. Returns null
     * when the format cannot express the kernel (not 6.x, a compat-carrier
     * select, or a route other than tcp/select).
     */
    private fun v0Document(v1: ValueMap): ValueMap? {
        val route = v1["route"].asValueMap()?.keys?.firstOrNull() ?: return null
        if (route != "select_stack" && route != "tcp_zerocopy") return null
        val branch = v1["route"].asValueMap()?.get(route).asValueMap() ?: return null
        if (((branch["compat_carrier"] as? Number)?.toLong() ?: 0L) != 0L) return null
        if ((v1.getLongAt("kernel_major") ?: 0L) != 6L) return null

        val id = v1["release"] as? String ?: return null
        val out = valueMapOf("release" to id)
        val symbols = valueMapOf()
        for (field in V0Offsets) {
            v1.getLongAt("offset.$field")?.let { symbols["off_$field"] = it }
        }
        out["symbols"] = symbols
        val task = valueMapOf()
        for (field in V0TaskFields) {
            v1.getLongAt("task_struct.$field")?.let { task["task_$field"] = it }
        }
        out["struct_fields"] = task
        v1.getLongAt("kernelsnitch.mm_struct_sz")?.let { out["mm_struct_sz"] = it }
        for (key in listOf("kernel_phys_load", "kernel_phys_offset")) {
            v1.getLongAt(key)?.let { out[key] = it }
        }
        when (route) {
            "select_stack" -> {
                val shift = v1.getLongAt("route.select_stack.waiter_shift") ?: return null
                out["pselect_waiter_shift"] = shift
            }

            "tcp_zerocopy" -> {
                val compact = v1.getLongAt("route.tcp_zerocopy.compact_waiter") ?: return null
                if (compact == 0L) return null
                out["compact_waiter"] = compact
                val fallback = v1["fallback"].asValueMap()?.get("to") as? String
                if (fallback == "select_stack") {
                    v1.getLongAt("fallback.route.select_stack.waiter_shift")?.let {
                        out["pselect_waiter_shift"] = it
                    }
                }
            }
        }
        return out
    }

    /** Only the values the v0 document states have to survive. */
    private fun assertV0Values(
        release: String,
        v0: ValueMap,
        model: ProfileConfig,
        imported: AndroidProfileConfigController,
    ) {
        val numbers = checkNotNull(imported.resolvedNumbers(release, pair)) {
            "$release (v0): no resolved values"
        }
        for (field in V0Offsets) {
            val expected = v0.getLongAt("symbols.off_$field") ?: continue
            assertEquals("$release (v0): offset.$field", expected, numbers["offset.$field"])
        }
        for (field in V0TaskFields) {
            val expected = v0.getLongAt("struct_fields.task_$field") ?: continue
            assertEquals("$release (v0): task_struct.$field", expected, numbers["task_struct.$field"])
        }
        v0.getLongAt("mm_struct_sz")?.let { expected ->
            assertEquals(
                "$release (v0): kernelsnitch.mm_struct_sz",
                expected,
                numbers["kernelsnitch.mm_struct_sz"],
            )
        }
        for (key in listOf("kernel_phys_load", "kernel_phys_offset")) {
            v0.getLongAt(key)?.let { expected ->
                assertEquals("$release (v0): $key", expected, numbers[key])
            }
        }
        val pselect = v0.getLongAt("pselect_waiter_shift")
        when (model.route) {
            "tcp_zerocopy" -> {
                assertEquals(
                    "$release (v0): fallback",
                    if (pselect != null) "select_stack" else "none",
                    model.fallbackTo,
                )
                pselect?.let { expected ->
                    assertEquals(
                        "$release (v0): fallback select waiter_shift",
                        expected,
                        numbers["fallback.route.select_stack.waiter_shift"],
                    )
                }
            }

            "select_stack" -> {
                assertEquals("$release (v0): fallback", "none", model.fallbackTo)
                val shift = checkNotNull(pselect) { "$release (v0): select route has no waiter_shift" }
                assertEquals(
                    "$release (v0): select waiter_shift",
                    shift,
                    numbers["route.select_stack.waiter_shift"],
                )
            }
        }
        val native = checkNotNull(imported.nativeDocument(model)) {
            "$release (v0): no native document"
        }
        val decoded = checkNotNull(Profile.fromBinary(native)) {
            "$release (v0): native document did not decode"
        }
        assertEquals("$release (v0): native release", release, decoded.release)
        assertEquals("$release (v0): native route", model.route, decoded.route.token)
    }

    private fun bundledEntries(): List<Entry> {
        val index = HoconSupport.parseValue(loader.load("kernel_profiles/index.conf")).asValueMap()
            ?: error("index.conf is not an object")
        return index["profiles"].asValueList().orEmpty()
            .mapNotNull { it.asValueMap() }
            .mapNotNull { entry ->
                val release = entry["release"] as? String ?: return@mapNotNull null
                val file = entry["file"] as? String ?: return@mapNotNull null
                Entry(release, file)
            }
            .filterNot { it.release.endsWith("-template") }
    }

    /** One map key from a v2 document, so the physical pair resolves. */
    private fun deviceKey(document: ValueMap): String? =
        listOf("kernel_phys_load", "kernel_phys_offset")
            .firstNotNullOfOrNull { key ->
                (document[key] as? Map<*, *>)?.keys?.firstOrNull()?.toString()
            }

    private fun controller(
        preferencesName: String,
        device: String,
        external: FakeExternalProfileStore = FakeExternalProfileStore(),
    ): AndroidProfileConfigController =
        AndroidProfileConfigController(
            context = context,
            externalProfiles = external,
            preferences = context.getSharedPreferences(preferencesName, 0)
                .also { it.edit().clear().commit() },
            deviceCodename = device,
            deviceAliases = emptyList(),
        )

    private companion object {
        private const val TestDevice = "test-device"

        /* The symbols/struct_fields the remote/main format carried. */
        private val V0Offsets = listOf(
            "init_task", "init_cred", "root_task_group", "selinux_enforcing",
            "selinux_blob_sizes", "security_hook_heads", "slide_nfulnl_logger",
            "slide_loggers_0_1", "slide_boot_id",
        )
        private val V0TaskFields = listOf(
            "prio", "normal_prio", "sched_task_group", "pi_lock", "pi_waiters",
            "pi_top_task", "pi_blocked_on", "pid", "tgid", "atomic_flags",
            "real_cred", "cred", "comm", "tasks", "seccomp",
        )
    }
}
