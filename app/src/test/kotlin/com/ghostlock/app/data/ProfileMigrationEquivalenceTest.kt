package com.ghostlock.app.data

import android.app.Application
import androidx.core.content.edit
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.repository.ProfileConfigController
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ProfileMigrationEquivalenceTest {
    private val context: Application = RuntimeEnvironment.getApplication()

    @Test
    fun `all remote main 6x profiles resolve identically through an external document`() = runBlocking {
        val legacyJson = checkNotNull(
            javaClass.classLoader?.getResourceAsStream("remote-main-6x-offsets.json"),
        ).bufferedReader().use { it.readText() }
        val legacyEntries = HoconSupport.parseValue(legacyJson).asValueList()
            ?: error("legacy fixture is not a list")
        val legacyReleases = legacyEntries.mapNotNull {
            it.asValueMap()?.get("release") as? String
        }.toSortedSet()

        val baseline = controller(preferencesName = "baseline")
        val external = FakeExternalProfileStore()
        val uri = external.add("content://legacy/remote-main-6x-offsets.json", legacyJson)
        val imported = controller(preferencesName = "imported", external = external)
        val current6x = baseline.builtinReleases()
            .filter { release ->
                !release.endsWith(ProfileConfigController.TemplateSuffix) &&
                    (release.startsWith("6.1.") || release.startsWith("6.6.") ||
                        release.startsWith("6.12."))
            }
            .toSortedSet()

        assertEquals("fixture must cover every current 6.x builtin", current6x, legacyReleases)
        assertEquals("remote/main fixture size", 55, legacyReleases.size)

        val pair = CpuPair(primary = 0, consumer = 1)
        for (release in legacyReleases) {
            /* An external document applies only once it is selected. */
            assertNotNull(
                "could not select the legacy document for $release",
                imported.selectExternalProfile(uri, release, pair),
            )
            val baselineModel = baseline.load(release, pair)
            val baselineNative = baseline.nativeDocument(baselineModel)
            val importedModel = imported.load(release, pair)
            val importedNative = imported.nativeDocument(importedModel)

            assertEquals("resolved ProfileConfig differs for $release", baselineModel, importedModel)
            assertNotNull("baseline native document missing for $release", baselineNative)
            assertNotNull("imported native document missing for $release", importedNative)
            assertArrayEquals(
                "native profile differs for $release",
                baselineNative,
                importedNative,
            )
        }
    }

    private fun controller(
        preferencesName: String,
        external: FakeExternalProfileStore = FakeExternalProfileStore(),
    ): AndroidProfileConfigController =
        AndroidProfileConfigController(
            context = context,
            externalProfiles = external,
            preferences = context.getSharedPreferences(preferencesName, 0)
                .also { it.edit().clear().commit() },
        )
}
