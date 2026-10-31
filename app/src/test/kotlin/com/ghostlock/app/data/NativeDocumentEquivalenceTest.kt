package com.ghostlock.app.data

import android.app.Application
import androidx.core.content.edit
import com.ghostlock.app.domain.model.CpuPair
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.nio.file.Files
import java.security.MessageDigest

/**
 * Batch 1 wire-equivalence lock: every builtin profile must still produce the
 * exact `NativeProfileDocument.toBinary()` bytes frozen before the refactor
 * (`app/src/test/resources/native-doc-golden.sha256`).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class NativeDocumentEquivalenceTest {
    private val context: Application = RuntimeEnvironment.getApplication()
    private val pair = CpuPair(primary = 0, consumer = 1)

    @Test
    fun `builtin native documents match the frozen golden`() = runBlocking {
        val golden = readGolden()
        assertTrue("golden fixture is empty", golden.isNotEmpty())

        val root = Files.createTempDirectory("native-doc-equivalence").toFile()
        try {
            val controller = AndroidProfileConfigController(
                context = context,
                externalProfiles = FakeExternalProfileStore(),
                preferences = context.getSharedPreferences("native-doc-equivalence", 0)
                    .also { it.edit().clear().commit() },
            )
            val computed = LinkedHashMap<String, String>()
            for ((release, _) in golden) {
                val config = controller.load(release, pair)
                assertTrue("$release did not resolve", config.hasProfile)
                val bytes = controller.nativeDocument(config)
                assertNotNull("$release has no native document", bytes)
                computed[release] = sha256(bytes!!)
            }
            /* Deliberate re-freeze for a schema change: the digest covers every
             * declared key, so adding an absent key moves every document's
             * bytes while changing no value. Set the env var to the resource
             * path to regenerate; a normal run compares. */
            val updatePath = System.getenv("UPDATE_NATIVE_DOC_GOLDEN")
            if (updatePath != null) {
                val stage4Note =
                    "\n# Re-frozen 2026-10-30 (Stage 4): the eight bundled 5.10 profiles carry the\n" +
                    "# page-free blocks -- `selinux` (enforcing 0, initialized 2) and `w1_scratch`\n" +
                    "# (the in-anchor slot on 136/209/226/236; bm_pmd on 81/177/198; the Samsung\n" +
                    "# array's zero gap on 101). Only those eight documents changed."
                val header = goldenHeader().let {
                    if (it.contains("Re-frozen 2026-10-30 (Stage 4)")) it else it + stage4Note
                }
                val rows = computed.entries.joinToString("\n") { "${it.key} ${it.value}" }
                Files.writeString(java.nio.file.Path.of(updatePath), "$header\n$rows\n")
                return@runBlocking
            }
            for ((release, expected) in golden) {
                assertEquals(
                    "$release wire bytes drifted",
                    expected,
                    computed.getValue(release),
                )
            }
        } finally {
            root.deleteRecursively()
        }
    }

    private fun readGolden(): Map<String, String> {
        val text = checkNotNull(
            javaClass.classLoader?.getResourceAsStream("native-doc-golden.sha256"),
        ).bufferedReader().use { it.readText() }
        return text.lineSequence()
            .filter { it.isNotBlank() && !it.trimStart().startsWith("#") }
            .associate { line ->
                val parts = line.trim().split(' ')
                parts[0] to parts[1]
            }
    }

    /** The comment block currently in the resource, preserved across a re-freeze. */
    private fun goldenHeader(): String =
        checkNotNull(
            javaClass.classLoader?.getResourceAsStream("native-doc-golden.sha256"),
        ).bufferedReader().use { reader ->
            reader.readText().lineSequence()
                .filter { it.trimStart().startsWith("#") }
                .joinToString("\n")
        }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
}
