package com.ghostlock.app.data

import com.ghostlock.app.domain.model.RunLogState
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The store is the only copy of a run now, so its rules get host tests: what a
 * run writes, which runs survive rotation, which one the picker offers first,
 * and how a run that died is told from one that finished.
 */
class RunLogStoreTest {
    private fun root(): File = Files.createTempDirectory("runs").toFile()

    private fun run(
        root: File,
        stamp: String,
        entry: String = "direct",
        state: RunLogState = RunLogState.COMPLETED,
        lines: List<String> = listOf("<k> line"),
        sidecar: String? = null,
    ) {
        val writer = RunLogStore.open(root, entry, stamp)
        lines.forEach(writer::append)
        sidecar?.let { writer.writeSidecar("profile.conf", it.toByteArray()) }
        writer.finish(state)
        writer.close()
    }

    @Test
    fun `a run keeps its log, its sidecar and the state it ended in`() {
        val root = root()
        run(root, "20261009-212803", entry = "shizuku", sidecar = "release = \"x\"\n")

        val dir = File(root, "20261009-212803")
        assertEquals("<k> line\n", File(dir, RunLogStore.LogName).readText())
        assertEquals("release = \"x\"\n", File(dir, "profile.conf").readText())
        assertEquals(RunLogState.COMPLETED, RunLogStore.readMeta(dir).state)
        assertEquals("shizuku", RunLogStore.readMeta(dir).entry)
    }

    @Test
    fun `rotation keeps the newest ten and deletes the rest`() {
        val root = root()
        for (day in 1..12) {
            run(root, String.format("20261009-%06d", day))
        }
        val kept = root.listFiles()!!.map { it.name }.sorted()
        assertEquals(RunLogStore.Keep, kept.size)
        assertFalse("oldest must be gone", kept.contains("20261009-000001"))
        assertTrue("newest must stay", kept.contains("20261009-000012"))
    }

    @Test
    fun `an unfinished run is marked and offered first`() {
        val root = root()
        run(root, "20261009-100000", state = RunLogState.COMPLETED)
        /* A run leaves `running` behind only when nothing wrote a terminal state. */
        run(root, "20261009-110000", state = RunLogState.RUNNING)
        run(root, "20261009-120000", state = RunLogState.COMPLETED)

        assertEquals(1, RunLogStore.markInterrupted(root))

        val listed = RunLogStore.list(root)
        assertEquals("20261009-110000", listed.first().stamp)
        assertEquals(RunLogState.INTERRUPTED, listed.first().state)
        /* Idempotent: a second pass finds nothing still running. */
        assertEquals(0, RunLogStore.markInterrupted(root))
    }

    @Test
    fun `the export zip carries the run under its own folder`() {
        val root = root()
        run(root, "20261009-212803", sidecar = "release = \"x\"\n")

        val bytes = ByteArrayOutputStream()
        assertTrue(RunLogStore.zip(File(root, "20261009-212803"), bytes))

        val entries = mutableMapOf<String, String>()
        ZipInputStream(bytes.toByteArray().inputStream()).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                entries[entry.name] = zip.readBytes().toString(Charsets.UTF_8)
            }
        }
        assertEquals("<k> line\n", entries["20261009-212803/${RunLogStore.LogName}"])
        assertEquals("release = \"x\"\n", entries["20261009-212803/profile.conf"])
        assertFalse("internal bookkeeping stays out", entries.keys.any { it.endsWith("/meta") })
    }

    @Test
    fun `an unreadable file is skipped, not fatal to the whole report`() {
        /* The root script's dumps land root-owned; on a run where it did not
         * chmod them the app cannot read them. That must cost the dump, not the
         * log -- the log is the whole point of the export. */
        val root = root()
        run(root, "20261009-212803")
        val locked = File(File(root, "20261009-212803"), "kernel-dmesg.log")
        locked.writeText("[    0.000000] Booting Linux\n")
        locked.setReadable(false)
        if (locked.canRead()) return // running as root: the premise cannot hold

        val bytes = ByteArrayOutputStream()
        assertTrue(RunLogStore.zip(File(root, "20261009-212803"), bytes))

        val entries = mutableMapOf<String, String>()
        ZipInputStream(bytes.toByteArray().inputStream()).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                entries[entry.name] = zip.readBytes().toString(Charsets.UTF_8)
            }
        }
        assertTrue(
            "the log must survive",
            entries["20261009-212803/${RunLogStore.LogName}"]?.isNotEmpty() == true,
        )
        assertFalse(
            "the unreadable dump is absent, not present-and-empty",
            entries.keys.any { it.endsWith("kernel-dmesg.log") },
        )
        locked.setReadable(true)
    }

    @Test
    fun `an unknown state reads as interrupted rather than finished`() {
        assertEquals(RunLogState.COMPLETED, RunLogState.fromToken("completed"))
        assertEquals(RunLogState.INTERRUPTED, RunLogState.fromToken(""))
        assertEquals(RunLogState.INTERRUPTED, RunLogState.fromToken("garbage"))
    }
}
