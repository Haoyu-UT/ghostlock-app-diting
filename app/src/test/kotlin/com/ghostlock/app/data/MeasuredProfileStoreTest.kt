package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class MeasuredProfileStoreTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private val release = "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284"

    private fun capture(
        releaseLine: String = release,
        slabLine: String = "mm_struct 1234 1300 960 34 8 : tunables 0 0 0 : slabdata 39 39 0",
    ): String = "# $releaseLine\n$slabLine\n"

    private fun newStore(name: String = "measured_profiles.conf"): MeasuredProfileStore =
        MeasuredProfileStore(File(temporaryFolder.root, name))

    @Test
    fun `parses the root capture into the stride fact`() {
        val fact = MeasuredProfileStore.parseSlabinfo(release, capture(), now = 42L)
        assertNotNull(fact)
        assertEquals(MeasuredProfileStore.KeyMmStructSz, fact!!.key)
        assertEquals(960L, fact.value)
        assertEquals(MeasuredProfileStore.SourceRootSlabinfo, fact.source)
        assertTrue(fact.evidence.startsWith("mm_struct "))
        assertEquals(42L, fact.measuredAt)
    }

    @Test
    fun `refuses a capture from another kernel`() {
        assertNull(MeasuredProfileStore.parseSlabinfo(release, capture(releaseLine = "5.10.81")))
    }

    @Test
    fun `refuses a capture without the mm_struct line`() {
        val raw = "# $release\ncred_jar 100 100 192 42 2 : tunables 0 0 0\n"
        assertNull(MeasuredProfileStore.parseSlabinfo(release, raw))
    }

    @Test
    fun `refuses an implausible object size`() {
        val raw = capture(slabLine = "mm_struct 1 1 7 34 8 : tunables 0 0 0")
        assertNull(MeasuredProfileStore.parseSlabinfo(release, raw))
    }

    @Test
    fun `records and reloads a fact`() {
        val store = newStore()
        val fact = MeasuredProfileStore.parseSlabinfo(release, capture(), now = 7L)!!
        assertTrue(store.record(release, fact))

        val reloaded = newStore().kernel(release)
        assertNotNull(reloaded)
        assertEquals(7L, reloaded!!.updatedAt)
        val loadedFact = reloaded.fact(MeasuredProfileStore.KeyMmStructSz)
        assertNotNull(loadedFact)
        assertEquals(960L, loadedFact!!.value)
        assertEquals(MeasuredProfileStore.SourceRootSlabinfo, loadedFact.source)
        assertTrue(loadedFact.evidence.contains("mm_struct"))
    }

    @Test
    fun `a second measurement replaces the same key`() {
        val store = newStore()
        store.record(release, MeasuredProfileStore.parseSlabinfo(release, capture(), now = 1L)!!)
        val second = MeasuredProfileStore.parseSlabinfo(
            release,
            capture(slabLine = "mm_struct 10 20 1024 32 8 : tunables 0 0 0"),
            now = 2L,
        )!!
        assertTrue(store.record(release, second))

        val kernel = store.kernel(release)!!
        assertEquals(1, kernel.facts.size)
        assertEquals(1024L, kernel.facts.single().value)
        assertEquals(2L, kernel.updatedAt)
    }

    @Test
    fun `keeps kernels independent`() {
        val store = newStore()
        store.record(release, MeasuredProfileStore.parseSlabinfo(release, capture(), now = 1L)!!)
        val other = "5.10.101-android12-9-gdeadbeef"
        store.record(
            other,
            MeasuredProfileStore.parseSlabinfo(
                other,
                capture(releaseLine = other, slabLine = "mm_struct 1 1 1024 32 8 : tunables 0 0 0"),
                now = 2L,
            )!!,
        )
        assertEquals(2, store.kernels().size)
        assertEquals(960L, store.kernel(release)!!.facts.single().value)
        assertEquals(1024L, store.kernel(other)!!.facts.single().value)
    }

    @Test
    fun `a newer schema is never overwritten`() {
        val file = File(temporaryFolder.root, "measured_profiles.conf")
        file.writeText("schema_version = 2\nkernels = []\n")
        val before = file.readText()

        val store = MeasuredProfileStore(file)
        val fact = MeasuredProfileStore.parseSlabinfo(release, capture(), now = 1L)!!
        assertFalse(store.record(release, fact))
        assertEquals(before, file.readText())
        assertTrue(store.kernels().isEmpty())
    }

    @Test
    fun `an unreadable file is not silently replaced`() {
        val file = File(temporaryFolder.root, "measured_profiles.conf")
        file.writeText("this is not hocon {{{")
        val store = MeasuredProfileStore(file)
        assertFalse(store.record(release, MeasuredProfileStore.parseSlabinfo(release, capture())!!))
    }
}
