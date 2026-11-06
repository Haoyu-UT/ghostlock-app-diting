package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ManagerScannerTest {
    private fun candidate(
        pkg: String,
        identity: Boolean? = true,
        iface: Boolean? = null,
        late: Boolean = true,
        allow: Boolean = true,
        builtin: Boolean = false,
    ) = ManagerScanner.Candidate(pkg, pkg, "/x/$pkg", builtin, late, allow, identity, iface)

    @Test
    fun `confirmed interface is suitable`() {
        assertTrue(candidate("a", iface = true).suitable)
    }

    @Test
    fun `missing interface is not suitable`() {
        assertFalse(candidate("a", iface = false).suitable)
    }

    @Test
    fun `identity failure is not suitable`() {
        assertFalse(candidate("a", identity = false).suitable)
    }

    @Test
    fun `unavailable probe falls back to static tokens`() {
        assertTrue(candidate("a", identity = null, iface = null).suitable)
        assertFalse(candidate("a", identity = null, iface = null, allow = false).suitable)
        assertFalse(candidate("a", identity = null, iface = null, late = false).suitable)
    }

    @Test
    fun `resolve prefers the selected suitable package`() {
        val list = listOf(candidate("a", iface = true), candidate("b", iface = true))
        assertEquals("b", ManagerScanner.resolve(list, "b")?.packageName)
    }

    @Test
    fun `resolve falls back to the first suitable`() {
        val list = listOf(candidate("a", iface = false), candidate("b", iface = true))
        assertEquals("b", ManagerScanner.resolve(list, "a")?.packageName)
    }

    @Test
    fun `resolve returns null when nothing is suitable`() {
        assertNull(ManagerScanner.resolve(listOf(candidate("a", iface = false)), null))
    }
}
