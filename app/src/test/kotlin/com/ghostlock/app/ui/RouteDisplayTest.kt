package com.ghostlock.app.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RouteDisplayTest {
    private val select236 = "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284"
    private val select66 = "6.6.66-android15-8-g29d86c5fc9dd-abogki428889875-4k"
    private val compat81 = "5.10.81-android12-9-00001-g6cd504626bae-ab8485363"
    private val tcp61 = "6.1.138-android14-11-g44bda9e8f6e9-ab13792638"

    @Test
    fun `select labels its waiter shape inline`() {
        val compact = mapOf("waiter_shift" to -2L, "compact_waiter" to 1L)
        assertEquals(
            "select_stack (compact waiter)",
            RouteDisplay.label("select_stack", compact, select236),
        )
        assertEquals(
            "select_stack (rb_node waiter)",
            RouteDisplay.label("select_stack", mapOf("waiter_shift" to -2L), select66),
        )
    }

    @Test
    fun `compat is a 32-bit tag, not a spelling of compact`() {
        val geometry = mapOf(
            "compat_carrier" to 1L,
            "waiter_home" to 432L,
            "select_dst_depth" to 480L,
            "compact_waiter" to 1L,
        )
        assertEquals(
            "select_stack (32-bit compat, compact waiter)",
            RouteDisplay.label("select_stack", geometry, compat81),
        )
        // Compact alone never produces the compat tag.
        assertEquals(
            "select_stack (compact waiter)",
            RouteDisplay.label(
                "select_stack",
                mapOf("compact_waiter" to 1L),
                select236,
            ),
        )
    }

    @Test
    fun `tcp, multicast and sigreturn carry their shape`() {
        assertEquals(
            "tcp_zerocopy (compact waiter)",
            RouteDisplay.label("tcp_zerocopy", mapOf("compact_waiter" to 1L), tcp61),
        )
        assertEquals(
            "multicast_waiter (compact waiter)",
            RouteDisplay.label("multicast_waiter", mapOf("compact_waiter" to 1L), "5.10.246-gki"),
        )
        assertEquals(
            "sigreturn (64-bit)",
            RouteDisplay.label("sigreturn", mapOf("waiter_off_plain" to 320L), compat81),
        )
    }

    @Test
    fun `grades are route-level and do not depend on the kernel build`() {
        assertEquals(RouteGrade.High, RouteDisplay.grade("select_stack"))
        assertEquals(RouteGrade.High, RouteDisplay.grade("tcp_zerocopy"))
        assertEquals(RouteGrade.High, RouteDisplay.grade("multicast_waiter"))
        assertEquals(RouteGrade.Medium, RouteDisplay.grade("sigreturn"))
        assertNull(RouteDisplay.grade("unknown"))
    }
}
