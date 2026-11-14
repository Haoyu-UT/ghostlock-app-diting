package com.ghostlock.app.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RouteDisplayTest {
    @Test
    fun `an option label is the route and its carrier, and nothing else`() {
        assertEquals(
            "select_stack (64-bit native)",
            RouteDisplay.optionLabel("select_stack", "native"),
        )
        assertEquals(
            "select_stack (32-bit compat)",
            RouteDisplay.optionLabel("select_stack", "compat"),
        )
        assertEquals(
            "multicast_waiter (32-bit compat)",
            RouteDisplay.optionLabel("multicast_waiter", "compat"),
        )
        assertEquals(
            "sigreturn (64-bit native)",
            RouteDisplay.optionLabel("sigreturn", "native"),
        )
        assertEquals(
            "tcp_zerocopy (64-bit native)",
            RouteDisplay.optionLabel("tcp_zerocopy", "native"),
        )
    }

    /** The display never invents or hides a carrier the superset accepted. */
    @Test
    fun `an unknown carrier is shown verbatim`() {
        assertEquals(
            "select_stack (future-carrier)",
            RouteDisplay.optionLabel("select_stack", "future-carrier"),
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
