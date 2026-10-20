package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The `--feasible-out` contract the app's two-pass picker depends on: the
 * extractor writes this JSON before exiting 7, and the picker must show
 * exactly the routes whose verdict is `feasible`.
 */
class FeasibleReportTest {
    @Test
    fun `parses the ambiguity report the extractor writes`() {
        val report = FeasibleReport.parse(
            """
            {
              "release" : "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284",
              "routes" : [
                {
                  "route" : "select_stack",
                  "verdict" : "feasible",
                  "reason" : "pselect/futex geometry derived (pselect 0xa0 + 0x1c0)",
                  "numbers" : { "delta" : 0, "pselect_shift" : -2 }
                },
                {
                  "route" : "multicast_waiter",
                  "verdict" : "infeasible",
                  "reason" : "copy window ends 0x48 short of the waiter"
                },
                { "route" : "sigreturn", "verdict" : "feasible", "reason" : "chain 0x300" }
              ],
              "chosen" : null
            }
            """.trimIndent(),
        )

        requireNotNull(report)
        assertEquals(
            "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284",
            report.release,
        )
        assertEquals(listOf("select_stack", "sigreturn"), report.feasible.map { it.route })
        assertEquals(listOf("select_stack", "multicast_waiter", "sigreturn"), report.routes.map { it.route })
        assertEquals(
            mapOf("delta" to 0L, "pselect_shift" to -2L),
            report.routes.first().numbers,
        )
        assertNull(report.chosen)
    }

    @Test
    fun `parses a chosen route from a single-feasible pass`() {
        val report = FeasibleReport.parse(
            """
            {
              "release" : "5.10.101-android12-9-00005-ga829d48e78bd-ab9206161",
              "routes" : [
                { "route" : "sigreturn", "verdict" : "feasible", "reason" : "derived" }
              ],
              "chosen" : "sigreturn"
            }
            """.trimIndent(),
        )

        requireNotNull(report)
        assertEquals("sigreturn", report.chosen)
        assertEquals(listOf("sigreturn"), report.feasible.map { it.route })
    }

    @Test
    fun `malformed text is not a report`() {
        assertNull(FeasibleReport.parse("not a route report"))
        assertNull(FeasibleReport.parse(""))
    }
}
