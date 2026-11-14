package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The `--options-out` contract: the app reads every option and applies the
 * display rules itself (auto-take one safe option, offer several without page,
 * offer page only when nothing safe exists). The cut must materialize a
 * profile from the document without another extractor run.
 */
class OptionSupersetTest {
    private val sample = """
        {
          "schema_version": 1,
          "release": "6.1.138-android14-11-g44bda9e8f6e9-ab13792638",
          "kernel_major": 6,
          "kernel_phys_load": 1073741824,
          "kernel_phys_offset": 1073741824,
          "phys_source": "vendor_boot DTB /memory",
          "routes": [
            { "route": "select_stack", "carrier": "native", "verdict": "feasible",
              "reason": "pselect/futex geometry derived",
              "anchor_capable": true,
              "geometry": { "compact_waiter": 1, "waiter_shift": 1 },
              "alternatives": [
                { "carrier": "compat", "verdict": "feasible",
                  "reason": "AArch32 compat carrier",
                  "geometry": { "compat_carrier": 1, "waiter_home": 432,
                                "select_dst_depth": 480, "compat_futex_abi": 0 } }
              ] },
            { "route": "tcp_zerocopy", "verdict": "feasible",
              "reason": "cap 0x40", "anchor_capable": false, "geometry": { "compact_waiter": 1 } }
          ],
          "candidates": [],
          "pipelines": [
            { "pipeline": "ghostlock", "verdict": "feasible", "reason": "KDP is not enabled" },
            { "pipeline": "dirtyfrag", "verdict": "feasible",
              "reason": "the ESP fix is absent; send path ip_append_page" }
          ],
          "pipeline_order": ["dirtyfrag", "ghostlock"],
          "plans": [
            { "route": "select_stack",
              "page": { "route": "select_stack", "anchor": null, "scratch": null,
                        "page_free": false, "conditioned": false, "reason": "page" },
              "anchor_only": { "route": "select_stack",
                        "anchor": { "image": 35802320, "bytes": 4096, "stride": 32 },
                        "scratch": null, "page_free": false, "conditioned": false,
                        "anchor_name": "__dump_skip.zeroes", "reason": "anchor lock, page W1" },
              "page_free": [
                { "route": "select_stack",
                  "anchor": { "image": 35802320, "bytes": 4096, "stride": 32 },
                  "scratch": { "image": 35459072, "window": 0 },
                  "page_free": true, "conditioned": false,
                  "anchor_name": "__dump_skip.zeroes", "scratch_source": "bm_pmd",
                  "reason": "unconditional page-free plan" },
                { "route": "select_stack",
                  "anchor": { "image": 35459072, "bytes": 4096, "stride": 32 },
                  "scratch": { "image": 35459072, "window": 256,
                               "reserved_first": 8, "reserved_last": 8 },
                  "page_free": true, "conditioned": false,
                  "anchor_name": "bm_pmd", "scratch_source": "in-anchor",
                  "reason": "unconditional page-free plan" },
                { "route": "select_stack",
                  "anchor": { "image": 35947744, "bytes": 7392, "stride": 32 },
                  "scratch": { "image": 35459072, "window": 0 },
                  "page_free": true, "conditioned": true,
                  "anchor_name": "s3c24xx_serial_ports", "scratch_source": "bm_pmd",
                  "reason": "conditional page-free plan" }
              ] },
            { "route": "tcp_zerocopy",
              "page": { "route": "tcp_zerocopy", "anchor": null, "scratch": null,
                        "page_free": false, "conditioned": false, "reason": "page" },
              "page_free": [] }
          ],
          "profile": {
            "": { "release": "\"6.1.138-android14-11-g44bda9e8f6e9-ab13792638\"",
                  "schema_version": "1", "kernel_major": "6",
                  "recommend_shizuku": "0",
                  "kernel_phys_load": "1073741824",
                  "kernel_phys_offset": "null" },
            "fallback": { "to": "\"none\"" },
            "selinux": { "enforcing": "0", "initialized": "2" },
            "kernelsnitch": { "collisions": "4", "rt_mutex_size": "32" },
            "task_struct": { "prio": "132", "comm": "2120" },
            "cred": { "copy_size": "128", "caps_offset": "40" },
            "offset": { "init_task": "33420800", "slide_loggers_0_1": "33368344" },
            "waiter_layout": { "compact": "1", "pi_tree": "24" }
          }
        }
    """.trimIndent()

    @Test
    fun `all options are exposed and the UI filters them`() {
        val superset = requireNotNull(OptionSuperset.parse(sample))
        assertEquals("6.1.138-android14-11-g44bda9e8f6e9-ab13792638", superset.release)
        val plans = requireNotNull(superset.plansFor("select_stack"))
        assertEquals(2, plans.safeOptions.size)
        assertEquals(1, plans.conditionalOptions.size)
        assertEquals("__dump_skip.zeroes + bm_pmd", plans.safeOptions[0].label)
        assertEquals("bm_pmd", plans.safeOptions[1].label)
        assertNotNull(plans.anchorOnly)
        assertEquals("__dump_skip.zeroes", plans.anchorOnly?.anchorName)
        assertTrue(plans.safeOptions[1].scratch?.inAnchor == true)
        assertFalse(plans.safeOptions[0].scratch?.inAnchor ?: true)
        val tcp = requireNotNull(superset.plansFor("tcp_zerocopy"))
        assertTrue(tcp.safeOptions.isEmpty())
        assertNull(tcp.anchorOnly)
    }

    @Test
    fun `the display rule follows the operator decision`() {
        val superset = requireNotNull(OptionSuperset.parse(sample))
        val plans = requireNotNull(superset.plansFor("select_stack"))
        val decision = plans.decision()
        require(decision is OptionDecision.Offer)
        assertEquals(2, decision.options.size)
        assertFalse(decision.pageOffered)

        val single = plans.copy(
            pageFree = listOf(plans.safeOptions.first()),
        )
        require(single.decision() is OptionDecision.Auto)

        val conditionalOnly = plans.copy(
            pageFree = listOf(plans.conditionalOptions.first()),
        )
        val offer = conditionalOnly.decision()
        require(offer is OptionDecision.Offer)
        assertTrue(offer.pageOffered)
        assertEquals(1, offer.options.size)

        val none = plans.copy(pageFree = emptyList())
        assertTrue(none.decision() is OptionDecision.NoPageFree)
    }

    @Test
    fun `both feasible pipelines are exposed and the cut carries the order`() {
        val superset = requireNotNull(OptionSuperset.parse(sample))
        val feasible = superset.feasiblePipelines
        assertEquals(listOf("ghostlock", "dirtyfrag"), feasible.map { it.pipeline })
        assertEquals(listOf("dirtyfrag", "ghostlock"), superset.pipelineOrder)
        val plan = superset.plansFor("select_stack")!!.safeOptions[0]
        /* The cut uses the superset's order by default... */
        val chosen = requireNotNull(superset.cut("select_stack", plan))
        assertTrue(chosen.contains("pipeline = ["))
        assertTrue(chosen.contains("\"dirtyfrag\""))
        assertTrue(chosen.contains("\"ghostlock\""))
        /* ...and an explicit order replaces it; an empty one is the legacy
         * no-pipeline form. */
        val override = requireNotNull(
            superset.cut("select_stack", plan, pipelineOrder = listOf("ghostlock")),
        )
        assertTrue(override.contains("\"ghostlock\""))
        assertFalse(override.contains("\"dirtyfrag\""))
        val legacy = requireNotNull(superset.cut("select_stack", plan, pipelineOrder = emptyList()))
        assertFalse(legacy.contains("pipeline ="))
    }

    @Test
    fun `carrier alternatives are exposed and the cut renders the chosen one`() {
        val superset = requireNotNull(OptionSuperset.parse(sample))
        val route = requireNotNull(superset.route("select_stack"))
        assertEquals("native", route.carrier)
        val compat = route.alternatives.single()
        assertEquals("compat", compat.carrier)
        assertEquals(1L, compat.geometry["compat_carrier"])
        val plan = superset.plansFor("select_stack")!!.safeOptions[0]
        val native = requireNotNull(superset.cut("select_stack", plan))
        assertTrue(native.contains("waiter_shift = 1"))
        assertFalse(native.contains("compat_carrier"))
        val chosen = requireNotNull(superset.cut("select_stack", plan, carrier = "compat"))
        assertTrue(chosen.contains("compat_carrier = 1"))
        assertTrue(chosen.contains("waiter_home = 432"))
        assertTrue(chosen.contains("select_dst_depth = 480"))
        assertTrue(chosen.contains("compat_futex_abi = 0"))
        assertFalse(chosen.contains("waiter_shift"))
        assertNull(superset.cut("select_stack", plan, carrier = "bogus"))
    }

    @Test
    fun `cut materializes the selected route and plan`() {
        val superset = requireNotNull(OptionSuperset.parse(sample))
        val plan = superset.plansFor("select_stack")!!.safeOptions[0]
        val cut = requireNotNull(superset.cut("select_stack", plan))
        assertTrue(cut.contains("release = \"6.1.138-android14-11-g44bda9e8f6e9-ab13792638\""))
        assertTrue(cut.contains("waiter_shift = 1"))
        assertTrue(cut.contains("compact_waiter = 1"))
        assertTrue(cut.contains("lock_anchor_image = 35802320"))
        assertTrue(cut.contains("w1_scratch {"))
        assertTrue(cut.contains("image = 35459072"))
        assertTrue(cut.contains("selinux {"))
        assertTrue(cut.contains("prio = 132"))
        val page = requireNotNull(superset.cut("select_stack", superset.plansFor("select_stack")!!.page))
        assertFalse(page.contains("lock_anchor_image"))
        assertFalse(page.contains("w1_scratch"))
        assertNull(superset.cut("sigreturn", plan))
    }
}
