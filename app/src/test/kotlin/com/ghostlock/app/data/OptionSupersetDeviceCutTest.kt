package com.ghostlock.app.data

import com.ghostlock.app.data.profile.PerDevicePhys
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The on-device extractor records one full derivation per device sidecar set.
 * The ambiguous-route cut must select the running device's entry and emit a
 * schema-v2 map; a legacy superset without devices keeps the scalar.
 */
class OptionSupersetDeviceCutTest {
    private val json = """
        {
          "release": "5.10.198-android12-9-00085-g226a9632f13d-ab11136126",
          "kernel_major": 5,
          "kernel_phys_load": 2818572288,
          "kernel_phys_offset": null,
          "phys_source": "uefi memory map",
          "routes": [
            {"route": "select_stack", "verdict": "feasible", "reason": "",
             "anchor_capable": true, "geometry": {"waiter_shift": -2}}
          ],
          "plans": [
            {"route": "select_stack",
             "page": {"route": "select_stack", "page_free": false,
                      "conditioned": false, "reason": "page"},
             "page_free": []}
          ],
          "profile": {
            "": {
              "release": "5.10.198-android12-9-00085-g226a9632f13d-ab11136126",
              "schema_version": "1",
              "kernel_major": "5",
              "recommend_shizuku": "0",
              "kernel_phys_load": "2818572288",
              "kernel_phys_offset": "null"
            }
          },
          "devices": [
            {"device": "diting", "kernel_phys_load": 2818572288,
             "kernel_phys_offset": null, "phys_source": "uefi memory map"},
            {"device": "yunluo", "kernel_phys_load": 1073741824,
             "kernel_phys_offset": 1073741824,
             "phys_source": "vendor_boot header (MediaTek)"}
          ]
        }
    """.trimIndent()

    private fun superset(): OptionSuperset =
        OptionSuperset.parse(json) ?: error("superset did not parse")

    private fun cutDocument(text: String): ValueMap =
        HoconSupport.parseValue(text).asValueMap() ?: error("cut is not an object")

    @Test
    fun `the cut selects the device pair and emits a v2 map`() {
        val superset = superset()
        assertEquals("diting", superset.device)
        val plans = superset.plansFor("select_stack") ?: error("no plans")
        val document = cutDocument(superset.cut("select_stack", plans.page)!!)
        assertEquals(2, (document["schema_version"] as Number).toInt())
        val resolved = PerDevicePhys.resolveFor(document, listOf("diting")).document
        assertEquals(2818572288L, resolved["kernel_phys_load"])
        assertNull(resolved["kernel_phys_offset"])
    }

    @Test
    fun `the cut can select another device`() {
        val superset = superset()
        val plans = superset.plansFor("select_stack") ?: error("no plans")
        val document = cutDocument(superset.cut("select_stack", plans.page, "yunluo")!!)
        val resolved = PerDevicePhys.resolveFor(document, listOf("yunluo")).document
        assertEquals(1073741824L, resolved["kernel_phys_load"])
        assertEquals(1073741824L, resolved["kernel_phys_offset"])
    }

    @Test
    fun `a legacy superset without devices keeps the scalar`() {
        val superset = superset().copy(devices = emptyList())
        val plans = superset.plansFor("select_stack") ?: error("no plans")
        val document = cutDocument(superset.cut("select_stack", plans.page)!!)
        assertEquals(1, (document["schema_version"] as Number).toInt())
        val resolved = PerDevicePhys.resolveFor(document, listOf("diting")).document
        assertEquals(2818572288L, resolved["kernel_phys_load"])
        assertNull(resolved["kernel_phys_offset"])
    }
}
