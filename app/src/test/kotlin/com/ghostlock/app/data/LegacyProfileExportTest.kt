package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class LegacyProfileExportTest {
    private val release = "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284"

    private fun base(): ValueMap = valueMapOf(
        "release" to release,
        "kernelsnitch" to valueMapOf("mm_struct_sz" to 960L, "collisions" to 8L),
        "route" to valueMapOf(
            "select_stack" to valueMapOf(
                "waiter_shift" to -2L,
                "compact_waiter" to 1L,
                "lock_anchor_image" to 44279184L,
            ),
        ),
        "fallback" to valueMapOf("to" to "none"),
    )

    @Test
    fun `a null in the same route branch keeps the document value`() {
        val entry = base()
        LegacyProfileExport.applyOverride(
            entry,
            valueMapOf(
                "route" to valueMapOf(
                    "select_stack" to valueMapOf("waiter_shift" to null),
                ),
            ),
        )

        val branch = entry["route"].asValueMap()!!["select_stack"].asValueMap()!!
        assertEquals(-2L, (branch["waiter_shift"] as Number).toLong())
        /* The whole branch must survive: the anchor is why the route works. */
        assertEquals(44279184L, (branch["lock_anchor_image"] as Number).toLong())
        assertEquals(1L, (branch["compact_waiter"] as Number).toLong())
    }

    @Test
    fun `a different route branch replaces the document branch`() {
        val entry = base()
        LegacyProfileExport.applyOverride(
            entry,
            valueMapOf(
                "route" to valueMapOf(
                    "multicast_waiter" to valueMapOf("waiter_off" to 48L),
                ),
            ),
        )

        val route = entry["route"].asValueMap()!!
        assertEquals(setOf("multicast_waiter"), route.keys.toSet())
        assertEquals(48L, (route["multicast_waiter"].asValueMap()!!["waiter_off"] as Number).toLong())
    }

    @Test
    fun `other namespaces deep-merge and nulls do not erase`() {
        val entry = base()
        LegacyProfileExport.applyOverride(
            entry,
            valueMapOf(
                "execution" to valueMapOf(
                    "selected_cpus" to valueMapOf("main" to 4L, "consumer" to 5L),
                ),
                "kernelsnitch" to valueMapOf("mm_struct_sz" to null),
            ),
        )

        val cpus = entry["execution"].asValueMap()!!["selected_cpus"].asValueMap()!!
        assertEquals(4L, (cpus["main"] as Number).toLong())
        assertEquals(5L, (cpus["consumer"] as Number).toLong())
        /* A null fact in the override never erases a measured value. */
        val snitch = entry["kernelsnitch"].asValueMap()!!
        assertEquals(960L, (snitch["mm_struct_sz"] as Number).toLong())
    }
}
