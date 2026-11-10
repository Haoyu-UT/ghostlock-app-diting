package com.ghostlock.app.data.profile

import com.ghostlock.app.data.ValueMap
import com.ghostlock.app.data.valueMapOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class PerDevicePhysTest {
    private fun doc(vararg pairs: Pair<String, Any?>): ValueMap = valueMapOf(*pairs)

    private fun v2(load: Map<String, Any?>, offset: Map<String, Any?>): ValueMap = doc(
        "schema_version" to 2L,
        "kernel_phys_load" to load,
        "kernel_phys_offset" to offset,
    )

    @Test
    fun `v1 scalars pass through`() {
        val out = PerDevicePhys.resolve(
            doc(
                "schema_version" to 1L,
                "kernel_phys_load" to 0xa8000000L,
                "kernel_phys_offset" to 0x80000000L,
            ),
            "diting",
        )
        assertEquals(0xa8000000L, out["kernel_phys_load"])
        assertEquals(0x80000000L, out["kernel_phys_offset"])
    }

    @Test
    fun `v2 maps select the running device case-insensitively`() {
        val out = PerDevicePhys.resolve(
            v2(mapOf("DITING" to 0xa8000000L), mapOf("diting" to 0x80000000L)),
            "Diting",
        )
        assertEquals(0xa8000000L, out["kernel_phys_load"])
        assertEquals(0x80000000L, out["kernel_phys_offset"])
    }

    @Test
    fun `an unlisted device is refused, not resolved to null`() {
        assertThrows(IllegalArgumentException::class.java) {
            PerDevicePhys.resolve(v2(mapOf("diting" to 1L), mapOf("diting" to 2L)), "dew")
        }
    }

    @Test
    fun `a null device with a map is refused`() {
        assertThrows(IllegalArgumentException::class.java) {
            PerDevicePhys.resolve(v2(mapOf("diting" to 1L), mapOf("diting" to 2L)), null)
        }
    }

    @Test
    fun `an empty map is refused`() {
        assertThrows(IllegalArgumentException::class.java) {
            PerDevicePhys.resolve(v2(emptyMap(), emptyMap()), "diting")
        }
    }

    @Test
    fun `the neutral export path keeps the pair null`() {
        val out = PerDevicePhys.resolveNeutral(v2(mapOf("diting" to 1L), mapOf("diting" to 2L)))
        assertNull(out["kernel_phys_load"])
        assertNull(out["kernel_phys_offset"])
    }

    @Test
    fun `v2 may keep legacy all-device scalars`() {
        val out = PerDevicePhys.resolve(
            doc(
                "schema_version" to 2L,
                "kernel_phys_load" to 0xa8000000L,
                "kernel_phys_offset" to 0x80000000L,
            ),
            "dew",
        )
        assertEquals(0xa8000000L, out["kernel_phys_load"])
        assertEquals(0x80000000L, out["kernel_phys_offset"])
    }

    @Test
    fun `a map in v1 is rejected`() {
        val document = v2(mapOf("diting" to 1L), mapOf("diting" to 2L))
        document["schema_version"] = 1L
        assertThrows(IllegalArgumentException::class.java) {
            PerDevicePhys.resolve(document, "diting")
        }
    }

    @Test
    fun `one map and one scalar is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            PerDevicePhys.resolve(
                doc(
                    "schema_version" to 2L,
                    "kernel_phys_load" to mapOf("diting" to 1L),
                    "kernel_phys_offset" to 2L,
                ),
                "diting",
            )
        }
    }

    @Test
    fun `different device key sets are rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            PerDevicePhys.resolve(
                v2(mapOf("diting" to 1L), mapOf("dew" to 2L)),
                "diting",
            )
        }
    }

    @Test
    fun `a non-number entry is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            PerDevicePhys.resolve(v2(mapOf("diting" to "x"), mapOf("diting" to 2L)), "diting")
        }
    }

    @Test
    fun `duplicate device keys ignoring case are rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            PerDevicePhys.resolve(
                v2(mapOf("diting" to 1L, "DITING" to 2L), mapOf("diting" to 2L)),
                "diting",
            )
        }
    }

    @Test
    fun `a future schema is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            PerDevicePhys.resolve(
                doc(
                    "schema_version" to 3L,
                    "kernel_phys_load" to 1L,
                    "kernel_phys_offset" to 2L,
                ),
                "diting",
            )
        }
    }

    @Test
    fun `the first candidate present selects the pair and its key`() {
        val result = PerDevicePhys.resolveFor(
            v2(mapOf("spinel" to 0x40000000L), mapOf("spinel" to 0x40000000L)),
            listOf("missi", "spinel", "generic"),
        )
        assertEquals(0x40000000L, result.document["kernel_phys_load"])
        assertEquals(0x40000000L, result.document["kernel_phys_offset"])
        assertEquals("spinel", result.device)
    }

    @Test
    fun `no matching candidate refuses`() {
        assertThrows(IllegalArgumentException::class.java) {
            PerDevicePhys.resolveFor(
                v2(mapOf("spinel" to 1L), mapOf("spinel" to 2L)),
                listOf("missi", "generic"),
            )
        }
    }

    @Test
    fun `a map with a null counterpart resolves the map side`() {
        val result = PerDevicePhys.resolveFor(
            doc(
                "schema_version" to 2L,
                "kernel_phys_load" to mapOf("diting" to 0xa8000000L),
                "kernel_phys_offset" to null,
            ),
            listOf("diting"),
        )
        assertEquals(0xa8000000L, result.document["kernel_phys_load"])
        assertNull(result.document["kernel_phys_offset"])
        assertEquals("diting", result.device)
    }

    @Test
    fun `a null load with an offset map resolves the offset side`() {
        val result = PerDevicePhys.resolveFor(
            doc(
                "schema_version" to 2L,
                "kernel_phys_load" to null,
                "kernel_phys_offset" to mapOf("diting" to 0x80000000L),
            ),
            listOf("diting"),
        )
        assertNull(result.document["kernel_phys_load"])
        assertEquals(0x80000000L, result.document["kernel_phys_offset"])
        assertEquals("diting", result.device)
    }
}
