package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExternalProfileStoreTest {
    private val release = "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284"

    @Test
    fun `parses an object document and converts the legacy layout`() {
        val text = """
            [
              {
                "release": "$release",
                "route": "select_stack",
                "pselect_waiter_shift": -2,
                "compact_waiter": 1
              }
            ]
        """.trimIndent()

        val entries = ProfileDocumentParser.entries(text)

        assertNotNull(entries)
        assertEquals(1, entries!!.size)
        val entry = entries.single()
        assertEquals(release, entry["release"])
        /* The converter moves the flat select keys into the route branch. */
        val route = entry["route"].asValueMap()
        assertNotNull(route)
        assertEquals(
            -2L,
            (route!!.get("select_stack").asValueMap()?.get("waiter_shift") as Number?)?.toLong(),
        )
    }

    @Test
    fun `resolves an include through the supplied loader`() {
        val text = """
            include "included.conf"
            release = "$release"
            schema_version = 1
        """.trimIndent()

        val entries = ProfileDocumentParser.entries(text) { target ->
            if (target == "included.conf") {
                "kernel_major = 5\nroute { select_stack { waiter_shift = -2 } }"
            } else {
                null
            }
        }

        val entry = entries?.single()
        assertEquals(5L, (entry?.get("kernel_major") as Number?)?.toLong())
        assertNotNull(entry?.get("route"))
    }

    @Test
    fun `a missing include fails the parse instead of guessing`() {
        val text = """
            include "absent.conf"
            release = "$release"
        """.trimIndent()

        assertNull(ProfileDocumentParser.entries(text))
        assertNull(ProfileDocumentParser.entries(text) { null })
    }

    @Test
    fun `entryForRelease picks the matching entry of a multi-release document`() {
        val text = """
            [
              { release = "6.1.1-a", kernel_major = 6 },
              { release = "$release", kernel_major = 5 }
            ]
        """.trimIndent()

        val entry = ProfileDocumentParser.entryForRelease(text, release)

        assertEquals(5L, (entry?.get("kernel_major") as Number?)?.toLong())
        assertNull(ProfileDocumentParser.entryForRelease(text, "9.9.9-unknown"))
    }

    @Test
    fun `a document without a release is not a profile`() {
        assertNull(ProfileDocumentParser.entries("kernel_major = 5\n"))
        assertNull(ProfileDocumentParser.entries("not hocon {{{"))
    }

    @Test
    fun `the lineage header round-trips`() {
        val parent = ProfileLineage.Parent("external:my-profile.conf", "abc123def456")
        val header = ProfileLineage.header(parent)

        assertEquals(parent, ProfileLineage.parse("$header\nrelease = \"x\"\n"))
        assertNull(ProfileLineage.parse("release = \"x\"\n"))
        assertEquals(
            ProfileLineage.Parent("bundled:$release", null),
            ProfileLineage.parse(ProfileLineage.header(ProfileLineage.Parent("bundled:$release", null))),
        )
    }

    @Test
    fun `sha256 is the document identity`() {
        assertEquals(
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            sha256Of("a"),
        )
        assertTrue(sha256Of("a") != sha256Of("b"))
    }
}
