package com.ghostlock.app.data

import com.ghostlock.app.data.profile.CpuPairView
import com.ghostlock.app.data.profile.ProfileMerger
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Throwaway probe (batch D debugging): does `route.select_stack.lock_anchor_image`
 * survive the Kotlin half of the profile pipeline — HOCON parse of the REAL
 * document on disk + ProfileMerger.resolveMerged against the REAL
 * `debug_profile_overrides` body read from the app's preference backup?
 *
 * Both inputs are the real artifacts, not a transcription, so a pass rules the
 * Kotlin pipeline out as the drop site and points at the native/wire side.
 */
class AnchorMergeProbeTest {
    private val release = "5.10.236-android12-9-00003-gfb24cf99ad97-ab14313284"
    private val anchor = 44279184L

    /** The stored prefs body, verbatim, from external/port/app-prefs-backup/. */
    private val overrideText = """
        "$release" {
          execution {
            selected_cpus {
              main = 4
              consumer = 5
            }
          }
          route {
            select_stack {
              waiter_shift = null
            }
          }
          fallback {
            to = "none"
          }
        }
    """.trimIndent()

    private fun locateConf(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val f = File(dir, "external/port/$release.conf")
            if (f.isFile) return f
            dir = dir.parentFile
        }
        throw AssertionError("device profile .conf not found above ${System.getProperty("user.dir")}")
    }

    @Test
    fun `real document plus real override body keep the anchor`() {
        // A. the document as the app reads it
        val confFile = locateConf()
        println("CONF: ${confFile.absolutePath}")
        val doc = HoconSupport.parseValue(confFile.readText()).asValueMap()
            ?: throw AssertionError("document did not parse to a map")
        val docRoute = (doc["route"] as? Map<*, *>)?.get("select_stack") as? Map<*, *>
        println("A. parsed doc route.select_stack = $docRoute")

        // B. the override body the app stores, keyed by release
        val allOverrides = HoconSupport.parseValue(overrideText).asValueMap()
        val overrides = allOverrides?.get(release).asValueMap()
        println("B. override body = $overrides")

        val merged = ProfileMerger.resolveMerged(
            deviceRelease = release,
            builtin = null,
            imported = doc,
            overrides = overrides,
            tuningExecution = null,
            pair = CpuPairView(4, 5),
            routePresets = emptyMap(),
        )

        val body = (merged["route"] as? Map<*, *>)?.get("select_stack") as? Map<*, *>
        println("C. MERGED route.select_stack = $body")
        println("C. lock_anchor_image = ${body?.get("lock_anchor_image")} (present=${body?.containsKey("lock_anchor_image")})")
        println("C. waiter_shift = ${body?.get("waiter_shift")} (present=${body?.containsKey("waiter_shift")})")
        println("C. kernel_major = ${merged["kernel_major"]}  cpus = ${(merged["execution"] as? Map<*, *>)?.get("selected_cpus")}")
        println("C. rendered:\n${HoconSupport.render(merged)}")

        assertEquals("document key must reach the merged profile", anchor, (body?.get("lock_anchor_image") as? Number)?.toLong())

        /* The rendered HOCON length is the only content signal the device's
         * zero-filled sidecars preserve -- compare it against the device dumps
         * (2314 B from 22:52 on, 2281 B at 21:12). */
        val renderWith = HoconSupport.render(merged)
        println("SIZE with anchor    = ${renderWith.toByteArray(Charsets.UTF_8).size}")
        val noAnchor = HoconSupport.parseValue(confFile.readText()).asValueMap()!!
        ((noAnchor["route"] as Map<*, *>)["select_stack"] as MutableMap<String, Any?>).remove("lock_anchor_image")
        val mergedNo = ProfileMerger.resolveMerged(release, null, noAnchor, overrides, null, CpuPairView(4, 5), emptyMap())
        println("SIZE without anchor = ${HoconSupport.render(mergedNo).toByteArray(Charsets.UTF_8).size}")
        val line = renderWith.lines().first { it.contains("lock_anchor_image") }
        println("anchor line = '${line}' (${line.toByteArray(Charsets.UTF_8).size + 1} bytes with newline)")
    }
}
