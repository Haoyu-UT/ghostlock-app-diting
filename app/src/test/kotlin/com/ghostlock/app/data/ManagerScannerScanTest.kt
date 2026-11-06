package com.ghostlock.app.data

import android.app.Application
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.File

/**
 * Covers the platform-facing scan(): package enumeration, the self/system
 * filters, the executable-shape prefilter, the token scan, and the fallback
 * when the `--version` probe cannot run (the fake binary is not executable,
 * so the probe is "unavailable" and suitability falls back to the tokens).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ManagerScannerScanTest {
    private lateinit var app: Application
    private lateinit var pm: PackageManager

    @Before
    fun setUp() {
        app = RuntimeEnvironment.getApplication() as Application
        pm = app.packageManager
    }

    private fun fakeKsudElf(): ByteArray {
        val bytes = ByteArray(4096)
        bytes[0] = 0x7f
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = 2                     // ELFCLASS64
        bytes[5] = 1                     // ELFDATA2LSB
        bytes[6] = 1                     // EV_CURRENT
        put16(bytes, 16, 3)              // ET_DYN
        put16(bytes, 18, 183)            // EM_AARCH64
        put64(bytes, 32, 64)             // e_phoff
        put16(bytes, 54, 56)             // e_phentsize
        put16(bytes, 56, 1)              // e_phnum
        put32(bytes, 64, 3)              // PT_INTERP
        "late-load\u0000--allow-shell\u0000kernelsu.ko\u0000KernelSU\u0000"
            .toByteArray()
            .copyInto(bytes, 200)
        return bytes
    }

    private fun put16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value and 0xff).toByte()
        target[offset + 1] = ((value ushr 8) and 0xff).toByte()
    }

    private fun put32(target: ByteArray, offset: Int, value: Long) {
        for (index in 0 until 4) {
            target[offset + index] = ((value ushr (8 * index)) and 0xff).toByte()
        }
    }

    private fun put64(target: ByteArray, offset: Int, value: Long) {
        for (index in 0 until 8) {
            target[offset + index] = ((value ushr (8 * index)) and 0xff).toByte()
        }
    }

    private fun install(pkg: String, system: Boolean, ksud: Boolean, elf: ByteArray = fakeKsudElf()) {
        val dir = File(app.cacheDir, "libs-$pkg-${System.nanoTime()}").apply { mkdirs() }
        if (ksud) File(dir, "libksud.so").writeBytes(elf)
        val info = ApplicationInfo().apply {
            packageName = pkg
            flags = if (system) ApplicationInfo.FLAG_SYSTEM else 0
            nativeLibraryDir = dir.absolutePath
        }
        shadowOf(pm).installPackage(
            PackageInfo().apply {
                packageName = pkg
                applicationInfo = info
            },
        )
    }

    @Test
    fun `scan keeps a user-installed ksud candidate and drops self and system apps`() {
        install("com.example.manager", system = false, ksud = true)
        install("com.ghostlock.app", system = false, ksud = true)
        install("com.android.settings", system = true, ksud = true)

        val result = ManagerScanner.scan(app)

        assertEquals(listOf("com.example.manager"), result.map { it.packageName })
        val candidate = result.single()
        assertTrue(candidate.lateLoadToken)
        assertTrue(candidate.allowShellToken)
        // The fake file is not executable, so the probe is unavailable and the
        // static tokens carry suitability.
        assertEquals(null, candidate.identity)
        assertEquals(null, candidate.interfaceOk)
        assertTrue(candidate.suitable)
    }

    @Test
    fun `scan includes a builtin manager installed as a system app`() {
        install("me.weishu.kernelsu", system = true, ksud = true)
        val result = ManagerScanner.scan(app)
        assertEquals(listOf("me.weishu.kernelsu"), result.map { it.packageName })
        assertTrue(result.single().builtin)
    }

    @Test
    fun `scan ignores packages without an executable-shaped lib`() {
        install("com.example.plain", system = false, ksud = false)
        assertTrue(ManagerScanner.scan(app).isEmpty())
    }
}
