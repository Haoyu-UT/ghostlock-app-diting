package com.ghostlock.app.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import java.io.File
import java.io.FileInputStream
import java.util.concurrent.TimeUnit

/**
 * Finds KernelSU-family managers that can late-load on this device and ranks
 * them. The pipeline is the 2026-11-06 design (PORT: ksud-judge-poc):
 *
 *  1. enumerate user-installed packages (and the built-in managers even when
 *     system-installed);
 *  2. per package, keep executable-shaped aarch64 ELFs (ET_DYN + PT_INTERP,
 *     or ET_EXEC) — a 4 KiB prefilter, so ordinary shared libraries cost
 *     almost nothing;
 *  3. token-scan only those candidates (`late-load`, `allow_shell`, capsule /
 *     bootstrap markers, `kernelsu.ko`);
 *  4. execute `late-load --help` for ksud-like candidates and require the
 *     exact interface this app calls (`--kmi` and `--allow-shell`).
 *
 * The `--version` banner is deliberately not used: forks print release names
 * (`ksud samsung-v2.2 (uapi: 5)`), and the interface probe is the contract
 * that matters. Suitability: a confirmed interface wins; a candidate whose
 * probe cannot run (SELinux denies exec, timeout) falls back to the static
 * late-load tokens.
 * There is deliberately no persistent cache — the whole pipeline is ~0.2 s
 * warm on a regular phone, and a stale "capable" verdict is the one failure
 * mode worth avoiding.
 */
object ManagerScanner {
    const val PREF_KEY = "manager_package"

    private const val PROBE_TIMEOUT_MS = 2000L
    private const val MAX_PROBE_OUTPUT = 8192
    private const val MAX_SCAN_BYTES = 64L * 1024 * 1024

    /** Built-in KernelSU-family managers, priority order. */
    val BUILTIN = listOf(
        "me.weishu.kernelsu.pr",
        "me.weishu.kernelsu",
        "com.rifsxd.ksunext",
        "com.resukisu.resukisu",
        "org.bakasu.bakasu",
        "com.kowx712.supermanager",
    )

    data class Candidate(
        val packageName: String,
        val label: String,
        val path: String,
        val builtin: Boolean,
        val lateLoadToken: Boolean,
        val allowShellToken: Boolean,
        /** null = the probe could not run (exec denied, timeout, crash). */
        val interfaceOk: Boolean?,
    ) {
        val suitable: Boolean
            get() = when {
                interfaceOk == true -> true
                interfaceOk == false -> false
                else -> lateLoadToken && allowShellToken
            }

        val verdict: String
            get() = when {
                interfaceOk == true -> "late-load interface confirmed"
                interfaceOk == false -> "late-load interface missing"
                lateLoadToken && allowShellToken -> "static late-load candidate (probe unavailable)"
                else -> "not suitable"
            }

        /** Label shown in the picker. */
        fun displayName(): String = "$label ($packageName) — $verdict"
    }

    /** Scan installed managers. Blocking I/O and probes: call from Dispatchers.IO. */
    fun scan(context: Context): List<Candidate> {
        val pm = context.packageManager
        val self = context.packageName
        @Suppress("DEPRECATION")
        val packages = pm.getInstalledPackages(0)
        val found = ArrayList<Candidate>()
        for (info in packages) {
            val app = info.applicationInfo ?: continue
            if (info.packageName == self) continue
            val system = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (system && info.packageName !in BUILTIN) continue
            val dir = app.nativeLibraryDir ?: continue
            val files = runCatching { File(dir).listFiles() }.getOrNull() ?: continue
            for (file in files) {
                if (!file.isFile) continue
                if (file.length() > MAX_SCAN_BYTES) continue
                if (!isExecutableShaped(file)) continue
                val tokens = scanTokens(file)
                if (!tokens.ksudLike) continue
                val probe = run(file, "late-load", "--help")
                val iface = if (probe.unavailable) {
                    null
                } else {
                    probe.exit == 0 && probe.output.contains("--allow-shell") && probe.output.contains("--kmi")
                }
                found += Candidate(
                    packageName = info.packageName,
                    label = runCatching { app.loadLabel(pm).toString() }.getOrDefault(info.packageName),
                    path = file.absolutePath,
                    builtin = info.packageName in BUILTIN,
                    lateLoadToken = tokens.lateLoad,
                    allowShellToken = tokens.allowShell,
                    interfaceOk = iface,
                )
            }
        }
        return found.sortedWith(compareByDescending<Candidate> { it.suitable }
            .thenByDescending { it.interfaceOk == true }
            .thenByDescending { it.builtin }
            .thenBy { it.label.lowercase() })
    }

    /** Selected package when it is still suitable, else the best suitable one. */
    fun resolve(candidates: List<Candidate>, selected: String?): Candidate? =
        candidates.firstOrNull { it.packageName == selected && it.suitable }
            ?: candidates.firstOrNull { it.suitable }

    private data class Tokens(
        val lateLoad: Boolean,
        val allowShell: Boolean,
        val capsule: Boolean,
        val bootstrap: Boolean,
        val kernelKo: Boolean,
        val brand: Boolean,
    ) {
        val ksudLike: Boolean
            get() = lateLoad || capsule || bootstrap || (brand && kernelKo)
    }

    private data class Probe(val exit: Int?, val output: String, val unavailable: Boolean)

    private fun run(file: File, vararg args: String): Probe {
        val command = ArrayList<String>(args.size + 1)
        command += file.absolutePath
        command += args
        val process = try {
            ProcessBuilder(command).redirectErrorStream(true).start()
        } catch (_: Exception) {
            return Probe(null, "", true)
        }
        val output = StringBuilder()
        val reader = Thread {
            runCatching {
                process.inputStream.bufferedReader().use { stream ->
                    val buffer = CharArray(4096)
                    while (true) {
                        val count = stream.read(buffer)
                        if (count < 0) break
                        if (output.length < MAX_PROBE_OUTPUT) {
                            output.append(buffer, 0, minOf(count, MAX_PROBE_OUTPUT - output.length))
                        }
                    }
                }
            }
        }.apply { isDaemon = true; start() }
        val finished = process.waitFor(PROBE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        if (!finished) {
            process.destroyForcibly()
            runCatching { process.waitFor(500, TimeUnit.MILLISECONDS) }
            reader.interrupt()
            return Probe(null, output.toString(), true)
        }
        runCatching { reader.join(500) }
        return Probe(runCatching { process.exitValue() }.getOrNull(), output.toString(), false)
    }

    /** ELF, little-endian aarch64, ET_DYN + PT_INTERP (PIE) or ET_EXEC. */
    private fun isExecutableShaped(file: File): Boolean {
        val head = ByteArray(4096)
        val count = try {
            FileInputStream(file).use { it.read(head) }
        } catch (_: Exception) {
            return false
        }
        if (count < 64) return false
        if (head[0] != 0x7f.toByte() || head[1] != 'E'.code.toByte() ||
            head[2] != 'L'.code.toByte() || head[3] != 'F'.code.toByte()
        ) {
            return false
        }
        if (head[5].toInt() != 1) return false            // ELFDATA2LSB
        val type = u16(head, 16)
        if (u16(head, 18) != 183) return false            // EM_AARCH64
        if (type == 2) return true                        // ET_EXEC
        if (type != 3) return false                       // ET_DYN
        val phoff = u64(head, 32)
        val phentsize = u16(head, 54)
        val phnum = u16(head, 56)
        var index = 0
        while (index < phnum && index < 64) {
            val offset = phoff + index.toLong() * phentsize
            if (offset + 4 > count.toLong()) break
            if (u32(head, offset.toInt()) == 3L) return true // PT_INTERP
            index++
        }
        return false
    }

    private fun scanTokens(file: File): Tokens {
        var lateLoad = false
        var allowShell = false
        var capsule = false
        var bootstrap = false
        var kernelKo = false
        var brand = false
        val chunk = ByteArray(64 * 1024 + 16)
        var keep = 0
        try {
            FileInputStream(file).use { stream ->
                while (true) {
                    val read = stream.read(chunk, keep, 64 * 1024)
                    if (read <= 0) break
                    val length = keep + read
                    lateLoad = lateLoad || contains(chunk, length, LATE_LOAD)
                    allowShell = allowShell || contains(chunk, length, ALLOW_SHELL) ||
                        contains(chunk, length, ALLOW_SHELL_UNDERSCORE)
                    capsule = capsule || contains(chunk, length, CAPSULE)
                    bootstrap = bootstrap || contains(chunk, length, BOOTSTRAP)
                    kernelKo = kernelKo || contains(chunk, length, KERNEL_KO)
                    brand = brand || contains(chunk, length, BRAND)
                    if (lateLoad && allowShell && (capsule || bootstrap)) {
                        // Everything this app needs is present; stop reading.
                        return Tokens(lateLoad, allowShell, capsule, bootstrap, kernelKo, brand)
                    }
                    keep = minOf(15, length)
                    System.arraycopy(chunk, length - keep, chunk, 0, keep)
                }
            }
        } catch (_: Exception) {
            // A partially-read file still yields whatever tokens were seen.
        }
        return Tokens(lateLoad, allowShell, capsule, bootstrap, kernelKo, brand)
    }

    private fun u16(buffer: ByteArray, offset: Int): Int =
        (buffer[offset].toInt() and 0xff) or ((buffer[offset + 1].toInt() and 0xff) shl 8)

    private fun u32(buffer: ByteArray, offset: Int): Long =
        (u16(buffer, offset).toLong()) or (u16(buffer, offset + 2).toLong() shl 16)

    private fun u64(buffer: ByteArray, offset: Int): Long {
        var value = 0L
        for (index in 7 downTo 0) {
            value = (value shl 8) or (buffer[offset + index].toLong() and 0xff)
        }
        return value
    }

    private fun contains(buffer: ByteArray, length: Int, needle: ByteArray): Boolean {
        if (length < needle.size) return false
        val last = length - needle.size
        outer@ for (start in 0..last) {
            for (index in needle.indices) {
                if (buffer[start + index] != needle[index]) continue@outer
            }
            return true
        }
        return false
    }

    private val LATE_LOAD = "late-load".toByteArray()
    private val ALLOW_SHELL = "--allow-shell".toByteArray()
    private val ALLOW_SHELL_UNDERSCORE = "allow_shell".toByteArray()
    private val CAPSULE = "KSULKM1".toByteArray()
    private val BOOTSTRAP = "ksu_bootstrap".toByteArray()
    private val KERNEL_KO = "kernelsu.ko".toByteArray()
    private val BRAND = "KernelSU".toByteArray()
}
