package com.ghostlock.app.data

import com.ghostlock.app.domain.model.CpuPair
import java.util.concurrent.TimeUnit

/**
 * Best-effort pre-run affinity probe for the selected CPU pair.
 *
 * The native pins with `sched_setaffinity`, which returns EINVAL when neither
 * requested CPU is in `cpu_active_mask` (the vendor `core_ctl` pauses one of
 * the gold cores and rotates which). The app cannot call that syscall itself,
 * so it asks toybox `taskset` to run a trivial child with the same mask: the
 * child is forked by the app exactly like the exploit native, so it sees the
 * same cgroup / active-CPU view.
 *
 * Every ambiguity fails open (no taskset, exec denied, timeout, unexpected
 * error): this check must never block a run it cannot judge. Only a definitive
 * "Invalid argument" from taskset blocks. The native's own SYSCHK remains the
 * authority, and the class-2 pattern covers the residue.
 */
internal object CpuPairProbe {
    private const val TASKSET = "/system/bin/taskset"
    private const val TRUE = "/system/bin/true"

    /** True when the pair looks usable, or when the probe cannot judge. */
    fun usable(pair: CpuPair): Boolean {
        if (pair.primary !in 0..31 || pair.consumer !in 0..31) return true
        val mask = ((1L shl pair.primary) or (1L shl pair.consumer)).toString(16)
        return try {
            val process = ProcessBuilder(TASKSET, mask, TRUE)
                .redirectErrorStream(true)
                .start()
            if (!process.waitFor(2, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                return true
            }
            val output = runCatching {
                process.inputStream.bufferedReader().use { it.readText() }
            }.getOrDefault("")
            process.exitValue() == 0 || !output.contains("Invalid argument", ignoreCase = true)
        } catch (_: Exception) {
            true
        }
    }
}
