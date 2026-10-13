package com.ghostlock.app.data

import android.content.Context
import android.os.SystemClock

/**
 * Whether this installation's data predates the current boot.
 *
 * The exploit's scratch region keeps its per-boot slot state in a file under the
 * app's data dir, and the region itself is only re-zeroed by a reboot. That file
 * is the *only* record of which slots this boot has spent, so when it is missing
 * the run has to decide between two cases:
 *
 * * the data dir was created (or wiped and recreated) **after** this boot began
 *   — a previous installation may have run since the boot and poisoned the
 *   region, so slot 0 is not safe and only a reboot fixes it;
 * * the data dir existed **before** this boot began — then any run this boot
 *   would have written the file, so its absence proves the region is still
 *   zeroed and slot 0 is safe.
 *
 * `PackageInfo.lastUpdateTime` is when this installation's data was created or
 * last carried over by an update; comparing it with the wall-clock instant the
 * boot happened (`now - elapsedRealtime`) separates the two.
 */
internal object InstallClock {
    /** Pure half, so the boundary cases are testable without a device. */
    fun installPredatesBoot(
        lastUpdateTimeMillis: Long,
        nowMillis: Long,
        elapsedRealtimeMillis: Long,
    ): Boolean {
        if (lastUpdateTimeMillis <= 0L) return false
        return lastUpdateTimeMillis <= nowMillis - elapsedRealtimeMillis
    }

    /** False when the package cannot be read — the caller then refuses, as before. */
    fun installPredatesBoot(context: Context): Boolean = runCatching {
        @Suppress("DEPRECATION")
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        installPredatesBoot(
            lastUpdateTimeMillis = info.lastUpdateTime,
            nowMillis = System.currentTimeMillis(),
            elapsedRealtimeMillis = SystemClock.elapsedRealtime(),
        )
    }.getOrDefault(false)
}
