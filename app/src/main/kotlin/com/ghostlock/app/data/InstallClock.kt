package com.ghostlock.app.data

import android.content.Context
import android.os.SystemClock

/** Whether the install predates this boot; a missing anchor file is safe only then. */
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
