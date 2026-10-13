package com.ghostlock.app.data

import android.content.Context
import com.ghostlock.app.domain.model.RunLogState
import java.io.Closeable
import java.io.File

/**
 * Debug-only archive for one attack attempt: the run's log plus the resolved
 * profile and the root script's kernel dumps, all in the app's own storage.
 *
 * The archive is the *only* copy — nothing is written to shared storage at run
 * time, because that copy is the one a hard reset destroys. The user exports the
 * run they want to report from the log screen. See [RunLogStore].
 */
internal class DebugAttackLog private constructor(
    private val writer: RunLogWriter,
    val displayName: String,
) : Closeable {
    /** The run's folder; also the root script's --dump-kernel-log target. */
    val folderFile: File
        get() = writer.folderFile

    @Synchronized
    fun append(line: String) = writer.append(line)

    /** Writes an extra file next to the log (e.g. the resolved runtime profile). */
    @Synchronized
    fun writeSidecar(name: String, bytes: ByteArray): Boolean {
        writer.writeSidecar(name, bytes)
        return true
    }

    /** How the run ended; recorded so the next start can tell it from a killed run. */
    @Synchronized
    fun finish(state: RunLogState) = writer.finish(state)

    @Synchronized
    override fun close() = writer.close()

    companion object {
        fun open(context: Context, entry: String): DebugAttackLog? = runCatching {
            val writer = RunLogStore.open(context, entry)
            DebugAttackLog(writer, "ghostlock-$entry-${writer.stamp}.log")
        }.getOrNull()
    }
}
