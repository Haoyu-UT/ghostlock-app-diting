package com.ghostlock.app.data

/**
 * The execution-time pipeline resolver: walks the profile's ordered list and
 * returns the first entry whose checks pass. The checks are callbacks because
 * GhostLock is a static verdict here, while DirtyFrag needs the ROM preflight
 * and the primitive probe (or a matching measured-DB record).
 *
 * Resolution happens once, **before W1**. A `null` callback result means the
 * entry is viable; a string is the rejection reason. No re-resolution after
 * W1: a stage failure is restore-or-reboot, never "try the next entry".
 */
internal object PipelineResolver {
    data class Decision(val pipeline: String?, val rejected: List<String>)

    fun resolve(
        order: List<String>,
        ghostlock: () -> String?,
        dirtyfrag: () -> String?,
    ): Decision {
        val rejected = mutableListOf<String>()
        for (entry in order) {
            val reason = when (entry) {
                "ghostlock" -> ghostlock()
                "dirtyfrag" -> dirtyfrag()
                else -> "unknown pipeline"
            }
            if (reason == null) {
                return Decision(entry, rejected)
            }
            rejected += "$entry: $reason"
        }
        return Decision(null, rejected)
    }
}
