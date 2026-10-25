package com.ghostlock.app.domain.repository

import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ExternalProfileInfo
import com.ghostlock.app.domain.model.ProfileConfig
import com.ghostlock.app.domain.model.ProfileDiffRow

/**
 * Single authority for profile configuration, measured-db model.
 *
 * A profile is a document (a bundled asset or an external file on the SD card)
 * plus, inside an editor session only, an in-memory sparse edit map. The live
 * controller has no edits and never persists any: exporting a document is the
 * only save (see `docs/analysis/measured-db-plan.md`).
 */
interface ProfileConfigController {
    /** Resolves the active source (external > builtin > bundled) for [release]. */
    suspend fun load(release: String, pair: CpuPair): ProfileConfig

    /** Records an in-memory general (execution tuning) edit. */
    suspend fun updateGeneral(
        release: String,
        pair: CpuPair,
        values: Map<String, Long>,
    ): ProfileConfig

    /** Rebuilds the in-memory sparse map from a set of edited dotted paths. */
    suspend fun updateAdvanced(
        release: String,
        pair: CpuPair,
        values: Map<String, Long>,
    ): ProfileConfig

    /** Drops every edit for the release. */
    suspend fun reset(release: String, pair: CpuPair): ProfileConfig

    /** Drops only the general (execution tuning) edits. */
    suspend fun resetGeneral(release: String, pair: CpuPair): ProfileConfig

    /** Drops route/fallback and advanced edits, keeping general ones. */
    suspend fun resetAdvanced(release: String, pair: CpuPair): ProfileConfig

    /** Removes the explicit CPU selection from the edits. */
    suspend fun clearSelectedCpus(release: String, pair: CpuPair): ProfileConfig

    /** Sets the explicit route; null restores the profile's own route. */
    suspend fun updateRoute(release: String, pair: CpuPair, route: String?): ProfileConfig

    /** Sets "fallback_to"; "none" disables, null removes the declaration. */
    suspend fun updateFallback(release: String, pair: CpuPair, fallbackTo: String?): ProfileConfig

    /** Renders the active document as the HOCON an export writes. */
    fun renderResolved(release: String, pair: CpuPair): String?

    /** Renders the resolved document verbatim (no trimming) for debug dumps. */
    fun renderResolvedForDebug(release: String, pair: CpuPair): String?

    /** Fields where this source differs from the bundled profile for [release]. */
    fun diffAgainstBundle(release: String, pair: CpuPair): List<ProfileDiffRow>

    /** Makes the bundle the session's base while keeping its edits. */
    suspend fun rebaseToBundle(release: String, pair: CpuPair): ProfileConfig

    /** Releases listed by the bundled kernel_profiles/index.conf. */
    suspend fun builtinReleases(): List<String>

    /** Manually selected builtin source, or null for automatic matching. */
    fun activeBuiltinRelease(): String?

    /** External document selected for the device release, or null. */
    fun activeExternalProfile(): ExternalProfileInfo?

    /**
     * Selects the SD-card document [uri] for [deviceRelease]. Returns null when
     * it cannot be read or carries no entry for that release; the previous
     * selection is then untouched.
     */
    suspend fun selectExternalProfile(
        uri: String,
        deviceRelease: String,
        pair: CpuPair,
    ): ProfileConfig?

    /** Drops the external selection; the bundle (or builtin) applies again. */
    suspend fun clearExternalProfile(deviceRelease: String, pair: CpuPair): ProfileConfig

    /**
     * Dangerous escape hatch: use another built-in profile as the source for
     * the current device. Null restores automatic matching. Also clears the
     * external selection, because the last explicit choice wins.
     */
    suspend fun selectBuiltin(
        release: String?,
        deviceRelease: String,
        pair: CpuPair,
    ): ProfileConfig

    /**
     * Typed binary document handed to the native process for [config]'s
     * release and pair; null when the source cannot be resolved.
     */
    fun nativeDocument(config: ProfileConfig): ByteArray?

    companion object {
        /** Reference templates ("6.6-template"): manually loadable, never auto-matched. */
        const val TemplateSuffix = "-template"
    }
}
