package com.ghostlock.app.domain.repository

import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.DebugSettings
import com.ghostlock.app.domain.model.ExternalProfileInfo
import com.ghostlock.app.domain.model.KernelSnapshot
import com.ghostlock.app.domain.model.LegacyProfileState
import com.ghostlock.app.domain.model.MeasuredKernelInfo
import com.ghostlock.app.domain.model.MeasurementMergeRow
import com.ghostlock.app.domain.model.OffsetCandidate
import com.ghostlock.app.domain.model.OffsetImportResult
import com.ghostlock.app.domain.model.ParseResult
import com.ghostlock.app.domain.model.ProfileConfig
import com.ghostlock.app.domain.model.ProfileDiffRow
import com.ghostlock.app.domain.model.RunLogEntry
import com.ghostlock.app.domain.model.StrideProbe
import com.ghostlock.app.domain.model.UserProfileFile
import com.ghostlock.app.domain.model.VrKoMode

interface GhostlockRepository {
    suspend fun snapshot(): KernelSnapshot

    fun selectCpuPair(index: Int)

    fun setSafeModeEnabled(enabled: Boolean)

    /** Skip the pre-attack KernelSU check and run the exploit as a test. */
    fun setForceAttackTest(enabled: Boolean)

    /** The user's vr.ko task-tag-clear choice (Auto recommends; On/Off are final). */
    fun setVrKoTagClear(mode: VrKoMode)

    /** The user's vr.ko SELinux-write-block choice (Auto recommends; On/Off are final). */
    fun setVrKoSelinuxBlock(mode: VrKoMode)

    /**
     * Build identity whose "layers were disabled" start-up notice the user has
     * already seen; null when none. The notice fires once per build, because a
     * new build is what disables the layers and the user has to be told once,
     * not every launch (PORT-PLAN Phase 8 §C.12a/12b).
     */
    fun layerNoticeAcknowledged(): String?

    /** Records that the start-up notice for [build] has been shown. */
    fun acknowledgeLayerNotice(build: String)

    fun setShizukuEnabled(enabled: Boolean)

    suspend fun parseSource(
        input: String,
        xblPath: String? = null,
        uefiPath: String? = null,
        /** vendor_boot.img (MediaTek only); derives kernel_phys_load from
         * its header and kernel_phys_offset from its embedded DTB /memory. */
        vendorBootPath: String? = null,
        /** dtbo.img (MediaTek only): the DTB fallback when vendor_boot carries
         * no usable /memory (`dtb_size = 0` or no root memory node). */
        dtboPath: String? = null,
        overwrite: Boolean = false,
        /** Selects one route explicitly; null lets the extractor decide and
         * returns [ParseResult.Ambiguous] when more than one is Feasible. */
        route: String? = null,
        onLog: (String) -> Unit = {},
    ): ParseResult

    /**
     * Run the unprivileged mm_struct leak probe for an in-memory generated
     * document and return its stride evidence table, or null when the probe
     * cannot run. Only meaningful when [release] is the running kernel.
     */
    suspend fun probeStride(
        release: String,
        documentText: String,
        pair: CpuPair,
        onLog: (String) -> Unit = {},
    ): StrideProbe?

    /**
     * Applies (or clears, with null) `kernelsnitch.mm_struct_sz` to the entry of
     * [release] in an in-memory document and returns the rendered text.
     */
    fun applyStrideToDocument(
        documentText: String,
        release: String,
        stride: Int?,
    ): String?

    /**
     * Applies the user's lock-source choice to an in-memory generated document:
     * `keepAnchor = false` removes the `lock_anchor_*` triple (page mode) and
     * returns the rendered text; `true` returns the text unchanged.
     */
    fun applyLockSourceToDocument(
        documentText: String,
        keepAnchor: Boolean,
    ): String?

    /* ---- profile sources (measured-db storage model) ---- */

    /** External document selected for the device release, or null. */
    fun activeExternalProfile(): ExternalProfileInfo?

    /**
     * Selects the SD-card document [uri] for the running kernel. Null when it
     * cannot be read or carries no entry for this release; the previous
     * selection is then untouched.
     */
    suspend fun selectExternalProfile(uri: String): ProfileConfig?

    /** Drops the external selection; the bundle (or builtin) applies again. */
    suspend fun clearExternalProfile(): ProfileConfig

    /** Renders the active source as the HOCON an export writes, lineage included. */
    fun liveProfileDocument(): String?

    /** Writes an exported profile into the document the user picked. */
    suspend fun writeProfileDocument(uri: String, text: String): Boolean

    /* ---- editing session: in-memory, export-only ---- */

    /** Opens an isolated editing session on the active source. */
    suspend fun beginEditSession(): ProfileConfig?

    /** Controller of the open editing session, null when none is open. */
    fun editSessionController(): ProfileConfigController?

    /** Label of the source the session started from; null when none. */
    fun editSessionTarget(): String?

    /** Release the editing session targets. */
    fun editSessionRelease(): String?

    /** Renders the session's result; the caller writes it through SAF. */
    fun editSessionDocument(): String?

    /** Fields where the session result differs from the bundle. */
    fun editSessionDiff(): List<ProfileDiffRow>

    /** Moves the session's base to the bundle while keeping its edits. */
    suspend fun rebaseEditSession(): ProfileConfig?

    fun endEditSession()

    /* ---- measured database ---- */

    /** Per-kernel measured facts, read-only; never a precedence layer. */
    suspend fun measurements(): List<MeasuredKernelInfo>

    /** Facts that would change the active profile for the running kernel. */
    suspend fun measurementMergeDiff(): List<MeasurementMergeRow>

    /** The active profile with every measured fact applied, ready to export. */
    fun mergedProfileDocument(): String?

    /* ---- legacy app-data cleanup (one-time) ---- */

    /** What a pre-measured-db install left in app data. */
    suspend fun legacyState(): LegacyProfileState

    /** Renders one legacy document, optionally with the stored override applied. */
    fun legacyProfileDocument(name: String, applyOverride: Boolean): String?

    /** Deletes the legacy documents and the override. Only after confirmation. */
    suspend fun finishLegacyCleanup(): Boolean

    /** Single authority for loading, editing and exporting profile config. */
    fun profileController(): ProfileConfigController

    suspend fun readDocument(uri: String): String

    suspend fun cacheDocument(uri: String, fileName: String): String

    /** Legacy app-data documents, newest first (cleanup screen only). */
    suspend fun userProfiles(): List<UserProfileFile>

    suspend fun debugSettings(): DebugSettings

    fun setDebugKernelLogEnabled(enabled: Boolean)

    /** Runs retained on the device, newest first, an unfinished one ahead of the rest. */
    suspend fun listRunLogs(): List<RunLogEntry>

    /** Streams one retained run into a document the user picked; false if it failed. */
    suspend fun exportRunLog(stamp: String, documentUri: String): Boolean

    suspend fun clearRunLogs()

    /**
     * Marks every run still recorded as running when the app starts: it was
     * killed with the device. Returns how many. See `RunLogStore`.
     */
    suspend fun markInterruptedRunLogs(): Int

    suspend fun runExploit(pair: CpuPair, onLog: (String) -> Unit): Int

    suspend fun runExploitWithShizuku(pair: CpuPair, onLog: (String) -> Unit): Int

    /**
     * The step left `in_progress` by the previous run (usually a kernel panic),
     * or null when the last run completed/failed cleanly. `w3*` means Shizuku
     * (shell uid, no seccomp) can skip that stage.
     */
    suspend fun lastRunStuckStep(): String?

    fun requestShizukuPermission()

    fun setShizukuStatusListener(listener: (() -> Unit)?)

    fun close()
}
