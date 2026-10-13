package com.ghostlock.app.domain.repository

import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.DebugSettings
import com.ghostlock.app.domain.model.KernelSnapshot
import com.ghostlock.app.domain.model.OffsetCandidate
import com.ghostlock.app.domain.model.OffsetImportResult
import com.ghostlock.app.domain.model.ParseResult
import com.ghostlock.app.domain.model.ProfileConfig
import com.ghostlock.app.domain.model.RunLogEntry
import com.ghostlock.app.domain.model.UserProfileFile

interface GhostlockRepository {
    suspend fun snapshot(): KernelSnapshot

    fun selectCpuPair(index: Int)

    fun setSafeModeEnabled(enabled: Boolean)

    /** Skip the pre-attack KernelSU check and run the exploit as a test. */
    fun setForceAttackTest(enabled: Boolean)

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

    /**
     * Imports one or more picked documents (file name -> text). Includes are
     * resolved against the picked files first, then the bundled assets; a
     * missing include fails the import so the user can pick it too.
     */
    suspend fun importOffsets(documents: Map<String, String>): OffsetImportResult

    suspend fun confirmImport(documents: Map<String, String>): OffsetImportResult

    suspend fun parseSource(
        input: String,
        xblPath: String? = null,
        uefiPath: String? = null,
        /** vendor_boot.img (MediaTek only); derives kernel_phys_load AND
         * kernel_phys_offset from its header. */
        vendorBootPath: String? = null,
        overwrite: Boolean = false,
        onLog: (String) -> Unit = {},
    ): ParseResult

    suspend fun readDocument(uri: String): String

    suspend fun cacheDocument(uri: String, fileName: String): String

    suspend fun publishOffsets(candidate: OffsetCandidate): String

    /** Verbatim user-imported documents, newest first. */
    suspend fun userProfiles(): List<UserProfileFile>

    suspend fun deleteUserProfile(name: String): Boolean

    /** Returns the resulting file name, or null when the rename failed. */
    suspend fun renameUserProfile(name: String, newName: String): String?

    /** Renders a stored document as HOCON, writes it to Downloads and shares it. */
    suspend fun exportUserProfile(name: String): String

    /**
     * Converts a legacy stored document into the current layout, stores the
     * result as a new user document and returns its file name.
     */
    suspend fun convertUserProfile(name: String): String?

    /**
     * Opens an isolated editing session for the saved profile [name] (null for
     * the current builtin source) and returns its resolved configuration. The
     * session never touches the live attack controller until committed.
     */
    suspend fun beginEditSession(name: String?): ProfileConfig?

    /** Controller of the open editing session, null when none is open. */
    fun editSessionController(): ProfileConfigController?

    /** True when the session edits the profile the attack controller loads. */
    fun editSessionIsLive(): Boolean

    /** File name edited by the open session; null when it edits the builtin. */
    fun editSessionTarget(): String?

    /** Copies the session overrides into the live controller. */
    suspend fun commitEditSession(): Boolean

    /** Updates the edited document in place with the session result. */
    suspend fun saveEditSessionInPlace(): Boolean

    /** Stores the session result as a new saved profile; returns its name. */
    suspend fun saveEditSessionAsNew(): String?

    /** Renders the session result as HOCON, writes it to Downloads, shares it. */
    suspend fun exportEditSession(): String

    /** Release the editing session targets; a stored document uses its own. */
    fun editSessionRelease(): String?

    fun endEditSession()

    /** Single authority for loading, editing and exporting profile config. */
    fun profileController(): ProfileConfigController

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
