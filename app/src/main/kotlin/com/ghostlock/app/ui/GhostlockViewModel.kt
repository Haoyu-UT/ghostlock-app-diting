package com.ghostlock.app.ui

import android.net.Uri
import androidx.core.net.toUri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.ghostlock.app.R
import com.ghostlock.app.data.MeasuredProfileStore
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ExternalProfileInfo
import com.ghostlock.app.domain.model.KernelSnapshot
import com.ghostlock.app.domain.model.LegacyProfileState
import com.ghostlock.app.domain.model.LogTone
import com.ghostlock.app.domain.model.MeasuredKernelInfo
import com.ghostlock.app.domain.model.MeasurementMergeRow
import com.ghostlock.app.domain.model.ParseResult
import com.ghostlock.app.domain.model.PhysImage
import com.ghostlock.app.domain.model.PhysPromptState
import com.ghostlock.app.domain.model.ProfileConfig
import com.ghostlock.app.domain.model.nextPhysImage
import com.ghostlock.app.domain.model.sourceSuppliesLoad
import com.ghostlock.app.domain.model.ProfileDiffRow
import com.ghostlock.app.domain.model.RunLogEntry
import com.ghostlock.app.domain.model.ProfileFieldNode
import com.ghostlock.app.domain.model.RouteVerdict
import com.ghostlock.app.domain.model.ShizukuStatus
import com.ghostlock.app.domain.model.StrideProbe
import com.ghostlock.app.domain.model.VrKoMode
import com.ghostlock.app.domain.repository.GhostlockRepository
import com.ghostlock.app.domain.repository.ProfileConfigController
import com.ghostlock.app.domain.usecase.FormatLogUseCase
import com.ghostlock.app.domain.usecase.LoadKernelSnapshotUseCase
import com.ghostlock.app.domain.usecase.ParseSourceUseCase
import com.ghostlock.app.domain.usecase.ReadDocumentUseCase
import com.ghostlock.app.domain.usecase.RunExploitUseCase
import com.ghostlock.app.domain.usecase.SelectCpuPairUseCase
import java.util.Locale
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface GhostlockEffect {
    data class PickDocument(val request: DocumentRequest) : GhostlockEffect
    data class CreateProfileDocument(val suggestedName: String) : GhostlockEffect

    /** Save dialog for one retained run log; the app streams the zip into it. */
    data class CreateRunLogDocument(val suggestedName: String) : GhostlockEffect
    data class Share(val uri: String) : GhostlockEffect
    data class Toast(val resourceId: Int) : GhostlockEffect
    data class Clipboard(val text: String) : GhostlockEffect
    data class KeepScreenAwake(val enabled: Boolean) : GhostlockEffect
    data object OpenShizuku : GhostlockEffect
}

private const val OverwriteSummaryLimit = 12

enum class DocumentRequest {
    SelectProfile, BootImage, XblImage, PayloadImage, UefiImage, VendorBootImage, DtboImage,
}

/** The parse pass in flight: the input plus the images attached so far. */
private data class ParseRequest(
    val input: String,
    val xblPath: String? = null,
    val uefiPath: String? = null,
    val vendorBootPath: String? = null,
    val dtboPath: String? = null,
    val overwrite: Boolean = false,
    val route: String? = null,
)

private enum class ParseDialogStage { Mode, PhysImage, Route, Lock, Source }

class GhostlockViewModel(
    private val repository: GhostlockRepository,
) : ViewModel() {
    private val effectChannel = Channel<GhostlockEffect>(Channel.BUFFERED)
    private val mutableState = MutableStateFlow(GhostlockUiState())
    private var initialized = false
    private var running = false
    private val loadKernelSnapshot = LoadKernelSnapshotUseCase(repository)
    private val selectCpuPairUseCase = SelectCpuPairUseCase(repository)
    private val parseSourceUseCase = ParseSourceUseCase(repository)
    private val readDocumentUseCase = ReadDocumentUseCase(repository)
    private val runExploitUseCase = RunExploitUseCase(repository)
    private val formatLog = FormatLogUseCase()
    private val profileController get() = repository.profileController()

    val state = mutableState.asStateFlow()
    val effects = effectChannel.receiveAsFlow()

    private var kernelSnapshot: KernelSnapshot? = null
    private var pendingParse: ParseRequest? = null
    /** The platform's recommended images already offered this session. */
    private var physVendorBootOffered = false
    private var physXblOffered = false
    private var physUefiOffered = false
    private var physDtboOffered = false
    /** The phys prompt on screen and the parsed result waiting behind it. */
    private var pendingPhysImage: PhysImage? = null
    private var pendingPhysAfter: ParseResult.Parsed? = null
    private var parseDialogStage = ParseDialogStage.Mode
    private var pendingConfirmation: PendingConfirmation? = null
    /** The pass that reported Ambiguous, re-run with the picked route. */
    private var pendingRouteParse: ParseRequest? = null
    private var pendingRouteChoices: List<RouteVerdict> = emptyList()
    private var pendingLockParse: ParseResult.Parsed? = null

    /** The generated document and its stride evidence, held while the picker is up. */
    private var pendingStrideParse: ParseResult.Parsed? = null
    private var pendingStrideProbe: StrideProbe? = null
    /** In-memory generated document; never stored until the user exports it. */
    private var pendingStrideDocument: String? = null
    private var pendingStrideName: String? = null
    private var pendingStrideRelease: String? = null

    /** The document text and behaviour waiting for the user's export destination. */
    private data class PendingProfileWrite(
        val text: String,
        val suggestedName: String,
        /** Offer to select the written document for the next run. */
        val selectAfterWrite: Boolean,
    )

    private var pendingProfileWrite: PendingProfileWrite? = null
    /** URI of a just-written profile awaiting the "use it?" confirmation. */
    private var pendingSelectUri: String? = null

    /** The layer notice is decided once per process, from the first resolution. */
    private var layerNoticeChecked = false

    fun initialize() {
        if (initialized) return
        initialized = true
        repository.setShizukuStatusListener { refreshAccessStatus() }
        viewModelScope.launch {
            refreshSnapshot()
            markInterruptedRunLogs()
            applyRecommendedShizuku()
            maybeSuggestShizukuForW3()
            refreshLegacyState()
        }
    }

    private var interruptedRunLogsMarked = false

    /**
     * A run writes a terminal state when it ends, so anything still `running`
     * when the app starts was killed with the device — the case a report is
     * usually about. Naming it here costs one directory scan per start.
     */
    private suspend fun markInterruptedRunLogs() {
        if (interruptedRunLogsMarked) return
        interruptedRunLogsMarked = true
        runCatching { repository.markInterruptedRunLogs() }
    }

    private var recommendedShizukuApplied = false

    /**
     * Kernels that recommend Shizuku start with the toggle on at every launch;
     * a manual switch-off still applies for the rest of the session.
     */
    private fun applyRecommendedShizuku() {
        if (recommendedShizukuApplied) return
        recommendedShizukuApplied = true
        val snapshot = kernelSnapshot ?: return
        if (!snapshot.recommendShizuku || state.value.shizukuEnabled) return
        toggleShizuku(true)
    }

    private var w3HintChecked = false

    /**
     * The previous run's native log survives export settings; when it failed
     * at the W3 seccomp bypass in-process, suggest switching to Shizuku.
     */
    private suspend fun maybeSuggestShizukuForW3() {
        if (w3HintChecked) return
        w3HintChecked = true
        val step = runCatching { repository.lastRunStuckStep() }.getOrNull() ?: return
        if (state.value.shizukuEnabled) return
        /* Any interrupted step is reported; only a W3 stall offers Shizuku,
         * because Shizuku (shell uid, no seccomp) skips exactly that stage. */
        val isW3 = step.startsWith("w3")
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = if (isW3) DialogType.CONFIRM else DialogType.NOTICE,
                dialogTitleRes = if (isW3) {
                    R.string.w3_shizuku_hint_title
                } else {
                    R.string.run_interrupted_title
                },
                dialogMessageRes = if (isW3) {
                    R.string.w3_shizuku_hint_message
                } else {
                    R.string.run_interrupted_message
                },
                /* Both notices that say "your run did not finish" carry the
                 * export: whichever one a reporter is looking at, the log they
                 * need to send is one tap away. */
                dialogExportLog = true,
            )
        }
    }

    fun refreshAccessStatus() {
        if (initialized) viewModelScope.launch { refreshSnapshot() }
    }

    /* profile-ui: the controller owns loading, merging and persistence. */
    fun loadExecutionProfile(preserveEditing: Boolean = false) {
        val snapshot = kernelSnapshot ?: return
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return
        viewModelScope.launch(Dispatchers.IO) {
            applyExecutionConfig(profileController.load(snapshot.kernelRelease, pair), preserveEditing)
            refreshMergeRows()
        }
    }

    private fun applyExecutionConfig(config: ProfileConfig, preserveEditing: Boolean) {
        mutableState.update { state ->
            state.copy(
                executionRelease = config.release,
                executionHasProfile = config.hasProfile,
                executionFields = config.general,
                executionEditing = if (preserveEditing) state.executionEditing
                else config.general.associate { field -> field.path to field.value.toString() },
                profileInvalidPaths = config.invalidPaths,
                profileRoute = config.route,
                profileFallback = config.fallbackTo,
                activeBuiltinProfile = profileController.activeBuiltinRelease(),
                externalProfile = profileController.activeExternalProfile(),
                activeUserProfile = config.layers
                    ?.takeIf { it.externalApplied }
                    ?.external,
                profileLayers = config.layers,
                customCpuPair = customCpuPairOf(config),
            )
        }
        if (!preserveEditing) maybeRaiseLayerNotice(config)
    }

    /** Recomputes the facts the home merge would change; cheap, runs on IO. */
    private suspend fun refreshMergeRows() {
        val rows = runCatching { repository.measurementMergeDiff() }.getOrDefault(emptyList())
        mutableState.update { it.copy(mergeRows = rows) }
    }

    private suspend fun refreshLegacyState() {
        val legacy = runCatching { repository.legacyState() }.getOrNull() ?: LegacyProfileState()
        mutableState.update {
            it.copy(
                legacyPresent = legacy.present,
                legacyProfiles = legacy.profiles,
                legacyOverridePresent = legacy.overridePresent,
            )
        }
    }

    /**
     * The layers this config reports are the ones a run would use right now: the
     * notice is driven by the resolution itself, never by a predicate the UI
     * recomputes, so what it says has already happened (§C.12b). Once per build
     * identity — the point is to tell the user what the update did, not to nag.
     */
    private fun maybeRaiseLayerNotice(config: ProfileConfig) {
        val layers = config.layers ?: return
        if (layerNoticeChecked) return
        layerNoticeChecked = true
        if (!layers.noticeDue(repository.layerNoticeAcknowledged())) return
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.NOTICE,
                dialogTitleRes = R.string.layer_notice_title,
                dialogMessageRes = 0,
                dialogMessage = "",
                dialogDocUrl = null,
                dialogConfirmLabelRes = R.string.dialog_dismiss,
                dialogLayerNotice = layers,
            )
        }
    }

    /** The pair actually resolved from the profile, when it beats the device pick. */
    private fun customCpuPairOf(config: ProfileConfig): CpuPair? {
        val snapshot = kernelSnapshot ?: return null
        val main = config.general
            .firstOrNull { it.path == "execution.selected_cpus.main" }?.value ?: return null
        val consumer = config.general
            .firstOrNull { it.path == "execution.selected_cpus.consumer" }?.value ?: return null
        val pair = CpuPair(main.toInt(), consumer.toInt())
        return pair.takeIf { it != snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) }
    }

    /** Route edits are draft-only; saving the session commits them. */
    fun onRouteChanged(index: Int) {
        val route = ProfileConfig.Routes.getOrNull(index - 1)
        if (route == state.value.profileRoute) return
        mutableState.update { it.copy(profileRoute = route) }
    }

    /** index 0 disables the fallback; the rest map to ProfileConfig.Routes. */
    fun onFallbackChanged(index: Int) {
        val fallback = if (index <= 0) "none" else ProfileConfig.Routes.getOrNull(index - 1)
        val current = state.value.profileFallback
        if (fallback == current || (fallback == "none" && current == null)) return
        mutableState.update { it.copy(profileFallback = fallback) }
    }

    /** General edits are draft-only; saving the session commits them. */
    fun updateExecutionField(path: String, value: String) {
        mutableState.update {
            it.copy(
                executionEditing = it.executionEditing + (path to value),
            )
        }
    }

    /* advanced-ui: the merged screen loads its editors and debug prefs. */
    fun onOpenAdvanced() {
        mutableState.update {
            it.copy(
                advancedScreenVisible = true,
                vrKoVisible = false,
                aboutVisible = false,
                measurementsVisible = false,
                parametersVisible = false,
                loadConfigVisible = false,
                builtinScreenVisible = false,
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
            )
        }
        loadExecutionProfile()
        viewModelScope.launch(Dispatchers.IO) {
            val settings = repository.debugSettings()
            mutableState.update {
                it.copy(
                    debugKernelLogEnabled = settings.kernelLogEnabled,
                )
            }
        }
    }

    fun onCloseAdvanced() {
        mutableState.update {
            it.copy(
                advancedScreenVisible = false,
                vrKoVisible = false,
                aboutVisible = false,
                measurementsVisible = false,
                parametersVisible = false,
                loadConfigVisible = false,
                builtinScreenVisible = false,
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
            )
        }
    }

    /** Opens the vr.ko anti-root countermeasure options screen from the home entry. */
    fun onOpenVrKo() {
        mutableState.update {
            it.copy(
                vrKoVisible = true,
                advancedScreenVisible = false,
                aboutVisible = false,
                measurementsVisible = false,
                parametersVisible = false,
                loadConfigVisible = false,
                builtinScreenVisible = false,
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
            )
        }
    }

    fun onCloseVrKo() {
        mutableState.update { it.copy(vrKoVisible = false) }
    }

    /** Opens the read-only measured-facts screen and refreshes its store. */
    fun onOpenMeasurements() {
        mutableState.update { it.copy(measurementsVisible = true) }
        viewModelScope.launch(Dispatchers.IO) {
            val kernels = runCatching { repository.measurements() }.getOrDefault(emptyList())
            mutableState.update { it.copy(measuredKernels = kernels) }
        }
    }

    fun onCloseMeasurements() {
        mutableState.update { it.copy(measurementsVisible = false) }
    }

    fun onOpenParameters() {
        mutableState.update {
            it.copy(
                advancedScreenVisible = true,
                parametersVisible = true,
                loadConfigVisible = false,
                builtinScreenVisible = false,
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
            )
        }
        loadExecutionProfile()
    }

    fun onCloseParameters() {
        mutableState.update {
            it.copy(
                parametersVisible = false,
                loadConfigVisible = false,
                builtinScreenVisible = false,
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
            )
        }
    }

    /** Opens the configuration-loading screen (source selection). */
    fun onOpenLoadConfig() {
        mutableState.update {
            it.copy(
                loadConfigVisible = true,
                builtinScreenVisible = false,
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
            )
        }
        viewModelScope.launch(Dispatchers.IO) { refreshLegacyState() }
    }

    fun onCloseLoadConfig() {
        mutableState.update { it.copy(loadConfigVisible = false, builtinScreenVisible = false) }
    }

    /** Picks an SD-card profile document; selecting it wins over the bundle. */
    fun onSelectProfileFile() {
        send(GhostlockEffect.PickDocument(DocumentRequest.SelectProfile))
    }

    private fun selectExternalProfile(uri: String) {
        val snapshot = kernelSnapshot ?: return
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val config = runCatching { repository.selectExternalProfile(uri) }.getOrNull()
            if (config == null) {
                send(GhostlockEffect.Toast(R.string.user_profile_load_failed))
                return@launch
            }
            applyExecutionConfig(config, preserveEditing = false)
            applyAdvancedConfig(config, preserveEditing = false)
            refreshSnapshot()
            refreshMergeRows()
            send(GhostlockEffect.Toast(R.string.user_profile_loaded))
        }
    }

    fun onClearExternalProfile() {
        viewModelScope.launch(Dispatchers.IO) {
            val config = runCatching { repository.clearExternalProfile() }.getOrNull()
            if (config == null) {
                send(GhostlockEffect.Toast(R.string.user_profile_load_failed))
                return@launch
            }
            applyExecutionConfig(config, preserveEditing = false)
            applyAdvancedConfig(config, preserveEditing = false)
            refreshSnapshot()
            refreshMergeRows()
            send(GhostlockEffect.Toast(R.string.user_profile_unloaded))
        }
    }

    /* ---- measured-db merge ---- */

    fun onOpenMergePreview() {
        viewModelScope.launch(Dispatchers.IO) {
            refreshMergeRows()
            if (state.value.mergeRows.isEmpty()) {
                send(GhostlockEffect.Toast(R.string.merge_nothing))
                return@launch
            }
            mutableState.update { it.copy(mergePreviewVisible = true) }
        }
    }

    fun onCloseMergePreview() {
        mutableState.update { it.copy(mergePreviewVisible = false) }
    }

    fun onExportMergedProfile() {
        val snapshot = kernelSnapshot ?: return
        val text = repository.mergedProfileDocument()
        if (text == null) {
            send(GhostlockEffect.Toast(R.string.export_failed))
            return
        }
        requestProfileWrite(
            PendingProfileWrite(
                text = text,
                suggestedName = exportDocumentName(snapshot.kernelRelease),
                selectAfterWrite = true,
            ),
        )
    }

    /* ---- editor diff/rebase ---- */

    fun onOpenProfileDiff() {
        viewModelScope.launch(Dispatchers.IO) {
            val rows = runCatching { repository.editSessionDiff() }.getOrDefault(emptyList())
            mutableState.update { it.copy(profileDiffRows = rows, profileDiffVisible = true) }
        }
    }

    fun onCloseProfileDiff() {
        mutableState.update { it.copy(profileDiffVisible = false) }
    }

    fun onRebaseToBundle() {
        val snapshot = kernelSnapshot ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val config = runCatching { repository.rebaseEditSession() }.getOrNull()
            if (config == null) {
                send(GhostlockEffect.Toast(R.string.execution_save_failed))
                return@launch
            }
            applyExecutionConfig(config, preserveEditing = false)
            applyAdvancedConfig(config, preserveEditing = false)
            val rows = runCatching { repository.editSessionDiff() }.getOrDefault(emptyList())
            mutableState.update {
                it.copy(
                    editTargetName = repository.editSessionTarget()
                        ?: snapshot.kernelRelease,
                    profileDiffRows = rows,
                )
            }
            send(GhostlockEffect.Toast(R.string.profile_rebased))
        }
    }

    /* ---- legacy app-data cleanup ---- */

    fun onOpenLegacyCleanup() {
        mutableState.update { it.copy(legacyVisible = true) }
        viewModelScope.launch(Dispatchers.IO) { refreshLegacyState() }
    }

    fun onCloseLegacyCleanup() {
        mutableState.update { it.copy(legacyVisible = false, legacyCleanupConfirm = false) }
    }

    fun onLegacyExport(name: String, applyOverride: Boolean) {
        val text = repository.legacyProfileDocument(name, applyOverride)
        if (text == null) {
            send(GhostlockEffect.Toast(R.string.export_failed))
            return
        }
        requestProfileWrite(
            PendingProfileWrite(
                text = text,
                /* A distinct name: the same release may already be exported as
                 * the active profile, and the cleanup export must not replace it. */
                suggestedName = "${name.substringBeforeLast('.').ifEmpty { "profile" }}" +
                    "-legacy.conf",
                selectAfterWrite = false,
            ),
        )
    }

    fun onLegacyCleanupRequest() {
        mutableState.update { it.copy(legacyCleanupConfirm = true) }
    }

    fun onLegacyCleanupDismiss() {
        mutableState.update { it.copy(legacyCleanupConfirm = false) }
    }

    fun onLegacyCleanupConfirm() {
        mutableState.update { it.copy(legacyCleanupConfirm = false) }
        viewModelScope.launch(Dispatchers.IO) {
            val ok = runCatching { repository.finishLegacyCleanup() }.getOrDefault(false)
            refreshLegacyState()
            if (ok) mutableState.update { it.copy(legacyVisible = false) }
            send(
                GhostlockEffect.Toast(
                    if (ok) R.string.legacy_cleanup_done else R.string.legacy_cleanup_failed,
                ),
            )
        }
    }

    /** Queues a document and opens the system destination dialog for it. */
    private fun requestProfileWrite(write: PendingProfileWrite) {
        pendingProfileWrite = write
        send(GhostlockEffect.CreateProfileDocument(write.suggestedName))
    }

    fun onShowAbout() {
        mutableState.update { it.copy(aboutVisible = true) }
    }

    fun onCloseAbout() {
        mutableState.update { it.copy(aboutVisible = false) }
    }

    private var pendingRunLogStamp: String? = null

    /** Opens the picker over the runs kept on the device. */
    fun onExportRunLog() {
        viewModelScope.launch {
            val runs = runCatching { repository.listRunLogs() }.getOrDefault(emptyList())
            mutableState.update { it.copy(runLogs = runs, runLogPickerVisible = true) }
        }
    }

    fun onRunLogPickerDismiss() =
        mutableState.update { it.copy(runLogPickerVisible = false) }

    fun onRunLogSelected(stamp: String) {
        pendingRunLogStamp = stamp
        mutableState.update { it.copy(runLogPickerVisible = false) }
        send(GhostlockEffect.CreateRunLogDocument("$stamp.zip"))
    }

    fun onExportRunLogDocumentPicked(documentUri: String?) {
        val stamp = pendingRunLogStamp ?: return
        pendingRunLogStamp = null
        if (documentUri.isNullOrBlank()) return
        viewModelScope.launch {
            val ok = runCatching { repository.exportRunLog(stamp, documentUri) }
                .getOrDefault(false)
            send(
                GhostlockEffect.Toast(
                    if (ok) R.string.run_log_export_done else R.string.export_failed,
                ),
            )
        }
    }

    fun onClearRunLogs() {
        viewModelScope.launch {
            runCatching { repository.clearRunLogs() }
            mutableState.update { it.copy(runLogs = emptyList(), runLogPickerVisible = false) }
            send(GhostlockEffect.Toast(R.string.run_log_cleared))
        }
    }

    fun onDebugKernelLogChanged(enabled: Boolean) {
        repository.setDebugKernelLogEnabled(enabled)
        mutableState.update { it.copy(debugKernelLogEnabled = enabled) }
    }

    /** Exports the active profile through the system document dialog. */
    fun onExportProfile() {
        val snapshot = kernelSnapshot ?: return
        val text = repository.liveProfileDocument()
        if (text == null) {
            send(GhostlockEffect.Toast(R.string.export_failed))
            return
        }
        requestProfileWrite(
            PendingProfileWrite(
                text = text,
                suggestedName = exportDocumentName(snapshot.kernelRelease),
                selectAfterWrite = false,
            ),
        )
    }

    fun onExportProfileDocumentPicked(documentUri: String?) {
        val write = pendingProfileWrite
        pendingProfileWrite = null
        if (write == null) return
        if (documentUri.isNullOrBlank()) {
            /* A cancelled export loses the document by design: the editor says
             * so before opening the picker (measured-db-plan §4). */
            send(GhostlockEffect.Toast(R.string.export_cancelled))
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            val ok = repository.writeProfileDocument(documentUri, write.text)
            if (!ok) {
                send(GhostlockEffect.Toast(R.string.export_failed))
                return@launch
            }
            if (!write.selectAfterWrite) {
                send(GhostlockEffect.Toast(R.string.override_export_done))
                return@launch
            }
            pendingSelectUri = documentUri
            mutableState.update {
                it.copy(
                    dialogVisible = true,
                    dialogType = DialogType.CONFIRM,
                    dialogTitleRes = R.string.profile_exported_title,
                    dialogMessageRes = R.string.profile_use_question,
                    dialogMessage = "",
                    dialogConfirmLabelRes = R.string.profile_use_confirm,
                    dialogDocUrl = null,
                    dialogExportLog = false,
                    dialogLayerNotice = null,
                )
            }
        }
    }

    private fun exportDocumentName(release: String): String =
        "${release.replace(Regex("[^A-Za-z0-9._-]"), "_")}.conf"

    /* ---- editing session: in-memory, export is the only save ---- */

    private fun currentPair(): CpuPair? {
        val snapshot = kernelSnapshot ?: return null
        return snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair)
    }

    /** Opens the editor for the profile the attack controller currently loads. */
    fun onOpenProfileOverrides() {
        viewModelScope.launch(Dispatchers.IO) {
            val config = runCatching { repository.beginEditSession() }.getOrNull()
            if (config == null) {
                send(GhostlockEffect.Toast(R.string.user_profile_load_failed))
                return@launch
            }
            applyExecutionConfig(config, preserveEditing = false)
            applyAdvancedConfig(config, preserveEditing = false)
            mutableState.update {
                it.copy(
                    builtinScreenVisible = false,
                    advancedOverrideVisible = false,
                    profileOverrideVisible = true,
                    editTargetName = repository.editSessionTarget(),
                    loadConfigVisible = false,
                )
            }
        }
    }

    /** Reloads the session, dropping every unsaved edit. */
    fun onRevertProfileEdits() {
        loadEditSession()
        send(GhostlockEffect.Toast(R.string.profile_reverted))
    }

    private fun loadEditSession(preserveEditing: Boolean = false) {
        val snapshot = kernelSnapshot ?: return
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return
        val session = repository.editSessionController() ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val release = repository.editSessionRelease() ?: snapshot.kernelRelease
            val config = runCatching { session.load(release, pair) }.getOrNull()
                ?: return@launch
            applyExecutionConfig(config, preserveEditing)
            applyAdvancedConfig(config, preserveEditing)
        }
    }

    /** Writes the draft (general, route/fallback, advanced) into the session. */
    private suspend fun commitDraftToSession(): ProfileConfig? {
        val snapshot = kernelSnapshot ?: return null
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return null
        val session = repository.editSessionController() ?: return null
        val release = repository.editSessionRelease() ?: snapshot.kernelRelease
        val general = mutableState.value.executionEditing.mapNotNull { (path, text) ->
            text.trim().toLongOrNull()?.let { value -> path to value }
        }.toMap()
        session.updateGeneral(release, pair, general)
        session.updateRoute(release, pair, mutableState.value.profileRoute)
        session.updateFallback(release, pair, mutableState.value.profileFallback)
        /* General edits share the execution.* tree paths. The advanced rebuild
         * replaces the whole edit map, so the drafts must be merged in or the
         * general edits would be dropped. */
        val drafts = mutableState.value.profileOverrideEditing +
                mutableState.value.executionEditing
        val advanced = drafts.mapNotNull { (path, text) ->
            text.trim().toLongOrNull()?.let { value -> path to value }
        }.toMap()
        return runCatching { session.updateAdvanced(release, pair, advanced) }.getOrNull()
    }

    /**
     * Exports the edited session. There is no other save: the document on the
     * SD card is the profile, and an unexported edit is lost.
     */
    private fun exportEditSession(selectAfterWrite: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            if (commitDraftToSession() == null) {
                send(GhostlockEffect.Toast(R.string.execution_save_failed))
                return@launch
            }
            val snapshot = kernelSnapshot ?: return@launch
            val text = repository.editSessionDocument()
            if (text == null) {
                send(GhostlockEffect.Toast(R.string.export_failed))
                return@launch
            }
            val stem = repository.editSessionTarget()
                ?.substringBeforeLast('.')
                ?.takeIf { it.isNotEmpty() }
                ?: snapshot.kernelRelease.replace(Regex("[^A-Za-z0-9._-]"), "_")
            requestProfileWrite(
                PendingProfileWrite(
                    text = text,
                    suggestedName = "$stem.conf",
                    selectAfterWrite = selectAfterWrite,
                ),
            )
        }
    }

    fun onSaveProfileEdits() = exportEditSession(selectAfterWrite = true)

    fun onSaveProfileAs() = exportEditSession(selectAfterWrite = true)

    fun onExportProfileEdits() = exportEditSession(selectAfterWrite = true)

    /** Opens the builtin picker; overrides stay keyed to the device kernel. */
    fun onOpenBuiltinProfiles() {
        val snapshot = kernelSnapshot ?: return
        mutableState.update { it.copy(builtinScreenVisible = true) }
        viewModelScope.launch(Dispatchers.IO) {
            val releases = runCatching { profileController.builtinReleases() }
                .getOrDefault(emptyList())
            val templates = releases.filter {
                it.endsWith(ProfileConfigController.TemplateSuffix)
            }
            val kernels = releases.filterNot {
                it.endsWith(ProfileConfigController.TemplateSuffix)
            }
            if (templates.isEmpty() && kernels.isEmpty()) {
                send(GhostlockEffect.Toast(R.string.load_builtin_failed))
                return@launch
            }
            mutableState.update {
                it.copy(
                    builtinTemplates = sortByKernelSimilarity(
                        snapshot.kernelRelease, templates,
                    ),
                    builtinProfiles = sortByKernelSimilarity(
                        snapshot.kernelRelease, kernels,
                    ),
                )
            }
        }
    }

    fun onCloseBuiltinProfiles() {
        mutableState.update { it.copy(builtinScreenVisible = false) }
    }

    fun onSelectBuiltinProfile(release: String?) {
        val snapshot = kernelSnapshot ?: return
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return
        viewModelScope.launch(Dispatchers.IO) {
            /* The controller keeps a single active source: picking a builtin
             * also clears the external selection (last explicit choice wins). */
            val config = runCatching {
                profileController.selectBuiltin(release, snapshot.kernelRelease, pair)
            }.getOrNull()
            if (config == null) {
                send(GhostlockEffect.Toast(R.string.load_builtin_failed))
                return@launch
            }
            applyExecutionConfig(config, preserveEditing = false)
            applyAdvancedConfig(config, preserveEditing = false)
            refreshSnapshot()
            refreshMergeRows()
            send(GhostlockEffect.Toast(R.string.load_builtin_done))
        }
    }

    /** Orders releases by absolute major/minor/fix/android distance to device. */
    private fun sortByKernelSimilarity(deviceRelease: String, releases: List<String>): List<String> {
        val device = kernelVersionKey(deviceRelease)
        return releases.sortedWith(Comparator { a, b ->
            compareIntLists(
                similarityKey(device, kernelVersionKey(a)),
                similarityKey(device, kernelVersionKey(b)),
            )
        })
    }

    private fun kernelVersionKey(release: String): List<Int> {
        val version = release.substringBefore('-').split('.')
            .mapNotNull { it.toIntOrNull() }
        val android = Regex("-android(\\d+)").find(release)
            ?.groupValues?.get(1)?.toIntOrNull()
        return if (android == null) version else version + android
    }

    private fun similarityKey(device: List<Int>, candidate: List<Int>): List<Int> =
        (0 until maxOf(device.size, candidate.size)).map { index ->
            kotlin.math.abs((device.getOrNull(index) ?: 0) - (candidate.getOrNull(index) ?: 0))
        }

    private fun compareIntLists(a: List<Int>, b: List<Int>): Int {
        for (index in 0 until maxOf(a.size, b.size)) {
            val result = (a.getOrNull(index) ?: 0).compareTo(b.getOrNull(index) ?: 0)
            if (result != 0) return result
        }
        return 0
    }

    fun onCloseProfileOverrides() {
        repository.endEditSession()
        mutableState.update {
            it.copy(
                profileOverrideVisible = false,
                advancedOverrideVisible = false,
                editTargetName = null,
            )
        }
    }

    fun onOpenAdvancedOverrides() {
        mutableState.update { it.copy(advancedOverrideVisible = true) }
        loadEditSession()
    }

    fun onCloseAdvancedOverrides() {
        mutableState.update { it.copy(advancedOverrideVisible = false) }
    }

    /** Advanced edits are draft-only; saving the session commits them. */
    fun onProfileOverrideChanged(path: String, value: String) {
        mutableState.update {
            it.copy(
                profileOverrideEditing = it.profileOverrideEditing + (path to value),
            )
        }
    }

    private fun applyAdvancedConfig(config: ProfileConfig, preserveEditing: Boolean) {
        mutableState.update { state ->
            state.copy(
                profileOverrideRelease = config.release,
                profileOverrideRoots = config.roots,
                profileOverrideEditing = if (preserveEditing) state.profileOverrideEditing
                else flattenLeaves(config.roots).associate { field ->
                    field.path to (field.value?.toString() ?: "")
                },
                profileInvalidPaths = config.invalidPaths,
                profileRoute = config.route,
                profileFallback = config.fallbackTo,
                activeBuiltinProfile = profileController.activeBuiltinRelease(),
                externalProfile = profileController.activeExternalProfile(),
                activeUserProfile = config.layers?.takeIf { it.externalApplied }?.external,
                profileLayers = config.layers,
            )
        }
    }

    private fun flattenLeaves(nodes: List<ProfileFieldNode>): List<ProfileFieldNode> =
        nodes.flatMap { node -> if (node.isGroup) flattenLeaves(node.children) else listOf(node) }

    fun selectCpuPair(index: Int) {
        val snapshot = kernelSnapshot ?: return
        if (index !in snapshot.cpuPairs.indices) return
        selectCpuPairUseCase(index)
        kernelSnapshot = snapshot.copy(selectedCpuPair = index)
        mutableState.update { it.copy(cpuPairIndex = index) }
        /* Picking a preset pair replaces an explicit profile selection. */
        if (mutableState.value.customCpuPair != null) {
            viewModelScope.launch(Dispatchers.IO) {
                val config = runCatching {
                    profileController.clearSelectedCpus(
                        snapshot.kernelRelease,
                        snapshot.cpuPairs[index],
                    )
                }.getOrNull() ?: return@launch
                applyExecutionConfig(config, preserveEditing = false)
                applyAdvancedConfig(config, preserveEditing = false)
            }
        }
    }

    fun toggleSafeMode(enabled: Boolean) {
        repository.setSafeModeEnabled(enabled)
        mutableState.update { it.copy(safeModeEnabled = enabled) }
    }

    fun toggleForceAttackTest(enabled: Boolean) {
        repository.setForceAttackTest(enabled)
        mutableState.update { it.copy(forceAttackTestEnabled = enabled) }
    }

    fun setVrKoTagClear(mode: VrKoMode) {
        repository.setVrKoTagClear(mode)
        mutableState.update { it.copy(vrKoTagClear = mode) }
    }

    fun setVrKoSelinuxBlock(mode: VrKoMode) {
        repository.setVrKoSelinuxBlock(mode)
        mutableState.update { it.copy(vrKoSelinuxBlock = mode) }
    }

    fun toggleShizuku(enabled: Boolean) {
        repository.setShizukuEnabled(enabled)
        mutableState.update { it.copy(shizukuEnabled = enabled) }
        if (!enabled && kernelSnapshot?.recommendShizuku == true) {
            send(GhostlockEffect.Toast(R.string.shizuku_recommended_hint))
        }
        // The grant dialog lands in another app, so the status is re-read and
        // onResume() refreshes it again when the dialog closes.
        viewModelScope.launch { refreshSnapshot() }
    }

    fun onRun() = runExploit()

    /** Explains why the run button is greyed out. */
    fun onProfileInvalid() {
        val state = state.value
        val messageRes = when {
            !state.executionHasProfile -> R.string.run_blocked_no_profile
            state.shizukuEnabled && state.shizukuStatus != ShizukuStatus.READY ->
                R.string.run_blocked_shizuku

            else -> R.string.profile_invalid
        }
        send(GhostlockEffect.Toast(messageRes))
    }

    fun onStatusClick() {
        val snapshot = kernelSnapshot ?: return
        /* shizukuEnabled already carries the profile suggestion unless the
         * user overrode it (PROFILE-SUGGEST-01). */
        if (!snapshot.shizukuEnabled) return
        when (snapshot.shizukuStatus) {
            ShizukuStatus.NOT_RUNNING -> send(GhostlockEffect.OpenShizuku)
            ShizukuStatus.PERMISSION_REQUIRED -> repository.requestShizukuPermission()
            ShizukuStatus.NOT_REQUIRED,
            ShizukuStatus.READY,
                -> Unit
        }
    }

    private fun runExploit() {
        val snapshot = kernelSnapshot ?: return
        if (!snapshot.kernelSupported) {
            if (beginOperation()) {
                appendLog("result: exploit chain unsupported by this kernel")
                endOperation()
            }
            return
        }
        val useShizuku = snapshot.shizukuEnabled
        if (useShizuku && snapshot.shizukuStatus != ShizukuStatus.READY) {
            onStatusClick()
            return
        }
        val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair) ?: return
        if (!beginOperation()) return
        send(GhostlockEffect.KeepScreenAwake(true))
        appendLog("==== start ${if (useShizuku) "Shizuku/V20" else "base"} ====")
        appendLog("cpu pair: ${snapshot.cpuPairLabels.getOrElse(snapshot.selectedCpuPair) { pair.toString() }}")
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val code = runExploitUseCase(pair, useShizuku, ::appendLog)
                appendLog(if (code == 0) "result: exploit completed" else "result: exploit failed (exit code=$code)")
                appendLog("exit code=$code")
            } finally {
                endOperation()
                send(GhostlockEffect.KeepScreenAwake(false))
            }
        }
    }

    fun onCloseExecutionSheet() {
        if (running && !state.value.executionSheetDismissible) return
        mutableState.update { it.copy(executionSheetVisible = false) }
    }

    fun copyLogs() {
        val text = state.value.logLines.joinToString(separator = "") { it.text }
        send(GhostlockEffect.Clipboard(text))
        send(GhostlockEffect.Toast(R.string.copied))
    }

    fun parseOffsets() {
        resetParseSession()
        parseDialogStage = ParseDialogStage.Mode
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.LIST,
                dialogTitleRes = R.string.parse_title,
                dialogItems = emptyList(),
                dialogItemResIds = listOf(
                    R.string.parse_option_payload,
                    R.string.parse_option_boot,
                ),
            )
        }
    }

    /**
     * The home entry: one sheet with the two profile sources. The OTA path
     * keeps its URL input; the on-device path accepts boot.img, a raw Image,
     * payload.bin or an OTA zip in one picker (the extractor detects the
     * format from the bytes).
     */
    fun promptParseSource() {
        resetParseSession()
        parseDialogStage = ParseDialogStage.Source
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.LIST,
                dialogTitleRes = R.string.parse_source_title,
                dialogItems = emptyList(),
                dialogItemResIds = listOf(
                    R.string.action_parse_ota,
                    R.string.action_parse,
                ),
                dialogCurrentItemIndex = -1,
                executionSheetVisible = false,
            )
        }
    }

    private fun resetParseSession() {
        pendingParse = null
        pendingLockParse = null
        physVendorBootOffered = false
        physXblOffered = false
        physUefiOffered = false
        physDtboOffered = false
        pendingPhysImage = null
        pendingPhysAfter = null
    }

    fun promptParseUrl() {
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.INPUT,
                dialogTitleRes = R.string.parse_url_title,
                dialogMessageRes = R.string.parse_url_hint,
                dialogInput = "",
                dialogConfirmLabelRes = R.string.parse_start,
            )
        }
    }

    fun onDocumentResult(request: DocumentRequest, uri: String) {
        when (request) {
            DocumentRequest.SelectProfile -> selectExternalProfile(uri)
            DocumentRequest.BootImage -> stageBoot(uri)
            DocumentRequest.XblImage -> stageXbl(uri)
            DocumentRequest.UefiImage -> stageUefi(uri)
            DocumentRequest.VendorBootImage -> stageVendorBoot(uri)
            DocumentRequest.DtboImage -> stageDtbo(uri)
            DocumentRequest.PayloadImage -> stagePayload(uri)
        }
    }

    fun onDialogItemSelected(index: Int) {
        dismissDialog()
        when (parseDialogStage) {
            ParseDialogStage.Mode -> when (index) {
                0 -> pickPayload()
                1 -> pickBoot()
            }

            ParseDialogStage.Source -> {
                parseDialogStage = ParseDialogStage.Mode
                when (index) {
                    0 -> promptParseUrl()
                    1 -> parseOffsets()
                }
            }

            ParseDialogStage.PhysImage -> {
                val image = pendingPhysImage
                if (image == null || index > 1) {
                    // no-op; keep the dialog state intact
                } else if (index == 0) {
                    when (image) {
                        PhysImage.VENDOR_BOOT -> send(GhostlockEffect.PickDocument(DocumentRequest.VendorBootImage))
                        PhysImage.XBL -> send(GhostlockEffect.PickDocument(DocumentRequest.XblImage))
                        PhysImage.UEFI -> send(GhostlockEffect.PickDocument(DocumentRequest.UefiImage))
                        PhysImage.DTBO -> send(GhostlockEffect.PickDocument(DocumentRequest.DtboImage))
                    }
                } else {
                    val after = pendingPhysAfter
                    pendingPhysImage = null
                    if (after != null) {
                        viewModelScope.launch(Dispatchers.IO) { advancePhys(after) }
                    } else {
                        launchParse()
                    }
                }
            }

            ParseDialogStage.Route -> {
                val parse = pendingRouteParse
                val route = pendingRouteChoices.getOrNull(index)?.route
                pendingRouteParse = null
                pendingRouteChoices = emptyList()
                parseDialogStage = ParseDialogStage.Mode
                if (parse != null && route != null) {
                    appendLog("route chosen: $route")
                    pendingParse = parse.copy(route = route)
                    launchParse()
                }
            }

            ParseDialogStage.Lock -> {
                val parse = pendingLockParse
                pendingLockParse = null
                parseDialogStage = ParseDialogStage.Mode
                val document = parse?.documentText
                if (parse != null && document != null) {
                    if (index == 1) {
                        appendLog("lock source: anchor")
                        viewModelScope.launch { continueParsed(parse, document) }
                    } else {
                        val page = repository.applyLockSourceToDocument(
                            document,
                            keepAnchor = false,
                        )
                        if (page == null) {
                            appendLog("result: could not remove the lock anchor; export cancelled")
                        } else {
                            appendLog("lock source: page (lock anchor removed)")
                            viewModelScope.launch { continueParsed(parse, page) }
                        }
                    }
                }
            }
        }
    }

    /**
     * Applies the chosen stride in memory and asks the user where to export the
     * generated document. Nothing is stored by the app; the export is the save.
     */
    private fun finishGeneratedProfile(
        document: String,
        name: String?,
        release: String,
        stride: Int?,
    ) {
        val text = if (stride != null) {
            repository.applyStrideToDocument(document, release, stride) ?: run {
                appendLog("stride: could not update the generated document")
                document
            }
        } else {
            document
        }
        if (stride != null) appendLog("stride: kernelsnitch.mm_struct_sz = $stride")
        val suggested = name?.takeIf { it.endsWith(".conf") }
            ?: exportDocumentName(release)
        requestProfileWrite(
            PendingProfileWrite(
                text = text,
                suggestedName = suggested,
                selectAfterWrite = true,
            ),
        )
    }

    fun onDialogInputChange(value: String) = mutableState.update { it.copy(dialogInput = value) }

    fun onDialogConfirm(value: String) {
        val dialogType = state.value.dialogType
        val selectUri = pendingSelectUri
        pendingSelectUri = null
        dismissDialog(clearConfirmation = false)
        when {
            selectUri != null -> selectExternalProfile(selectUri)
            dialogType == DialogType.INPUT -> parseUrl(value)
            dialogType == DialogType.CONFIRM -> toggleShizuku(true)
            else -> Unit
        }
    }

    fun onDialogDismiss() {
        if (parseDialogStage == ParseDialogStage.Route) {
            pendingRouteParse = null
            pendingRouteChoices = emptyList()
            parseDialogStage = ParseDialogStage.Mode
            appendLog("result: route choice cancelled")
        }
        if (parseDialogStage == ParseDialogStage.Lock) {
            pendingLockParse = null
            parseDialogStage = ParseDialogStage.Mode
            appendLog("result: lock source choice cancelled")
        }
        if (parseDialogStage == ParseDialogStage.Source) {
            parseDialogStage = ParseDialogStage.Mode
            appendLog("result: profile source choice cancelled")
        }
        pendingSelectUri = null
        dismissDialog()
    }

    /* ---- the slab-stride decision sheet ---- */

    fun onStrideOptionSelected(value: Int) {
        mutableState.update { state ->
            val picker = state.stridePicker ?: return@update state
            state.copy(stridePicker = picker.copy(selectedValue = value))
        }
    }

    fun onStrideUse() {
        val value = state.value.stridePicker?.selectedValue ?: return
        finishStride(value)
    }

    fun onStrideSkip() = finishStride(null)

    /** Dismissing the sheet means the same as Skip, with the same log line. */
    fun onStridePickerDismiss() = finishStride(null)

    /**
     * Applies the chosen stride to the in-memory generated document and asks
     * where to export it — in the measured-db model the export is the save.
     */
    private fun finishStride(value: Int?) {
        val parse = pendingStrideParse
        val document = pendingStrideDocument
        val name = pendingStrideName
        val release = pendingStrideRelease
        pendingStrideParse = null
        pendingStrideProbe = null
        pendingStrideDocument = null
        pendingStrideName = null
        pendingStrideRelease = null
        mutableState.update { it.copy(stridePicker = null) }
        if (document == null || release == null) return
        if (value == null) {
            appendLog("stride left unset (native default + stride-agnostic scan)")
        } else {
            appendLog("stride chosen: $value")
        }
        finishGeneratedProfile(document, name, release, value)
        parse?.takeIf { it.missing.isNotEmpty() }?.let(::showMissingSidecarNotice)
    }

    /** The root-measured stride for this kernel, when the measured DB has one. */
    private suspend fun rootMeasuredStride(release: String): Int? = runCatching {
        repository.measurements()
            .firstOrNull { it.release == release }
            ?.facts
            ?.firstOrNull { it.key == MeasuredProfileStore.KeyMmStructSz }
            ?.value
            ?.toInt()
    }.getOrNull()

    /** "Export log & report" from the failed-run notice: dismiss, then the picker. */
    fun onDialogExportLog() {
        dismissDialog()
        onExportRunLog()
    }

    fun onDialogDismissFinished() {
        if (!state.value.dialogVisible) {
            clearDialog()
        }
    }

    override fun onCleared() {
        repository.close()
        effectChannel.close()
        super.onCleared()
    }

    private suspend fun refreshSnapshot() {
        val snapshot = withContext(Dispatchers.IO) { loadKernelSnapshot() }
        /* Validate the resolved profile here so the run button can grey out. */
        val loaded = withContext(Dispatchers.IO) {
            val pair = snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair)
                ?: return@withContext null
            runCatching { profileController.load(snapshot.kernelRelease, pair) }.getOrNull()
        }
        kernelSnapshot = snapshot
        mutableState.update {
            it.copy(
                deviceName = snapshot.deviceName,
                kernelRelease = snapshot.kernelRelease,
                socName = snapshot.socName,
                kernelSupported = snapshot.kernelSupported,
                cpuPairLabels = snapshot.cpuPairLabels,
                cpuPairIndex = snapshot.selectedCpuPair,
                safeModeEnabled = snapshot.safeModeEnabled,
                forceAttackTestEnabled = snapshot.forceAttackTest,
                vrKoTagClear = snapshot.vrKoTagClear,
                vrKoSelinuxBlock = snapshot.vrKoSelinuxBlock,
                shizukuEnabled = snapshot.shizukuEnabled,
                shizukuStatus = snapshot.shizukuStatus,
                profileInvalidPaths = loaded?.invalidPaths ?: emptySet(),
                executionHasProfile = loaded?.hasProfile ?: false,
                profileLayers = loaded?.layers,
                externalProfile = profileController.activeExternalProfile(),
                activeUserProfile = loaded?.layers?.takeIf { it.externalApplied }?.external,
                customCpuPair = loaded?.let(::customCpuPairOf),
            )
        }
        /* At start-up, and from the resolution the run button was just judged
         * on — the same one a run uses (§C.12b). */
        loaded?.let(::maybeRaiseLayerNotice)
        refreshMergeRows()
    }

    private fun pickPayload() {
        send(GhostlockEffect.Toast(R.string.parse_pick_payload_hint))
        send(GhostlockEffect.PickDocument(DocumentRequest.PayloadImage))
    }

    private fun pickBoot() {
        send(GhostlockEffect.PickDocument(DocumentRequest.BootImage))
    }

    /** The input image is staged; ask for the platform's recommended image
     * before the first pass. */
    private fun beginParseInput(input: String) {
        pendingParse = ParseRequest(input)
        val first = when {
            isMediaTek() -> PhysImage.VENDOR_BOOT
            isQualcomm() -> PhysImage.XBL
            else -> null
        }
        if (first == null) launchParse() else showPhysPrompt(first, after = null)
    }

    private fun launchParse() {
        val request = pendingParse ?: return
        pendingPhysImage = null
        pendingPhysAfter = null
        viewModelScope.launch(Dispatchers.IO) { runParse(request) }
    }

    private fun stageBoot(uri: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val bootPath = readDocumentUseCase.cache(uri, "boot.img")
                appendLog("boot.img ready: $bootPath")
                beginParseInput(bootPath)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                appendLog("parse error: ${error.message}")
                appendLog("result: parse failed")
                showNotice(R.string.parse_result_title, R.string.parse_failed)
            }
        }
    }

    /** Caches one recommended image and re-runs the pass with it attached. */
    private fun stageSidecar(
        uri: String,
        name: String,
        update: (ParseRequest, String) -> ParseRequest,
    ) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val path = readDocumentUseCase.cache(uri, name)
                appendLog("$name ready: $path")
                pendingParse = pendingParse?.let { update(it, path) }
                launchParse()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                appendLog("parse error: ${error.message}")
                appendLog("result: parse failed")
                showNotice(R.string.parse_result_title, R.string.parse_failed)
            }
        }
    }

    private fun stageXbl(uri: String) =
        stageSidecar(uri, "xbl_config.img") { request, path -> request.copy(xblPath = path) }

    private fun stageUefi(uri: String) =
        stageSidecar(uri, "uefi.img") { request, path -> request.copy(uefiPath = path) }

    private fun stageVendorBoot(uri: String) =
        stageSidecar(uri, "vendor_boot.img") { request, path -> request.copy(vendorBootPath = path) }

    private fun stageDtbo(uri: String) =
        stageSidecar(uri, "dtbo.img") { request, path -> request.copy(dtboPath = path) }

    private fun stagePayload(uri: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val payloadPath = readDocumentUseCase.cache(uri, "payload.bin")
                appendLog("payload.bin ready: $payloadPath")
                beginParseInput(payloadPath)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                appendLog("parse error: ${error.message}")
                appendLog("result: parse failed")
                showNotice(R.string.parse_result_title, R.string.parse_failed)
            }
        }
    }

    private fun parseUrl(value: String) {
        val url = value.trim()
        if (url.isEmpty() || !(url.startsWith("http://") || url.startsWith("https://"))) {
            appendLog("error: invalid OTA URL: $url")
            appendLog("result: parse failed")
            showNotice(R.string.parse_result_title, R.string.parse_failed_url)
            return
        }
        appendLog("parse OTA: $url")
        pendingParse = ParseRequest(url)
        /* A remote payload's xbl_config is auto-extracted; a MediaTek payload's
         * vendor_boot is not, so the follow-up asks for it. */
        physXblOffered = isQualcomm()
        launchParse()
    }

    /** Confirm/notice popup for an extractor outcome; unlike a Toast it waits
     * for the user and can link the matching documentation page. */
    private fun showNotice(titleRes: Int, messageRes: Int, docUrl: String? = null) {
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.NOTICE,
                dialogTitleRes = titleRes,
                dialogMessageRes = messageRes,
                dialogDocUrl = docUrl,
                dialogConfirmLabelRes = R.string.dialog_dismiss,
            )
        }
    }

    /** The sidecar warning deferred while the stride picker was up. */
    private fun showMissingSidecarNotice(result: ParseResult.Parsed) {
        val mediaTek = isMediaTek()
        showNotice(
            titleRes = R.string.parse_result_title,
            messageRes = if (mediaTek) {
                R.string.parse_missing_phys_mediatek
            } else {
                R.string.parse_missing_phys_hint
            },
            docUrl = if (mediaTek) mediatekDocUrl() else null,
        )
    }

    private fun isMediaTek(): Boolean {
        val soc = kernelSnapshot?.socName?.lowercase(Locale.ROOT).orEmpty()
        return soc.contains("mediatek") || soc.contains("mtk") ||
                soc.contains("dimensity") || soc.contains("helio")
    }

    private fun isQualcomm(): Boolean {
        val soc = kernelSnapshot?.socName?.lowercase(Locale.ROOT).orEmpty()
        return soc.contains("qualcomm") || soc.contains("qti") || soc.contains("snapdragon")
    }

    private fun mediatekDocUrl(): String =
        "https://github.com/YuKongA/ghostlock-app/blob/main/docs/kernel_profiles/" +
                if (Locale.getDefault().language == "zh") "MEDIATEK_ZH.md" else "MEDIATEK.md"

    private suspend fun runParse(request: ParseRequest) {
        if (!beginOperation()) return
        try {
            when (
                val result = parseSourceUseCase(
                    request.input, request.xblPath, request.uefiPath,
                    request.vendorBootPath, request.dtboPath,
                    request.overwrite, request.route, ::appendLog,
                )
            ) {
                is ParseResult.RequiresOverwrite -> {
                    pendingConfirmation = PendingConfirmation.Parse(request)
                    showOverwriteDialog(result.releases)
                }

                is ParseResult.Ambiguous -> {
                    val feasible = result.routes.filter { it.verdict == "feasible" }
                    appendLog(
                        "result: ${feasible.size} feasible routes: " +
                            feasible.joinToString(", ") { it.route },
                    )
                    if (feasible.isEmpty()) {
                        appendLog("result: route ambiguity without a usable route")
                        showNotice(R.string.parse_result_title, R.string.parse_failed)
                    } else {
                        /* The choice is the user's: both routes are derived from
                         * the image, and which one runs is a device fact. The
                         * second pass forces the pick with --route. */
                        pendingRouteParse = request
                        pendingRouteChoices = feasible
                        parseDialogStage = ParseDialogStage.Route
                        mutableState.update {
                            it.copy(
                                dialogVisible = true,
                                dialogType = DialogType.LIST,
                                dialogTitleRes = R.string.parse_route_title,
                                dialogItems = feasible.map { choice ->
                                    "${choice.route} — ${choice.reason}"
                                },
                                dialogItemResIds = emptyList(),
                                dialogCurrentItemIndex = -1,
                                /* The picker must be the only overlay on
                                 * screen; a log sheet behind it would swallow
                                 * its taps (same rule as the overwrite dialog). */
                                executionSheetVisible = false,
                            )
                        }
                    }
                }

                is ParseResult.Parsed -> advancePhys(result)

                ParseResult.AlreadyPresent -> {
                    appendLog("result: offsets already present")
                    showNotice(R.string.parse_result_title, R.string.offsets_already_exist)
                }

                is ParseResult.Failed -> {
                    result.reason?.let { appendLog("parse failed: $it") }
                    appendLog("result: ${parseFailureResult(result.code)}")
                    showNotice(R.string.parse_result_title, parseFailureToast(result.code))
                }
            }
        } finally {
            endOperation()
        }
    }

    /**
     * The platform's image advice: ask for the next recommended image while
     * one can still fill the physical pair, otherwise finish the pass.
     */
    private suspend fun advancePhys(result: ParseResult.Parsed) {
        val next = nextPhysImage(physState(result))
        if (next != null) {
            showPhysPrompt(next, after = result)
            return
        }
        if (isMediaTek() && !result.physOffsetPresent) {
            appendLog(
                "warning: kernel_phys_offset is still missing; attach a vendor_boot/dtbo " +
                    "with /memory or fill it manually",
            )
        }
        if (isQualcomm() && !sourceSuppliesLoad(result.physSource)) {
            appendLog(
                "warning: kernel_phys_load was not supplied by xbl_config/uefi; " +
                    "attach uefi.img or fill it manually",
            )
        }
        finishParsed(result)
    }

    private fun physState(result: ParseResult.Parsed) = PhysPromptState(
        mediaTek = isMediaTek(),
        qualcomm = isQualcomm(),
        physSource = result.physSource,
        offsetPresent = result.physOffsetPresent,
        vendorBootOffered = physVendorBootOffered,
        xblOffered = physXblOffered,
        uefiOffered = physUefiOffered,
        dtboOffered = physDtboOffered,
    )

    /** One per-platform prompt: attach the recommended image or skip it. */
    private fun showPhysPrompt(image: PhysImage, after: ParseResult.Parsed?) {
        pendingPhysImage = image
        pendingPhysAfter = after
        when (image) {
            PhysImage.VENDOR_BOOT -> physVendorBootOffered = true
            PhysImage.XBL -> physXblOffered = true
            PhysImage.UEFI -> physUefiOffered = true
            PhysImage.DTBO -> physDtboOffered = true
        }
        val title = when (image) {
            PhysImage.VENDOR_BOOT -> R.string.parse_phys_vendor_boot_title
            PhysImage.XBL -> R.string.parse_phys_xbl_title
            PhysImage.UEFI -> R.string.parse_phys_uefi_title
            PhysImage.DTBO -> R.string.parse_phys_dtbo_title
        }
        val attach = when (image) {
            PhysImage.VENDOR_BOOT -> R.string.parse_phys_attach_vendor_boot
            PhysImage.XBL -> R.string.parse_phys_attach_xbl
            PhysImage.UEFI -> R.string.parse_phys_attach_uefi
            PhysImage.DTBO -> R.string.parse_phys_attach_dtbo
        }
        parseDialogStage = ParseDialogStage.PhysImage
        mutableState.update {
            it.copy(
                dialogVisible = true,
                dialogType = DialogType.LIST,
                dialogTitleRes = title,
                dialogItems = emptyList(),
                dialogItemResIds = listOf(attach, R.string.parse_phys_skip),
                dialogCurrentItemIndex = -1,
                executionSheetVisible = false,
            )
        }
    }

    /** The Parsed branch once the image advice is satisfied. */
    private suspend fun finishParsed(result: ParseResult.Parsed) {
        val document = result.documentText
        if (document == null) {
            appendLog("result: the extractor produced no document")
            showNotice(R.string.parse_result_title, R.string.parse_failed)
            return
        }
        refreshSnapshot()
        refreshLegacyState()
        result.route?.let { appendLog("route: $it") }
        result.anchor?.let {
            appendLog(
                "anchor: " + it.removePrefix("info: ").removePrefix("warning: "),
            )
        }
        appendLog("profile generated: ${result.releases.joinToString()}")
        appendLog("result: profile generated; export it to use it")
        /* The lock source is the user's choice: page (safe, lower rate) or the
         * generated anchor (higher rate if the zero-page region is correct).
         * The extractor only emits a triple for routes that use one. */
        if (result.hasAnchor) {
            pendingLockParse = result
            parseDialogStage = ParseDialogStage.Lock
            mutableState.update {
                it.copy(
                    dialogVisible = true,
                    dialogType = DialogType.LIST,
                    dialogTitleRes = R.string.parse_lock_title,
                    dialogItems = emptyList(),
                    dialogItemResIds = listOf(
                        R.string.parse_lock_page,
                        R.string.parse_lock_anchor,
                    ),
                    dialogCurrentItemIndex = -1,
                    executionSheetVisible = false,
                )
            }
            return
        }
        continueParsed(result, document)
    }

    /**
     * The stride probe and the export are shared by the no-anchor path and the
     * post-choice path: [document] is what will be exported (page mode has had
     * the `lock_anchor_*` triple removed in memory).
     */
    private suspend fun continueParsed(result: ParseResult.Parsed, document: String) {
        /* The live stride probe only makes sense for the running kernel; a
         * profile generated for another image skips it. */
        val runningRelease = kernelSnapshot?.kernelRelease
        val pair = kernelSnapshot?.let { snapshot ->
            snapshot.cpuPairs.getOrNull(snapshot.selectedCpuPair)
        }
        val strideProbe = if (runningRelease != null && pair != null &&
            runningRelease in result.releases
        ) {
            appendLog("stride: probing the mm_struct slab on the running kernel")
            runCatching {
                repository.probeStride(runningRelease, document, pair, ::appendLog)
            }.getOrNull()
        } else {
            null
        }
        if (strideProbe != null && runningRelease != null) {
            pendingStrideParse = result
            pendingStrideProbe = strideProbe
            pendingStrideDocument = document
            pendingStrideName = result.documentName
            pendingStrideRelease = runningRelease
            val recommendation = recommendStride(
                strideProbe,
                confirmedValue = rootMeasuredStride(runningRelease),
            )
            appendLog(
                "stride: ${strideProbe.candidates.size} candidate(s), " +
                    "gcd=0x${strideProbe.gcd.toString(16)}, " +
                    "rounds=${strideProbe.rounds}, samples=${strideProbe.samples}",
            )
            mutableState.update {
                it.copy(
                    stridePicker = StridePickerUiState(
                        recommendation = recommendation,
                        selectedValue = recommendation.recommendedValue,
                        footerRes = R.string.stride_footer_export,
                    ),
                    executionSheetVisible = false,
                )
            }
        } else {
            finishGeneratedProfile(
                document,
                result.documentName,
                runningRelease ?: result.releases.firstOrNull() ?: "profile",
                null,
            )
        }
        if (result.missing.isNotEmpty()) {
            appendLog(
                "warning: missing ${result.missing.joinToString()}; " +
                    "attach the platform image or fill the fields manually",
            )
        }
    }

    fun onOverwriteConfirm() {
        mutableState.update { it.copy(overwriteDialogVisible = false, overwriteMessage = "") }
        confirmPendingOperation()
    }

    fun onOverwriteDismiss() {
        pendingConfirmation = null
        running = false
        appendLog("result: overwrite cancelled")
        mutableState.update {
            it.copy(
                overwriteDialogVisible = false,
                overwriteMessage = "",
                running = false,
                executionSheetDismissible = true,
            )
        }
    }

    private fun confirmPendingOperation() {
        val confirmation = pendingConfirmation ?: return
        pendingConfirmation = null
        when (confirmation) {
            is PendingConfirmation.Parse -> {
                pendingParse = confirmation.request.copy(overwrite = true)
                launchParse()
            }
        }
    }

    private fun showOverwriteDialog(releases: List<String>) {
        mutableState.update {
            it.copy(
                overwriteDialogVisible = true,
                overwriteMessage = overwriteSummary(releases),
                /* The confirmation must be the only overlay on screen; a log
                 * sheet behind it would swallow its taps. */
                executionSheetVisible = false,
            )
        }
    }

    /** Keeps the confirmation readable when a document carries many releases. */
    private fun overwriteSummary(releases: List<String>): String {
        val head = releases.take(OverwriteSummaryLimit).joinToString("\n")
        val rest = releases.size - OverwriteSummaryLimit
        return if (rest > 0) "$head\n… (+$rest)" else head
    }

    private fun dismissDialog(clearConfirmation: Boolean = true) {
        if (clearConfirmation) pendingConfirmation = null
        /* Shown is as good as read: acknowledging on the way out keeps the
         * notice to once per build however it was dismissed. */
        state.value.dialogLayerNotice?.let { repository.acknowledgeLayerNotice(it.build) }
        mutableState.update {
            it.copy(
                dialogVisible = false,
            )
        }
    }

    private fun clearDialog() {
        mutableState.update {
            it.copy(
                dialogVisible = false,
                dialogType = DialogType.NONE,
                dialogTitleRes = 0,
                dialogMessage = "",
                dialogMessageRes = 0,
                dialogItems = emptyList(),
                dialogItemResIds = emptyList(),
                dialogCurrentItemIndex = -1,
                dialogExportLog = false,
                dialogInput = "",
                dialogConfirmLabelRes = R.string.parse_start,
                dialogDocUrl = null,
                dialogLayerNotice = null,
            )
        }
    }

    private fun appendLog(line: String) {
        /* The final result lines are Kotlin-side; tag them so they read as <k>. */
        val tagged = if (line.startsWith("result:")) "<k> $line" else line
        val entry = formatLog(tagged)
        val uiLine = GhostlockLogLine(entry.text, toneColor(entry.tone))
        mutableState.update { it.copy(logLines = it.logLines + uiLine) }
    }

    private fun beginOperation(showLogSheet: Boolean = true): Boolean {
        if (running) return false
        running = true
        mutableState.update {
            if (showLogSheet) {
                it.copy(
                    running = true,
                    executionSheetVisible = true,
                    executionSheetDismissible = false,
                )
            } else {
                it.copy(running = true)
            }
        }
        return true
    }

    private fun endOperation() {
        running = false
        mutableState.update { it.copy(running = false, executionSheetDismissible = true) }
    }

    private fun send(effect: GhostlockEffect) {
        effectChannel.trySend(effect)
    }

    private fun toneColor(tone: LogTone): Int = when (tone) {
        LogTone.Error -> 0xFFFF6B6B.toInt()
        LogTone.Success -> 0xFF5FD68A.toInt()
        LogTone.Warning -> 0xFFFFC94D.toInt()
        LogTone.Progress -> 0xFF60A5FA.toInt()
        LogTone.Kotlin -> 0xFF5EEAD4.toInt()
        LogTone.Shizuku -> 0xFFC084FC.toInt()
        LogTone.Default -> -1
    }

    private fun parseFailureToast(code: Int): Int = when (code) {
        3, 4 -> R.string.parse_failed_route
        5 -> R.string.parse_failed_kallsyms
        6 -> R.string.parse_failed_fixed
        -1 -> R.string.parse_timeout
        else -> R.string.parse_failed
    }

    private fun parseFailureResult(code: Int): String = when (code) {
        3, 4 -> "exploit chain unsupported by this kernel"
        5 -> "kernel symbol table could not be recovered"
        6 -> "kernel has fixed the vulnerability"
        -1 -> "parse timed out"
        else -> "parse failed"
    }

    private sealed interface PendingConfirmation {
        data class Parse(val request: ParseRequest) : PendingConfirmation
    }
}
