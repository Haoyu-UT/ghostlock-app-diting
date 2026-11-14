package com.ghostlock.app.ui

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.RemoveCircleOutline
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostlock.app.R
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ExecutionFieldValue
import com.ghostlock.app.domain.model.ExternalProfileInfo
import com.ghostlock.app.domain.model.MeasuredKernelInfo
import com.ghostlock.app.domain.model.MeasurementMergeRow
import com.ghostlock.app.domain.model.ProfileDiffRow
import com.ghostlock.app.domain.model.ProfileFieldNode
import com.ghostlock.app.domain.model.ProfileLayers
import com.ghostlock.app.domain.model.RunLogEntry
import com.ghostlock.app.domain.model.RunLogState
import com.ghostlock.app.domain.model.ShizukuStatus
import com.ghostlock.app.domain.model.UserProfileFile
import com.ghostlock.app.domain.model.VrKoMode
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.DropdownItem
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TextFieldDefaults
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberTopAppBarState
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Close
import top.yukonga.miuix.kmp.icon.extended.Copy
import top.yukonga.miuix.kmp.nav.core.NavBackStack
import top.yukonga.miuix.kmp.nav.core.NavDisplay
import top.yukonga.miuix.kmp.nav.core.NavDisplayEffects
import top.yukonga.miuix.kmp.nav.core.NavKey
import top.yukonga.miuix.kmp.nav.core.navBackStackOf
import top.yukonga.miuix.kmp.nav.core.rememberNavSystemCornerRadius
import top.yukonga.miuix.kmp.nav.transition.NavSwipeDirection
import top.yukonga.miuix.kmp.overlay.OverlayBottomSheet
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.OverlaySpinnerPreference
import top.yukonga.miuix.kmp.preference.RadioButtonLocation
import top.yukonga.miuix.kmp.preference.RadioButtonPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme
import top.yukonga.miuix.kmp.utils.PressFeedbackType
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

data class GhostlockUiState(
    val deviceName: String = "",
    val kernelRelease: String = "",
    val socName: String = "",
    val kernelSupported: Boolean = false,
    /**
     * The stored external selection cannot be read, so there is no profile and
     * no run: the home names the real cause and sends the user to re-select it
     * instead of claiming the kernel is unsupported.
     */
    val externalProfileUnreadable: Boolean = false,
    val shizukuEnabled: Boolean = false,
    val shizukuStatus: ShizukuStatus = ShizukuStatus.NOT_REQUIRED,
    /** Root-manager choice (package name); null means Auto. */
    val selectedManagerPackage: String? = null,
    val running: Boolean = false,
    /** The last run's terminal status, shown in the sheet footer. */
    val runStatus: RunStatus = RunStatus.Idle,
    val cpuPairLabels: List<String> = emptyList(),
    val cpuPairIndex: Int = 0,
    /** CPU pair from the resolved profile when it differs from the device pick. */
    val customCpuPair: CpuPair? = null,
    val safeModeEnabled: Boolean = false,
    val forceAttackTestEnabled: Boolean = false,
    val secondWayEnabled: Boolean = false,
    val vrKoTagClear: VrKoMode = VrKoMode.AUTO,
    val vrKoSelinuxBlock: VrKoMode = VrKoMode.AUTO,
    val tcpRouteEnabled: Boolean = true,
    val compact: Boolean = false,
    val executionSheetVisible: Boolean = false,
    val executionSheetDismissible: Boolean = false,
    val dialogVisible: Boolean = false,
    val dialogType: DialogType = DialogType.NONE,
    val dialogTitleRes: Int = 0,
    val dialogMessage: String = "",
    val dialogMessageRes: Int = 0,
    val dialogItems: List<String> = emptyList(),
    val dialogItemResIds: List<Int> = emptyList(),
    /** Optional success-grade chip per [dialogItems] entry (route picker). */
    val dialogItemGrades: List<DialogChip?> = emptyList(),
    /** A leading LIST row given as a string resource (the page option row). */
    val dialogLeadingResId: Int? = null,
    val dialogCurrentItemIndex: Int = -1,
    val dialogInput: String = "",
    val dialogConfirmLabelRes: Int = R.string.parse_start,
    /** Documentation URL shown as an extra button on a NOTICE dialog. */
    val dialogDocUrl: String? = null,
    /**
     * Offer "export log & report" on this dialog: a run that ended badly is
     * exactly the moment someone wants to send the log, and the notice telling
     * them it ended badly is where they are looking.
     */
    val dialogExportLog: Boolean = false,
    /**
     * Layers of the resolution that raised the start-up notice; non-null means
     * the dialog body is built from this instead of [dialogMessageRes], so it
     * states the layers that are already inactive (§C.12b).
     */
    val dialogLayerNotice: ProfileLayers? = null,
    val overwriteDialogVisible: Boolean = false,
    val overwriteMessage: String = "",
    val logLines: List<GhostlockLogLine> = emptyList(),
    /** Runs retained on the device, as the export picker lists them. */
    val runLogs: List<RunLogEntry> = emptyList(),
    val runLogPickerVisible: Boolean = false,
    val executionRelease: String = "",
    val executionHasProfile: Boolean = false,
    val executionFields: List<ExecutionFieldValue> = emptyList(),
    val executionEditing: Map<String, String> = emptyMap(),
    val advancedScreenVisible: Boolean = false,
    /** The vr.ko anti-root countermeasure options screen. */
    val vrKoVisible: Boolean = false,
    /** Read-only measurements screen state. */
    val measurementsVisible: Boolean = false,
    val measuredKernels: List<MeasuredKernelInfo> = emptyList(),
    val debugKernelLogEnabled: Boolean = true,
    val aboutVisible: Boolean = false,
    val parametersVisible: Boolean = false,
    val profileOverrideVisible: Boolean = false,
    val advancedOverrideVisible: Boolean = false,
    /** Stored document edited by the open session; null for the builtin. */
    val editTargetName: String? = null,
    val profileOverrideRelease: String = "",
    val profileOverrideRoots: List<ProfileFieldNode> = emptyList(),
    val profileOverrideEditing: Map<String, String> = emptyMap(),
    /** Controller-reported geometry violations, dotted paths. */
    val profileInvalidPaths: Set<String> = emptySet(),
    /** Explicit route from the profile; null means geometry inference. */
    val profileRoute: String? = null,
    /** Declared fallback route; null/"none" means disabled. */
    val profileFallback: String? = null,
    /** Manually selected builtin source; null means automatic matching. */
    val activeBuiltinProfile: String? = null,
    val builtinScreenVisible: Boolean = false,
    /** Unfilled reference templates, listed separately on the builtin picker. */
    val builtinTemplates: List<String> = emptyList(),
    /** Builtin releases sorted by similarity to the device kernel. */
    val builtinProfiles: List<String> = emptyList(),
    val loadConfigVisible: Boolean = false,
    /** External document selected for this kernel (applied or not). */
    val externalProfile: ExternalProfileInfo? = null,
    /** External document actually applied to the last resolution. */
    val activeUserProfile: String? = null,
    /** Which layers the last resolution applied, and which it deliberately did not. */
    val profileLayers: ProfileLayers? = null,
    /** The slab-stride choice sheet; non-null while a probe result awaits. */
    val stridePicker: StridePickerUiState? = null,
    /** Measured facts that would change the active profile. */
    val mergeRows: List<MeasurementMergeRow> = emptyList(),
    val mergePreviewVisible: Boolean = false,
    /** Diff of the editor session against the bundle. */
    val profileDiffVisible: Boolean = false,
    val profileDiffRows: List<ProfileDiffRow> = emptyList(),
    /** One-time legacy app-data cleanup. */
    val legacyVisible: Boolean = false,
    val legacyPresent: Boolean = false,
    val legacyProfiles: List<UserProfileFile> = emptyList(),
    val legacyOverridePresent: Boolean = false,
    val legacyCleanupConfirm: Boolean = false,
)

enum class DialogType { NONE, LIST, INPUT, CONFIRM, NOTICE, NOTIFICATION_PERMISSION }

/** The last attack run's state; the run-status notification mirrors it. */
enum class RunStatus { Idle, Running, Success, Failure }

/**
 * One line per layer that is present but deliberately not applied. Shared by
 * the start-up notice and the profile screen's banner, so the two can never
 * describe the same state differently.
 */
@Composable
internal fun layerNoticeBody(layers: ProfileLayers): String = buildList {
    val imported = layers.imported
    if (imported != null && !layers.importedApplied) {
        add(stringResource(R.string.layer_import_not_applied, imported))
    }
    layers.external?.takeIf { !layers.externalApplied }?.let { name ->
        add(stringResource(R.string.layer_external_not_applied, name))
    }
    if (layers.overridesPresent && !layers.overridesApplied) {
        add(stringResource(R.string.layer_overrides_not_applied))
    }
}.joinToString("\n\n")


data class GhostlockLogLine(val text: String, val color: Int)

interface GhostlockActions {
    fun onRun()
    fun onProfileInvalid()
    fun onStatusClick()
    fun onCloseExecutionSheet()
    fun onCopyLogs()
    fun onExportRunLog()
    fun onRunLogSelected(stamp: String)
    fun onRunLogPickerDismiss()
    fun onClearRunLogs()
    fun onSelectProfileFile()
    fun onClearExternalProfile()
    fun onParseOta()
    fun onParseImage()
    fun onGenerateProfile()
    fun onCpuPairSelected(index: Int)
    fun onSafeModeChanged(enabled: Boolean)
    fun onForceAttackTestChanged(enabled: Boolean)
    fun onSecondWayChanged(enabled: Boolean)
    fun onVrKoTagClearChanged(mode: VrKoMode)
    fun onVrKoSelinuxBlockChanged(mode: VrKoMode)
    fun onShizukuChanged(enabled: Boolean)
    fun onOpenManagerPicker()
    fun onOpenManager()
    fun onDialogItemSelected(index: Int)
    fun onDialogInputChange(value: String)
    fun onDialogConfirm(value: String)
    fun onDialogDismiss()
    fun onDialogDismissFinished()
    fun onDialogExportLog()
    fun onOverwriteConfirm()
    fun onOverwriteDismiss()
    fun onStrideOptionSelected(value: Int)
    fun onStrideUse()
    fun onStrideSkip()
    fun onStridePickerDismiss()
    fun onExecutionFieldChanged(path: String, value: String)
    fun onRouteChanged(index: Int)
    fun onFallbackChanged(index: Int)
    fun onExportProfile()
    fun onSaveProfileEdits()
    fun onSaveProfileAs()
    fun onExportProfileEdits()
    fun onRevertProfileEdits()
    fun onOpenAdvanced()
    fun onCloseAdvanced()
    fun onOpenVrKo()
    fun onCloseVrKo()
    fun onOpenMeasurements()
    fun onCloseMeasurements()
    fun onShowAbout()
    fun onCloseAbout()
    fun onDebugKernelLogChanged(enabled: Boolean)
    fun onOpenParameters()
    fun onCloseParameters()
    fun onOpenLoadConfig()
    fun onCloseLoadConfig()
    fun onOpenMergePreview()
    fun onCloseMergePreview()
    fun onExportMergedProfile()
    fun onOpenProfileDiff()
    fun onCloseProfileDiff()
    fun onRebaseToBundle()
    fun onOpenLegacyCleanup()
    fun onCloseLegacyCleanup()
    fun onLegacyExport(name: String, applyOverride: Boolean)
    fun onLegacyCleanupRequest()
    fun onLegacyCleanupConfirm()
    fun onLegacyCleanupDismiss()
    fun onOpenBuiltinProfiles()
    fun onCloseBuiltinProfiles()
    fun onSelectBuiltinProfile(release: String?)
    fun onOpenProfileOverrides()
    fun onCloseProfileOverrides()
    fun onOpenAdvancedOverrides()
    fun onCloseAdvancedOverrides()
    fun onProfileOverrideChanged(path: String, value: String)
}

internal sealed interface GhostlockScreen : NavKey {
    data object Main : GhostlockScreen
    data object VrKo : GhostlockScreen
    data object Advanced : GhostlockScreen
    data object About : GhostlockScreen
    data object Measurements : GhostlockScreen
    data object Parameters : GhostlockScreen
    data object LoadConfig : GhostlockScreen
    data object Builtin : GhostlockScreen
    data object MergePreview : GhostlockScreen
    data object ProfileDiff : GhostlockScreen
    data object Legacy : GhostlockScreen
    data object ProfileOverride : GhostlockScreen
    data object AdvancedOverride : GhostlockScreen
}

internal fun navigationPath(state: GhostlockUiState): List<GhostlockScreen> {
    val path = mutableListOf<GhostlockScreen>(GhostlockScreen.Main)
    if (state.legacyVisible) {
        path += GhostlockScreen.Legacy
        return path
    }
    if (state.mergePreviewVisible) {
        path += GhostlockScreen.MergePreview
        return path
    }
    if (state.vrKoVisible) {
        path += GhostlockScreen.VrKo
        return path
    }
    if (!state.advancedScreenVisible) return path
    path += GhostlockScreen.Advanced
    if (state.aboutVisible) {
        path += GhostlockScreen.About
        return path
    }
    if (state.measurementsVisible) {
        path += GhostlockScreen.Measurements
        return path
    }
    if (!state.parametersVisible) return path
    path += GhostlockScreen.Parameters
    if (state.loadConfigVisible) {
        path += GhostlockScreen.LoadConfig
        if (state.builtinScreenVisible) path += GhostlockScreen.Builtin
    }
    if (state.profileOverrideVisible) {
        path += GhostlockScreen.ProfileOverride
        if (state.advancedOverrideVisible) path += GhostlockScreen.AdvancedOverride
        if (state.profileDiffVisible) path += GhostlockScreen.ProfileDiff
    }
    return path
}

internal fun syncNavigationPath(backStack: NavBackStack, desired: List<GhostlockScreen>) {
    var common = 0
    while (common < backStack.size && common < desired.size &&
        backStack[common] == desired[common]
    ) {
        common++
    }
    while (backStack.size > common) backStack.removeAt(backStack.lastIndex)
    backStack.addAll(desired.drop(common))
}

private fun closeScreen(screen: GhostlockScreen, actions: GhostlockActions) {
    when (screen) {
        GhostlockScreen.Main -> Unit
        GhostlockScreen.VrKo -> actions.onCloseVrKo()
        GhostlockScreen.Advanced -> actions.onCloseAdvanced()
        GhostlockScreen.About -> actions.onCloseAbout()
        GhostlockScreen.Measurements -> actions.onCloseMeasurements()
        GhostlockScreen.Parameters -> actions.onCloseParameters()
        GhostlockScreen.LoadConfig -> actions.onCloseLoadConfig()
        GhostlockScreen.Builtin -> actions.onCloseBuiltinProfiles()
        GhostlockScreen.MergePreview -> actions.onCloseMergePreview()
        GhostlockScreen.ProfileDiff -> actions.onCloseProfileDiff()
        GhostlockScreen.Legacy -> actions.onCloseLegacyCleanup()
        GhostlockScreen.ProfileOverride -> actions.onCloseProfileOverrides()
        GhostlockScreen.AdvancedOverride -> actions.onCloseAdvancedOverrides()
    }
}

@Composable
internal fun GhostlockApp(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    MiuixTheme(
        colors = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme(),
    ) {
        val desiredPath = navigationPath(state)
        val backStack = remember {
            navBackStackOf(GhostlockScreen.Main).apply { addAll(desiredPath.drop(1)) }
        }
        LaunchedEffect(desiredPath) { syncNavigationPath(backStack, desiredPath) }
        val swipeBack = if (LocalLayoutDirection.current == LayoutDirection.Rtl) {
            NavSwipeDirection.RightToLeft
        } else {
            NavSwipeDirection.LeftToRight
        }
        Scaffold(modifier = Modifier.fillMaxSize()) { _ ->
            Box(modifier = Modifier.fillMaxSize()) {
                NavDisplay(
                    backStack = backStack,
                    modifier = Modifier.fillMaxSize(),
                    effects = NavDisplayEffects(cornerClipRadius = rememberNavSystemCornerRadius()),
                    onBack = {
                        when {
                            state.executionSheetVisible -> {
                                if (state.executionSheetDismissible) actions.onCloseExecutionSheet()
                            }

                            state.overwriteDialogVisible -> actions.onOverwriteDismiss()
                            state.dialogVisible -> actions.onDialogDismiss()
                            else -> {
                                val screen = backStack.lastOrNull() as? GhostlockScreen
                                if (screen != null && screen != GhostlockScreen.Main) {
                                    closeScreen(screen, actions)
                                    backStack.removeAt(backStack.lastIndex)
                                }
                            }
                        }
                    },
                ) {
                    entry<GhostlockScreen.Main>(swipeDismiss = NavSwipeDirection.None) {
                        MainScreen(state = state, actions = actions)
                    }
                    entry<GhostlockScreen.VrKo>(swipeDismiss = swipeBack) {
                        VrKoScreen(state = state, actions = actions)
                    }
                    entry<GhostlockScreen.Advanced>(swipeDismiss = swipeBack) {
                        AdvancedScreen(state = state, actions = actions)
                    }
                    entry<GhostlockScreen.About>(swipeDismiss = swipeBack) {
                        AboutScreen(onBack = actions::onCloseAbout)
                    }
                    entry<GhostlockScreen.Measurements>(swipeDismiss = swipeBack) {
                        MeasurementsScreen(state = state, actions = actions)
                    }
                    entry<GhostlockScreen.Parameters>(swipeDismiss = swipeBack) {
                        ParameterScreen(state = state, actions = actions)
                    }
                    entry<GhostlockScreen.LoadConfig>(swipeDismiss = swipeBack) {
                        LoadConfigScreen(state = state, actions = actions)
                    }
                    entry<GhostlockScreen.Builtin>(swipeDismiss = swipeBack) {
                        BuiltinProfileScreen(state = state, actions = actions)
                    }
                    entry<GhostlockScreen.MergePreview>(swipeDismiss = swipeBack) {
                        MergePreviewScreen(state = state, actions = actions)
                    }
                    entry<GhostlockScreen.ProfileDiff>(swipeDismiss = swipeBack) {
                        ProfileDiffScreen(state = state, actions = actions)
                    }
                    entry<GhostlockScreen.Legacy>(swipeDismiss = swipeBack) {
                        LegacyCleanupScreen(state = state, actions = actions)
                    }
                    entry<GhostlockScreen.ProfileOverride>(swipeDismiss = swipeBack) {
                        ProfileOverrideScreen(state = state, actions = actions)
                    }
                    entry<GhostlockScreen.AdvancedOverride>(swipeDismiss = swipeBack) {
                        AdvancedOverrideScreen(state = state, actions = actions)
                    }
                }
                GhostlockDialog(state = state, actions = actions)
                GhostlockOverwriteDialog(state = state, actions = actions)
                RunLogPickerDialog(state = state, actions = actions)
                StridePickerDialog(state = state, actions = actions)
                GhostlockExecutionSheet(state = state, actions = actions)
            }
        }
    }
}

@Composable
private fun MainScreen(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = "GhostLock",
                scrollBehavior = scrollBehavior,
            )
        },
    ) { paddingValues ->
        MainContent(
            state = state,
            actions = actions,
            scrollBehavior = scrollBehavior,
            scaffoldPadding = paddingValues,
            modifier = Modifier.fillMaxSize(),
        )
    }
}

@Composable
internal fun pageContentPadding(
    scaffoldPadding: PaddingValues,
    top: Dp = 8.dp,
    bottom: Dp = 12.dp,
    horizontalMin: Dp = 12.dp,
): PaddingValues {
    val windowWidth = with(LocalDensity.current) {
        LocalWindowInfo.current.containerSize.width.toDp()
    }
    val horizontal = ((windowWidth - 800.dp) / 2).coerceAtLeast(horizontalMin)
    return PaddingValues(
        start = horizontal,
        end = horizontal,
        top = scaffoldPadding.calculateTopPadding() + top,
        bottom = scaffoldPadding.calculateBottomPadding() + bottom,
    )
}

@Composable
private fun GhostlockExecutionSheet(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    OverlayBottomSheet(
        show = state.executionSheetVisible,
        title = stringResource(R.string.log_title),
        allowDismiss = state.executionSheetDismissible,
        onDismissRequest = actions::onCloseExecutionSheet,
        startAction = {
            IconButton(onClick = actions::onCopyLogs) {
                Icon(
                    imageVector = MiuixIcons.Copy,
                    contentDescription = stringResource(R.string.action_copy),
                    tint = MiuixTheme.colorScheme.onBackground,
                )
            }
        },
        endAction = {
            IconButton(
                enabled = state.executionSheetDismissible,
                onClick = actions::onCloseExecutionSheet,
            ) {
                Icon(
                    imageVector = MiuixIcons.Close,
                    contentDescription = stringResource(R.string.action_close),
                )
            }
        },
        content = {
            LogPanel(
                lines = state.logLines,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 240.dp, max = 520.dp)
                    .navigationBarsPadding(),
            )
            /* The run's visible verdict, and the explicit way into the
             * KernelSU manager once the run is over. The manager itself is
             * never auto-launched by the app: on a late-load ROM its own
             * restart is what takes the foreground mid-handoff. */
            if (state.executionSheetDismissible && state.runStatus != RunStatus.Idle) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = stringResource(
                            if (state.runStatus == RunStatus.Success) {
                                R.string.run_status_root_active
                            } else {
                                R.string.run_status_failed
                            },
                        ),
                        modifier = Modifier.weight(1f),
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    TextButton(
                        text = stringResource(R.string.run_notif_open_manager),
                        onClick = actions::onOpenManager,
                    )
                }
            }
        },
    )
}

@Composable
private fun GhostlockDialog(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    OverlayDialog(
        show = state.dialogVisible,
        title = if (state.dialogType == DialogType.NONE) null else stringResource(state.dialogTitleRes),
        onDismissRequest = actions::onDialogDismiss,
        onDismissFinished = actions::onDialogDismissFinished,
        content = {
            when (state.dialogType) {
                DialogType.LIST -> {
                    val items = state.dialogItems.ifEmpty { state.dialogItemResIds.map { stringResource(it) } }
                    val leading = state.dialogLeadingResId
                    val offset = if (leading != null) 1 else 0
                    if (leading != null) {
                        TextButton(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 12.dp),
                            text = stringResource(leading),
                            onClick = { actions.onDialogItemSelected(0) },
                        )
                    }
                    items.forEachIndexed { index, item ->
                        val grade = state.dialogItemGrades.getOrNull(index)
                        val label = if (index == state.dialogCurrentItemIndex) {
                            stringResource(R.string.export_current_marker, item)
                        } else {
                            item
                        }
                        if (grade == null) {
                            /* No chip (image sources, phys choices): keep the
                             * miuix TextButton's centred label and container. */
                            TextButton(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(bottom = 12.dp),
                                text = label,
                                onClick = { actions.onDialogItemSelected(index + offset) },
                            )
                        } else {
                            val chipColors = ButtonDefaults.textButtonColors()
                            Row(
                                /* A chip row: the same TextButton container,
                                 * with the label left-aligned so the chip sits
                                 * right after it. The miuix ButtonDefaults
                                 * values (corner 16.dp, inside margin 16x13.dp)
                                 * are not exposed to app code; they are read
                                 * from the library's constants. */
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(bottom = 12.dp)
                                    .clip(RoundedCornerShape(16.dp))
                                    .background(chipColors.color)
                                    .clickable { actions.onDialogItemSelected(index + offset) }
                                    .padding(horizontal = 16.dp, vertical = 13.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = label,
                                    color = chipColors.textColor,
                                    /* The text fills the row so the chip is
                                     * always right-aligned inside the box. */
                                    modifier = Modifier.weight(1f),
                                )
                                DialogBadge(grade)
                            }
                        }
                    }
                    TextButton(
                        modifier = Modifier.fillMaxWidth(),
                        text = stringResource(R.string.cancel),
                        onClick = actions::onDialogDismiss,
                    )
                }

                DialogType.INPUT -> {
                    TextField(
                        value = state.dialogInput,
                        onValueChange = actions::onDialogInputChange,
                        label = stringResource(state.dialogMessageRes),
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 16.dp)
                    ) {
                        TextButton(
                            modifier = Modifier.weight(1f),
                            text = stringResource(R.string.cancel),
                            onClick = actions::onDialogDismiss,
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        TextButton(
                            modifier = Modifier.weight(1f),
                            text = stringResource(state.dialogConfirmLabelRes),
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                            onClick = { actions.onDialogConfirm(state.dialogInput) },
                        )
                    }
                }

                DialogType.CONFIRM -> {
                    Text(
                        text = stringResource(state.dialogMessageRes),
                        modifier = Modifier.fillMaxWidth(),
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    if (state.dialogExportLog) {
                        TextButton(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                            text = stringResource(R.string.run_log_export),
                            onClick = actions::onDialogExportLog,
                        )
                    }
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 16.dp),
                    ) {
                        TextButton(
                            modifier = Modifier.weight(1f),
                            text = stringResource(R.string.cancel),
                            onClick = actions::onDialogDismiss,
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        TextButton(
                            modifier = Modifier.weight(1f),
                            text = stringResource(R.string.w3_shizuku_hint_enable),
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                            onClick = { actions.onDialogConfirm("") },
                        )
                    }
                }

                DialogType.NOTICE -> {
                    val layerNotice = state.dialogLayerNotice
                    Text(
                        text = if (layerNotice != null) {
                            layerNoticeBody(layerNotice)
                        } else {
                            stringResource(state.dialogMessageRes)
                        },
                        modifier = Modifier.fillMaxWidth(),
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 16.dp),
                    ) {
                        if (state.dialogExportLog) {
                            TextButton(
                                modifier = Modifier.weight(1f),
                                text = stringResource(R.string.run_log_export),
                                onClick = actions::onDialogExportLog,
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                        }
                        state.dialogDocUrl?.let { docUrl ->
                            val uriHandler = LocalUriHandler.current
                            TextButton(
                                modifier = Modifier.weight(1f),
                                text = stringResource(R.string.dialog_open_guide),
                                onClick = { uriHandler.openUri(docUrl) },
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                        }
                        TextButton(
                            modifier = Modifier.weight(1f),
                            text = stringResource(R.string.dialog_dismiss),
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                            onClick = actions::onDialogDismiss,
                        )
                    }
                }

                DialogType.NOTIFICATION_PERMISSION -> {
                    Text(
                        text = stringResource(state.dialogMessageRes),
                        modifier = Modifier.fillMaxWidth(),
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 16.dp),
                    ) {
                        TextButton(
                            modifier = Modifier.weight(1f),
                            text = stringResource(R.string.run_notif_permission_later),
                            onClick = actions::onDialogDismiss,
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        TextButton(
                            modifier = Modifier.weight(1f),
                            text = stringResource(R.string.run_notif_permission_allow),
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                            onClick = { actions.onDialogConfirm("") },
                        )
                    }
                }

                DialogType.NONE -> Unit
            }
        },
    )
}

@Composable
private fun RunLogPickerDialog(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    val context = LocalContext.current
    OverlayDialog(
        show = state.runLogPickerVisible,
        title = stringResource(R.string.run_log_pick_title),
        summary = stringResource(R.string.run_log_pick_summary),
        onDismissRequest = actions::onRunLogPickerDismiss,
        content = {
            Column(modifier = Modifier.fillMaxWidth()) {
                state.runLogs.forEach { run ->
                    TextButton(
                        modifier = Modifier.fillMaxWidth(),
                        text = runLogLabel(context, run),
                        onClick = { actions.onRunLogSelected(run.stamp) },
                    )
                }
                if (state.runLogs.isEmpty()) {
                    Text(
                        text = stringResource(R.string.run_log_empty),
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    )
                }
                if (state.runLogs.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    TextButton(
                        modifier = Modifier.fillMaxWidth(),
                        text = stringResource(R.string.run_log_clear),
                        onClick = actions::onClearRunLogs,
                    )
                }
            }
        },
    )
}

/**
 * The slab-stride decision sheet: one recommendation with an evidence level in
 * plain language, the alternatives as radio rows, and the raw table behind a
 * "technical details" toggle. Dismissing it is the same as Skip.
 */
@Composable
private fun StridePickerDialog(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    val picker = state.stridePicker ?: return
    val recommendation = picker.recommendation
    var detailsExpanded by remember { mutableStateOf(false) }
    OverlayDialog(
        show = true,
        title = stringResource(R.string.stride_title),
        summary = stringResource(R.string.stride_subtitle, recommendation.samples),
        onDismissRequest = actions::onStridePickerDismiss,
        content = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = recommendation.recommendedValue
                                    ?.let { stringResource(R.string.stride_bytes, it) }
                                    ?: stringResource(R.string.stride_none),
                                modifier = Modifier.weight(1f),
                                fontSize = 22.sp,
                                fontWeight = FontWeight.Bold,
                                color = MiuixTheme.colorScheme.onSurface,
                            )
                            Text(
                                text = stringResource(strideLevelRes(recommendation.level)),
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = if (recommendation.level == StrideEvidenceLevel.CONFIRMED ||
                                    recommendation.level == StrideEvidenceLevel.CONSISTENT
                                ) {
                                    MiuixTheme.colorScheme.primary
                                } else {
                                    MiuixTheme.colorScheme.onSurfaceVariantSummary
                                },
                            )
                        }
                        Text(
                            text = strideReasonText(recommendation.reason),
                            style = MiuixTheme.textStyles.body2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        recommendation.confirmedValue?.let { confirmed ->
                            Text(
                                text = stringResource(R.string.stride_confirmed_line, confirmed),
                                style = MiuixTheme.textStyles.body2,
                                color = MiuixTheme.colorScheme.primary,
                            )
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 280.dp)
                        .verticalScroll(rememberScrollState()),
                ) {
                    recommendation.options.forEach { option ->
                        RadioButtonPreference(
                            title = stringResource(
                                R.string.stride_option,
                                option.value,
                                option.matches,
                                option.samples,
                            ),
                            selected = picker.selectedValue == option.value,
                            onClick = { actions.onStrideOptionSelected(option.value) },
                            radioButtonLocation = RadioButtonLocation.End,
                        )
                    }
                }
                TextButton(
                    text = if (detailsExpanded) {
                        "▾ " + stringResource(R.string.stride_details)
                    } else {
                        "▸ " + stringResource(R.string.stride_details)
                    },
                    onClick = { detailsExpanded = !detailsExpanded },
                    modifier = Modifier.fillMaxWidth(),
                )
                if (detailsExpanded) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            text = stringResource(
                                R.string.stride_details_measurements,
                                recommendation.samples,
                                recommendation.rounds,
                            ),
                            style = MiuixTheme.textStyles.body2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        Text(
                            text = stringResource(
                                R.string.stride_details_gcd,
                                recommendation.gcd.toString(16),
                            ),
                            style = MiuixTheme.textStyles.body2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        recommendation.options.forEach { option ->
                            Text(
                                text = stringResource(
                                    R.string.stride_details_candidate,
                                    option.value,
                                    option.matches,
                                    option.samples,
                                    option.objectsPerSlab,
                                ),
                                style = MiuixTheme.textStyles.body2,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            )
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    TextButton(
                        text = picker.selectedValue
                            ?.let { stringResource(R.string.stride_use, it) }
                            ?: stringResource(R.string.stride_use_none),
                        enabled = picker.selectedValue != null,
                        onClick = actions::onStrideUse,
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        text = stringResource(R.string.stride_skip),
                        onClick = actions::onStrideSkip,
                        modifier = Modifier.weight(1f),
                    )
                }
                Text(
                    text = stringResource(picker.footerRes),
                    style = MiuixTheme.textStyles.body2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }
        },
    )
}

private fun strideLevelRes(level: StrideEvidenceLevel): Int = when (level) {
    StrideEvidenceLevel.CONFIRMED -> R.string.stride_level_confirmed
    StrideEvidenceLevel.CONSISTENT -> R.string.stride_level_consistent
    StrideEvidenceLevel.MIXED -> R.string.stride_level_mixed
    StrideEvidenceLevel.INSUFFICIENT -> R.string.stride_level_insufficient
}

@Composable
private fun strideReasonText(reason: StrideReason): String = when (reason) {
    is StrideReason.ConfirmedAgree -> stringResource(
        R.string.stride_reason_confirmed_agree,
        reason.samples,
    )

    is StrideReason.ConfirmedOnly -> stringResource(R.string.stride_reason_confirmed)
    is StrideReason.Agree -> stringResource(R.string.stride_reason_agree, reason.samples)
    is StrideReason.Partial -> stringResource(
        R.string.stride_reason_partial,
        reason.matches,
        reason.samples,
        reason.runnerUp,
    )

    StrideReason.Tie -> stringResource(R.string.stride_reason_tie)
    is StrideReason.Single -> stringResource(
        if (reason.samples > 0) R.string.stride_reason_single else R.string.stride_reason_none,
    )
}

/** `20261009-212803 · Shizuku · interrupted · 42 KB` */
private fun runLogLabel(context: Context, run: RunLogEntry): String {    val state = context.getString(
        when (run.state) {
            RunLogState.RUNNING -> R.string.run_log_state_running
            RunLogState.COMPLETED -> R.string.run_log_state_completed
            RunLogState.FAILED -> R.string.run_log_state_failed
            RunLogState.INTERRUPTED -> R.string.run_log_state_interrupted
        },
    )
    val size = android.text.format.Formatter.formatShortFileSize(context, run.bytes)
    return "${run.stamp} · ${run.entry} · $state · $size"
}

@Composable
private fun GhostlockOverwriteDialog(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    OverlayDialog(
        show = state.overwriteDialogVisible,
        title = stringResource(R.string.overwrite_title),
        summary = stringResource(R.string.overwrite_message, state.overwriteMessage),
        onDismissRequest = actions::onOverwriteDismiss,
        content = {
            Row(modifier = Modifier.fillMaxWidth()) {
                TextButton(
                    modifier = Modifier.weight(1f),
                    text = stringResource(R.string.cancel),
                    onClick = actions::onOverwriteDismiss,
                )
                Spacer(modifier = Modifier.width(12.dp))
                TextButton(
                    modifier = Modifier.weight(1f),
                    text = stringResource(R.string.overwrite_yes),
                    colors = ButtonDefaults.textButtonColorsPrimary(),
                    onClick = actions::onOverwriteConfirm,
                )
            }
        },
    )
}

@Composable
private fun MainContent(
    state: GhostlockUiState,
    actions: GhostlockActions,
    scrollBehavior: ScrollBehavior,
    scaffoldPadding: PaddingValues,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier
            .scrollEndHaptic()
            .overScrollVertical()
            .scrollEndHaptic()
            .fillMaxHeight()
            .nestedScroll(scrollBehavior.nestedScrollConnection)
            .imePadding(),
        contentPadding = pageContentPadding(scaffoldPadding),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(key = "controls") {
            ControlPanel(
                state = state,
                actions = actions,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        if (state.mergeRows.isNotEmpty()) {
            item(key = "merge") {
                Card(modifier = Modifier.fillMaxWidth()) {
                    ArrowPreference(
                        title = stringResource(R.string.merge_preview_title),
                        summary = stringResource(R.string.merge_summary),
                        onClick = actions::onOpenMergePreview,
                    )
                }
            }
        }
        item(key = "export-run-log") {
            TextButton(
                modifier = Modifier.fillMaxWidth(),
                text = stringResource(R.string.run_log_export),
                onClick = actions::onExportRunLog,
            )
        }
        item(key = "run") {
            RunButton(
                running = state.running,
                supported = state.kernelSupported &&
                        state.executionHasProfile &&
                        (!state.shizukuEnabled ||
                                state.shizukuStatus == ShizukuStatus.READY),
                profileValid = state.profileInvalidPaths.isEmpty(),
                labelRes = R.string.action_run,
                onClick = actions::onRun,
                onBlockedClick = actions::onProfileInvalid,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        /* The one-time legacy cleanup sits below the primary action, so it can
         * never push the run button off a fresh screen. */
        if (state.legacyPresent) {
            item(key = "legacy") {
                Card(modifier = Modifier.fillMaxWidth()) {
                    ArrowPreference(
                        title = stringResource(R.string.legacy_present_title),
                        summary = stringResource(R.string.legacy_present_summary),
                        onClick = actions::onOpenLegacyCleanup,
                    )
                }
            }
        }
    }
}

@Composable
private fun ControlPanel(
    state: GhostlockUiState,
    actions: GhostlockActions,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier) {
        ActivationStatusCard(
            supported = state.kernelSupported,
            externalUnreadable = state.externalProfileUnreadable,
            profileAvailable = state.executionHasProfile,
            profileValid = state.profileInvalidPaths.isEmpty(),
            shizukuEnabled = state.shizukuEnabled,
            shizukuStatus = state.shizukuStatus,
            onParametersClick = actions::onOpenParameters,
            onShizukuClick = actions::onStatusClick,
            modifier = Modifier.fillMaxWidth(),
        )
        DeviceInfoCard(
            deviceName = state.deviceName,
            socName = state.socName,
            kernelRelease = state.kernelRelease,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp),
        )
        /* The profile-generation entry sits on the home: one sheet, OTA link
         * or an on-device image, instead of the deep advanced page. */
        Card(modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
            ArrowPreference(
                title = stringResource(R.string.home_generate_profile),
                summary = stringResource(R.string.home_generate_profile_summary),
                onClick = actions::onGenerateProfile,
            )
        }
        Card(modifier = modifier.padding(top = 12.dp)) {
            if (state.cpuPairLabels.isNotEmpty()) {
                val customPair = state.customCpuPair
                val customSummary = customPair?.let {
                    stringResource(
                        R.string.cpu_pair_custom,
                        "${it.primary}, ${it.consumer}",
                    )
                }
                OverlaySpinnerPreference(
                    title = stringResource(R.string.cpu_pair_label),
                    items = state.cpuPairLabels.map { DropdownItem(icon = null, title = it) },
                    selectedIndex = if (customPair == null) state.cpuPairIndex else -1,
                    summary = customSummary,
                    showValue = customPair == null,
                    onSelectedIndexChange = actions::onCpuPairSelected,
                )
            }
            SwitchPreference(
                checked = state.safeModeEnabled,
                onCheckedChange = actions::onSafeModeChanged,
                title = stringResource(R.string.safe_mode_label),
                summary = stringResource(R.string.safe_mode_summary),
            )
            /* PROFILE-SUGGEST-01: the profile suggestion seeds the toggle but no
             * longer hides it; an explicit user choice overrides either way. */
            SwitchPreference(
                checked = state.shizukuEnabled,
                onCheckedChange = actions::onShizukuChanged,
                title = stringResource(R.string.shizuku_label),
                summary = stringResource(
                    when {
                        !state.shizukuEnabled -> R.string.shizuku_summary
                        state.shizukuStatus == ShizukuStatus.READY -> R.string.shizuku_status_ready
                        state.shizukuStatus == ShizukuStatus.PERMISSION_REQUIRED ->
                            R.string.shizuku_status_permission_required

                        state.shizukuStatus == ShizukuStatus.NOT_RUNNING ->
                            R.string.shizuku_status_not_running

                        else -> R.string.shizuku_status_checking
                    },
                ),
            )
            val tagMode = stringResource(vrKoModeLabelRes(state.vrKoTagClear))
            val selinuxMode = stringResource(vrKoModeLabelRes(state.vrKoSelinuxBlock))
            ArrowPreference(
                title = stringResource(R.string.vr_ko_entry_label),
                summary = stringResource(R.string.vr_ko_entry_summary, tagMode, selinuxMode),
                onClick = actions::onOpenVrKo,
            )
        }
        Card(modifier = modifier.padding(top = 12.dp)) {
            ArrowPreference(
                title = stringResource(R.string.advanced_settings),
                summary = stringResource(R.string.advanced_settings_summary),
                onClick = actions::onOpenAdvanced,
            )
        }
    }
}

@Composable
private fun ActivationStatusCard(
    supported: Boolean,
    externalUnreadable: Boolean,
    profileAvailable: Boolean,
    profileValid: Boolean,
    shizukuEnabled: Boolean,
    shizukuStatus: ShizukuStatus,
    onParametersClick: () -> Unit,
    onShizukuClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val accessReady = !shizukuEnabled || shizukuStatus == ShizukuStatus.READY
    val ready = supported && profileAvailable && profileValid && accessReady
    val missing = !supported || !profileAvailable
    val (backgroundColor, title, icon) = when {
        ready -> Triple(
            when {
                MiuixTheme.isDynamicColor -> MiuixTheme.colorScheme.secondaryContainer
                isSystemInDarkTheme() -> Color(0xFF1A3825)
                else -> Color(0xFFDFFAE4)
            },
            R.string.kernel_supported,
            Icons.Rounded.CheckCircleOutline,
        )

        /* The selected document itself cannot be read: the resolver has no
         * profile, and the fault is the selection, not the kernel. Checked
         * before `missing` so the card never blames the kernel match. */
        externalUnreadable -> Triple(
            MiuixTheme.colorScheme.errorContainer,
            R.string.kernel_external_unreadable,
            Icons.Rounded.ErrorOutline,
        )

        missing -> Triple(
            MiuixTheme.colorScheme.errorContainer,
            if (!supported) R.string.kernel_unsupported else R.string.kernel_profile_required,
            Icons.Rounded.RemoveCircleOutline,
        )

        else -> Triple(
            when {
                MiuixTheme.isDynamicColor -> MiuixTheme.colorScheme.tertiaryContainer
                isSystemInDarkTheme() -> Color(0xFF3E2F1B)
                else -> Color(0xFFFFF0DB)
            },
            if (!profileValid) R.string.kernel_profile_invalid else R.string.shizuku_label,
            Icons.Rounded.ErrorOutline,
        )
    }
    val summary = when {
        ready && shizukuEnabled -> R.string.kernel_profile_ready_shizuku
        ready -> R.string.kernel_profile_ready
        externalUnreadable -> R.string.kernel_external_unreadable_summary
        !supported -> R.string.kernel_unsupported_summary
        !profileAvailable -> R.string.kernel_profile_required_summary
        !profileValid -> R.string.kernel_profile_invalid_summary
        shizukuStatus == ShizukuStatus.PERMISSION_REQUIRED ->
            R.string.shizuku_status_permission_required

        else -> R.string.shizuku_status_not_running
    }
    val action = if (!externalUnreadable && supported && profileAvailable && profileValid && !accessReady) {
        onShizukuClick
    } else {
        onParametersClick
    }
    Card(
        modifier = modifier,
        colors = CardDefaults.defaultColors(color = backgroundColor),
        onClick = action,
        showIndication = true,
        pressFeedbackType = PressFeedbackType.Tilt,
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 110.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (MiuixTheme.isDynamicColor) {
                    when (icon) {
                        Icons.Rounded.CheckCircleOutline -> MiuixTheme.colorScheme.primary.copy(alpha = 0.8f)
                        Icons.Rounded.RemoveCircleOutline ->
                            MiuixTheme.colorScheme.onTertiaryContainer.copy(alpha = 0.8f)

                        else -> MiuixTheme.colorScheme.onErrorContainer.copy(alpha = 0.8f)
                    }
                } else {
                    when (icon) {
                        Icons.Rounded.CheckCircleOutline -> Color(0xFF36D167)
                        Icons.Rounded.RemoveCircleOutline -> Color(0xFFF5A623)
                        else -> Color(0xFFF72727)
                    }
                },
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .offset(x = 27.dp, y = 31.dp)
                    .size(110.dp),
            )
            Column(
                modifier = Modifier.padding(start = 16.dp, top = 14.dp, end = 120.dp, bottom = 14.dp),
            ) {
                Text(
                    text = stringResource(title),
                    fontSize = 22.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(modifier = Modifier.height(1.dp))
                Text(
                    text = stringResource(summary),
                    fontSize = 15.sp,
                )
            }
        }
    }
}

@Composable
private fun DeviceInfoCard(
    deviceName: String,
    socName: String,
    kernelRelease: String,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier,
        insideMargin = PaddingValues(16.dp),
    ) {
        SelectionContainer {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(20.dp),
            ) {
                DeviceInfoItem(
                    title = stringResource(R.string.device_label),
                    value = deviceName,
                )
                DeviceInfoItem(
                    title = stringResource(R.string.soc_label),
                    value = socName,
                )
                DeviceInfoItem(
                    title = stringResource(R.string.kernel_label),
                    value = kernelRelease,
                )
            }
        }
    }
}

@Composable
private fun DeviceInfoItem(
    title: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier) {
        Text(
            text = title,
            fontSize = 18.sp,
            fontWeight = FontWeight.Medium,
            color = MiuixTheme.colorScheme.onSurface,
        )
        Text(
            text = value,
            modifier = Modifier.padding(top = 2.dp),
            fontSize = 14.sp,
            color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.68f),
        )
    }
}

/* profile-ui: resolved execution view with auto-saved sparse overrides. */
@Composable
internal fun ExecutionEditor(
    state: GhostlockUiState,
    actions: GhostlockActions,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        for (field in state.executionFields) {
            val text = state.executionEditing[field.path] ?: field.value.toString()
            val invalid = isFieldInputInvalid(text) || field.path in state.profileInvalidPaths
            TextField(
                value = text,
                onValueChange = { value -> actions.onExecutionFieldChanged(field.path, value) },
                label = fieldLabel(field.path, field.path.substringAfterLast('.')),
                colors = when {
                    invalid ->
                        TextFieldDefaults.textFieldColors(labelColor = FieldErrorHighlight)

                    field.overridden ->
                        TextFieldDefaults.textFieldColors(labelColor = OverrideHighlight)

                    else -> TextFieldDefaults.textFieldColors()
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
        }
    }
}

internal val OverrideHighlight = Color(0xFFF5A623)

/** Red marks an unfilled or non-numeric field in the parameter editors. */
internal val FieldErrorHighlight = Color(0xFFE53935)

internal fun isFieldInputInvalid(text: String): Boolean = text.trim().toLongOrNull() == null

@Composable
private fun RunButton(
    running: Boolean,
    supported: Boolean,
    profileValid: Boolean,
    labelRes: Int,
    onClick: () -> Unit,
    onBlockedClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Box(modifier = modifier) {
        TextButton(
            text = stringResource(if (running) R.string.action_running else labelRes),
            enabled = supported && profileValid && !running,
            colors = ButtonDefaults.textButtonColorsPrimary(),
            onClick = onClick,
            modifier = Modifier.fillMaxWidth(),
        )
        /* A disabled TextButton consumes no pointer input, so this overlay
         * explains why the run is blocked. */
        if (!running && (!supported || !profileValid)) {
            Box(
                modifier = Modifier
                    .matchParentSize()
                    .clickable { onBlockedClick() },
            )
        }
    }
}

@Composable
private fun LogPanel(
    lines: List<GhostlockLogLine>,
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.scrollToItem(lines.lastIndex)
    }
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(Color(0xFF0B1220))
            .padding(12.dp),
    ) {
        SelectionContainer {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(top = 8.dp),
            ) {
                items(lines) { line ->
                    Text(
                        text = line.text.trimEnd('\r', '\n'),
                        color = lineColor(line.color),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                    )
                }
            }
        }
    }
}

/**
 * A dialog choice's chip, rendered inline after the option (same row, trailing)
 * rather than on its own line above it: a colored dot + the short label.
 */
@Composable
private fun DialogBadge(chip: DialogChip) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(start = 8.dp),
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(chip.color),
        )
        Spacer(Modifier.width(6.dp))
        Text(
            text = stringResource(chip.labelRes),
            fontSize = 11.sp,
        )
    }
}

private fun lineColor(color: Int): Color = when (color) {
    0xFFFF6B6B.toInt() -> Color(0xFFFF6B6B)
    0xFF5FD68A.toInt() -> Color(0xFF5FD68A)
    0xFFFFC94D.toInt() -> Color(0xFFFFC94D)
    0xFF60A5FA.toInt() -> Color(0xFF60A5FA)
    else -> Color(0xFFD1D5DB)
}
