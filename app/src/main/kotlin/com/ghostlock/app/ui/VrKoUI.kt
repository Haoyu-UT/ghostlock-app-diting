package com.ghostlock.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.ghostlock.app.R
import com.ghostlock.app.domain.model.VrKoMode
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.DropdownItem
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberTopAppBarState
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.preference.OverlaySpinnerPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

internal fun vrKoModeLabelRes(mode: VrKoMode): Int = when (mode) {
    VrKoMode.AUTO -> R.string.vr_ko_mode_auto
    VrKoMode.ON -> R.string.vr_ko_mode_on
    VrKoMode.OFF -> R.string.vr_ko_mode_off
}

@Composable
private fun vrKoModeItems(): List<DropdownItem> = listOf(
    DropdownItem(icon = null, title = stringResource(R.string.vr_ko_mode_auto)),
    DropdownItem(icon = null, title = stringResource(R.string.vr_ko_mode_on)),
    DropdownItem(icon = null, title = stringResource(R.string.vr_ko_mode_off)),
)

/**
 * Auto is a run-time resolution, not a promise: the tag probe reads
 * /proc/modules inside the native, so the summary states only the version half
 * and the run log carries the effective decision.
 */
@Composable
private fun vrKoTagClearSummary(release: String, mode: VrKoMode): String {
    val major = release.substringBefore('.').toIntOrNull()
    return when {
        mode == VrKoMode.OFF -> stringResource(R.string.vr_ko_tag_clear_summary_off)
        mode == VrKoMode.ON && (major == null || major < 6) ->
            stringResource(R.string.vr_ko_tag_clear_summary_on_5x)

        mode == VrKoMode.ON -> stringResource(R.string.vr_ko_tag_clear_summary_on)
        major == null -> stringResource(R.string.vr_ko_tag_clear_summary_auto_unknown)
        major < 6 -> stringResource(R.string.vr_ko_tag_clear_summary_auto_5x)
        else -> stringResource(R.string.vr_ko_tag_clear_summary_auto_6x)
    }
}

@Composable
private fun vrKoSelinuxBlockSummary(release: String, mode: VrKoMode): String {
    val is198 = release.startsWith("5.10.198")
    return when {
        mode == VrKoMode.OFF -> stringResource(R.string.vrko_selinux_block_summary_off)
        mode == VrKoMode.ON && !is198 ->
            stringResource(R.string.vrko_selinux_block_summary_on_other)

        mode == VrKoMode.ON -> stringResource(R.string.vrko_selinux_block_summary_on)
        is198 -> stringResource(R.string.vrko_selinux_block_summary_auto_198)
        else -> stringResource(R.string.vrko_selinux_block_summary_auto_other)
    }
}

/**
 * The vr.ko options, one screen behind the home entry. The home row shows only
 * the two current modes; the explanations and the exact scope live here.
 */
@Composable
internal fun VrKoScreen(
    state: GhostlockUiState,
    actions: GhostlockActions,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.vr_ko_entry_label),
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = actions::onCloseVrKo) {
                        Icon(
                            imageVector = MiuixIcons.Back,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .imePadding()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            contentPadding = pageContentPadding(paddingValues),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "options") {
                Card {
                    Column {
                        OverlaySpinnerPreference(
                            title = stringResource(R.string.vr_ko_tag_clear_label),
                            items = vrKoModeItems(),
                            selectedIndex = state.vrKoTagClear.ordinal,
                            summary = vrKoTagClearSummary(state.kernelRelease, state.vrKoTagClear),
                            showValue = true,
                            onSelectedIndexChange = { index ->
                                actions.onVrKoTagClearChanged(VrKoMode.entries[index])
                            },
                        )
                        OverlaySpinnerPreference(
                            title = stringResource(R.string.vrko_selinux_block_label),
                            items = vrKoModeItems(),
                            selectedIndex = state.vrKoSelinuxBlock.ordinal,
                            summary = vrKoSelinuxBlockSummary(
                                state.kernelRelease,
                                state.vrKoSelinuxBlock,
                            ),
                            showValue = true,
                            onSelectedIndexChange = { index ->
                                actions.onVrKoSelinuxBlockChanged(VrKoMode.entries[index])
                            },
                        )
                    }
                }
            }
            item(key = "scope") {
                Card {
                    Text(
                        text = stringResource(R.string.vr_ko_scope),
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
            }
        }
    }
}
