package com.ghostlock.app.domain.model

/**
 * Why the run-start pre-flight refused to start the native.
 *
 * Only failures the app can decide from its own state belong here (class 1 of
 * the 2026-11-07 exit audit): they are checked before the log sheet opens, so
 * no run-store entry and no native process are created. Post-run patterns
 * (dirty race, chain failures, signals) are a separate mapping.
 */
enum class PreflightFailure {
    /** The anchor state file is absent/unreadable and the install postdates the boot. */
    ANCHOR_STATE_UNCONFIRMED,

    /** Every anchor slot this boot is spent; another attempt would walk live .bss. */
    ANCHOR_BUDGET_SPENT,

    /** The state file's slot grid is not this profile's grid (or its count is invalid). */
    ANCHOR_GRID_MISMATCH,

    /** The selected CPU pair refuses sched_setaffinity (paused core / cpuset). */
    CPU_PAIR_UNAVAILABLE,

    /** No late-load-capable KernelSU-family manager is installed. */
    NO_ROOT_MANAGER,
}

sealed interface PreflightResult {
    data object Passed : PreflightResult

    data class Blocked(val failure: PreflightFailure) : PreflightResult
}
