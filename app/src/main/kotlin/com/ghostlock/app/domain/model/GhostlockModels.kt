package com.ghostlock.app.domain.model

data class CpuPair(val primary: Int, val consumer: Int) {
    override fun toString(): String = "$primary,$consumer"
}

data class KernelSnapshot(
    val deviceName: String,
    val kernelRelease: String,
    val socName: String = "",
    val kernelSupported: Boolean,
    val cpuPairs: List<CpuPair>,
    val cpuPairLabels: List<String>,
    val selectedCpuPair: Int,
    val safeModeEnabled: Boolean,
    /** Skip the pre-attack KernelSU check and run the exploit as a test. */
    val forceAttackTest: Boolean = false,
    /** Profile/imported offsets force the Shizuku path. */
    val recommendShizuku: Boolean,
    /** User-selected Shizuku path for kernels that do not require it. */
    val shizukuEnabled: Boolean = false,
    val shizukuStatus: ShizukuStatus,
)

enum class ShizukuStatus { NOT_REQUIRED, NOT_RUNNING, PERMISSION_REQUIRED, READY }

enum class LogTone { Default, Error, Success, Warning, Progress, Kotlin, Shizuku }

data class LogEntry(val text: String, val tone: LogTone)

data class OffsetCandidate(val release: String, val document: String)

/** One verbatim user-imported document in the user profile folder. */
data class UserProfileFile(
    val name: String,
    val releases: List<String>,
    val importedAt: Long,
    val sizeBytes: Long,
    val parseError: Boolean,
    /** 1 = legacy layout (load only), 2 = current layout (editable). */
    val version: Int = 2,
)

/** One editable advisory execution value (PROFILE-SUGGEST-01 / profile-ui). */
data class ExecutionFieldValue(
    val path: String,
    val value: Long,
    val overridden: Boolean,
)

/**
 * Debug-only preferences shown by the hidden debug screen. The run log itself is
 * not among them: it is always kept, because the run that needs reporting is the
 * one that failed.
 */
data class DebugSettings(
    val kernelLogEnabled: Boolean = true,
)

/** How a retained run ended; [INTERRUPTED] is decided at the next app start. */
enum class RunLogState(val token: String) {
    RUNNING("running"),
    COMPLETED("completed"),
    FAILED("failed"),
    INTERRUPTED("interrupted"),
    ;

    companion object {
        /** An unknown token reads as [INTERRUPTED]: it did not record a clean end. */
        fun fromToken(token: String): RunLogState =
            entries.firstOrNull { it.token == token } ?: INTERRUPTED
    }
}

/**
 * One retained run, as the export picker lists it. [entry] is the launch path
 * (`direct` or `shizuku`), [bytes] the run's footprint on the device.
 */
data class RunLogEntry(
    val stamp: String,
    val entry: String,
    val state: RunLogState,
    val bytes: Long,
)

/** One node of the resolved profile tree: a JSON group or a numeric leaf. */
data class ProfileFieldNode(
    val path: String,
    val name: String,
    val value: Long? = null,
    /** True when this field or any descendant has an explicit override. */
    val overridden: Boolean = false,
    val children: List<ProfileFieldNode> = emptyList(),
) {
    val isGroup: Boolean get() = children.isNotEmpty()
}

/**
 * Which profile layers a resolution actually used, and why the others did not
 * (PORT-PLAN Phase 8 §B/§C). Built by the controller on every resolve, logged
 * by every run, and shown when a layer is present but inactive.
 */
data class ProfileLayers(
    /** Release the builtin layer resolved through; null when nothing matched. */
    val builtinRelease: String? = null,
    /**
     * True when the builtin layer is the **bundled** asset for the device's own
     * release — the case where the bundled profile is authoritative and a
     * shadowing import is not applied.
     */
    val bundledAuthoritative: Boolean = false,
    /** True when a builtin release was selected by hand instead of auto-matched. */
    val builtinSelected: Boolean = false,
    /** Imported document that would feed the imported layer, if one is loaded. */
    val imported: String? = null,
    val importedApplied: Boolean = false,
    /** Stored overrides exist for this release, whether or not they apply. */
    val overridesPresent: Boolean = false,
    val overridesApplied: Boolean = false,
    /** Build that wrote the stored overrides, when it is not the running one. */
    val overridesBuild: String? = null,
    /** Build identity of the running app (`BuildConfig.GIT_SHA`). */
    val build: String = "",
    /** Keys the resolved profile carries that no wire section declares. */
    val uncarriedKeys: List<String> = emptyList(),
) {
    /** True when something on disk was deliberately not applied. */
    val hasInactiveLayer: Boolean
        get() = (imported != null && !importedApplied) || (overridesPresent && !overridesApplied)

    /**
     * Whether this state owes the user the start-up notice, given the build
     * they last acknowledged it for. Pure on purpose: the *caller* must pass the
     * layers of a real resolution, because the notice states what has already
     * happened — see PORT-PLAN §C.12b.
     */
    fun noticeDue(acknowledgedBuild: String?): Boolean =
        hasInactiveLayer && build.isNotEmpty() && acknowledgedBuild != build

    /** Human-readable layer state; one clause per layer. */
    fun describe(): String = buildList {
        add(
            when {
                builtinRelease == null -> "builtin=none"
                bundledAuthoritative -> "builtin=$builtinRelease (bundled, authoritative)"
                builtinSelected -> "builtin=$builtinRelease (selected by hand)"
                else -> "builtin=$builtinRelease"
            },
        )
        imported?.let { name ->
            add(
                if (importedApplied) {
                    "imported=$name applied"
                } else {
                    "imported=$name SKIPPED (superseded by the bundled profile)"
                },
            )
        }
        add(
            when {
                !overridesPresent -> "overrides=none"
                overridesApplied -> "overrides applied"
                else -> "overrides DISABLED (written by build ${overridesBuild ?: "unknown"}, " +
                    "running $build)"
            },
        )
        add("build=$build")
    }.joinToString("; ")
}

/** Resolved execution view for the advanced editor (controller-owned). */
data class ProfileConfig(
    val release: String,
    val hasProfile: Boolean,
    /**
     * CPU pair this config was resolved for. The native document is resolved on
     * demand rather than cached, so it needs the pair the caller resolved with.
     */
    val pair: CpuPair = CpuPair(0, 0),
    /** Layer state of this resolution; null when nothing resolved. */
    val layers: ProfileLayers? = null,
    /** Hierarchical view of every numeric leaf, override flags included. */
    val roots: List<ProfileFieldNode> = emptyList(),
    /** General (execution tuning) subset exposed by the parameters screen. */
    val general: List<ExecutionFieldValue> = emptyList(),
    /** Explicit route from the profile; null means geometry inference. */
    val route: String? = null,
    /** Declared fallback route ("none"/"<route>"); null means unset. */
    val fallbackTo: String? = null,
    /** Dotted paths whose resolved value violates the geometry rules. */
    val invalidPaths: Set<String> = emptySet(),
) {
    companion object {
        /** Routes a profile may declare ("" is the inference fallback). */
        val Routes = listOf("tcp_zerocopy", "select_stack", "multicast_waiter")

        /**
         * Route-independent execution tuning paths the general editor always
         * exposes. Route-specific tuning is appended dynamically from the
         * resolved profile for the active route (plus its fallback), so a
         * profile never shows another route's knobs.
         */
        val GeneralPaths = listOf(
            "execution.selected_cpus.main",
            "execution.selected_cpus.consumer",
            "execution.heap.prepare_max_attempts",
            "execution.heap.prepare_timeout_ms",
            "execution.heap.kernelsnitch_timeout_ms",
            "execution.race.route_wait_ms",
            "execution.race.route_done_timeout_ms",
            "execution.race.setup_settle_us",
            "execution.race.state_poll_interval_us",
            "execution.stages.w1_attempts",
            "execution.stages.w1_settle_us",
            "execution.stages.w1_scratch_repair_attempts",
            "execution.stages.w2_attempts",
            "execution.stages.w2_settle_us",
            "execution.stages.w3_chain_rounds",
            "execution.stages.w3_attempts",
            "execution.stages.w3_settle_us",
            "execution.handoff.pre_dispatch_settle_ms",
            "execution.handoff.module_poll_attempts",
            "execution.handoff.module_poll_interval_ms",
            "execution.handoff.enforce_poll_attempts",
            "execution.handoff.enforce_poll_interval_ms",
        )
    }
}

data class KernelOffsets(
    val release: String,
    val scalars: Map<String, Long?>,
    val symbols: Map<String, Long?>,
    val structFields: Map<String, Long?>,
)

sealed interface OffsetImportResult {
    data class Imported(val releases: List<String>) : OffsetImportResult
    data class RequiresOverwrite(val releases: List<String>) : OffsetImportResult
    data object AlreadyPresent : OffsetImportResult
    data class MissingIncludes(val files: List<String>) : OffsetImportResult
    data class Failed(val reason: String) : OffsetImportResult
}

sealed interface ParseResult {
    /** Fields only an xbl_config/uefi sidecar can supply (e.g.
     * `kernel_phys_load`) that the parsed profile is still missing. */
    data class Parsed(
        val releases: List<String>,
        val missing: Set<String> = emptySet(),
        /** Name of the stored document, so the caller can auto-load it. */
        val documentName: String? = null,
    ) : ParseResult

    data class RequiresOverwrite(
        val releases: List<String>,
        val missing: Set<String> = emptySet(),
    ) : ParseResult

    data object AlreadyPresent : ParseResult

    data class Failed(val code: Int, val reason: String? = null) : ParseResult
}
