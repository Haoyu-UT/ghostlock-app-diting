package com.ghostlock.app.domain.model

import com.ghostlock.app.data.OptionSuperset
import java.util.Locale

data class CpuPair(val primary: Int, val consumer: Int) {
    override fun toString(): String = "$primary,$consumer"
}

/**
 * The profile's CPU hint, accepted only when it names one of the device's own
 * candidate pairs. A hint from another device (8/9 on an 8-core phone, a
 * negative value, or a value that overflows an Int) is ignored rather than
 * displayed or acted on; the session pair remains the only pinning input.
 */
internal fun customCpuPairHint(
    primary: Long,
    consumer: Long,
    candidates: List<CpuPair>,
    devicePair: CpuPair?,
): CpuPair? {
    if (primary !in 0L..Int.MAX_VALUE.toLong() || consumer !in 0L..Int.MAX_VALUE.toLong()) return null
    val pair = CpuPair(primary.toInt(), consumer.toInt())
    return pair.takeIf { it in candidates && it != devicePair }
}

/** True when the runtime SoC string names a MediaTek part. */
internal fun isMediaTekSoc(socName: String): Boolean {
    val soc = socName.lowercase(Locale.ROOT)
    return soc.contains("mediatek") || soc.contains("mtk") ||
        /* ro.soc.model / ro.board.platform are `MTxxxx` on MediaTek; mirror the
         * native detector's prefix rule. */
        soc.startsWith("mt") ||
        soc.contains("dimensity") || soc.contains("helio")
}

/**
 * Whether the resolved physical pair may be used on this device.
 *
 * A profile-supplied pair is always usable. A missing pair falls back to the
 * compiled platform default only on platforms where that default has a track
 * record (Qualcomm's per-generation KernelBaseAddr). MediaTek has no reliable
 * compiled default -- the sampled fleet uses 0x40000000, 0x40080000/+0x40000000
 * and 0x80000000 -- so an MTK device without a bootloader-derived pair is not
 * runnable; it must supply vendor_boot/dtbo and re-parse.
 */
internal fun physicalPairUsable(socName: String, pairKnown: Boolean): Boolean =
    pairKnown || !isMediaTekSoc(socName)

data class KernelSnapshot(
    val deviceName: String,
    val kernelRelease: String,
    val socName: String = "",
    val kernelSupported: Boolean,
    /** The kernel is known but its physical layout is missing on this MTK device. */
    val devicePairMissing: Boolean = false,
    val cpuPairs: List<CpuPair>,
    val cpuPairLabels: List<String>,
    val selectedCpuPair: Int,
    val safeModeEnabled: Boolean,
    /** Skip the pre-attack KernelSU check and run the exploit as a test. */
    val forceAttackTest: Boolean = false,
    /** Clear the vendor vr.ko task tags before W2; Auto follows the probe/version recommendation. */
    val vrKoTagClear: VrKoMode = VrKoMode.AUTO,
    /** Block the vr.ko SELinux 0/1 enforce write; Auto targets the 5.10.198 class only. */
    val vrKoSelinuxBlock: VrKoMode = VrKoMode.AUTO,
    /** Profile/imported offsets force the Shizuku path. */
    val recommendShizuku: Boolean,
    /** User-selected Shizuku path for kernels that do not require it. */
    val shizukuEnabled: Boolean = false,
    val shizukuStatus: ShizukuStatus,
)

enum class ShizukuStatus { NOT_REQUIRED, NOT_RUNNING, PERMISSION_REQUIRED, READY }

/**
 * User-authoritative tri-state control for a vr.ko behaviour.
 *
 * Auto is the only value that consults the version/probe recommendation; On and Off are final.
 * [wire] is what the native environment and the root script receive.
 */
enum class VrKoMode(val wire: String) {
    AUTO("auto"),
    ON("on"),
    OFF("off"),
    ;

    companion object {
        /** Lenient parser for stored preferences and the old boolean values. */
        fun fromWire(value: String?): VrKoMode = when (value?.trim()?.lowercase()) {
            "on", "1", "true" -> ON
            "off", "0", "false" -> OFF
            else -> AUTO
        }
    }
}

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

/** One root-measured fact, as the read-only measurements screen shows it. */
data class MeasuredFactInfo(
    /** Dotted profile path (`kernelsnitch.mm_struct_sz`). */
    val key: String,
    val value: Long,
    /** Only `root-slabinfo` today; the screen shows it verbatim. */
    val source: String,
    /** The raw `/proc/slabinfo` line, the fact's basis. */
    val evidence: String,
    val measuredAt: Long,
)

/** Facts measured on one kernel release. */
data class MeasuredKernelInfo(
    val release: String,
    val updatedAt: Long,
    val facts: List<MeasuredFactInfo>,
)

/**
 * One fact the measured database would change in the active profile. The home
 * merge preview lists these; the export applies exactly these values.
 */
data class MeasurementMergeRow(
    val path: String,
    val profileValue: Long?,
    val measuredValue: Long,
    val source: String,
    val evidence: String,
    val measuredAt: Long,
)

/** What the one-time legacy cleanup found in app data. */
data class LegacyProfileState(
    val profiles: List<UserProfileFile> = emptyList(),
    val overridePresent: Boolean = false,
) {
    val present: Boolean get() = profiles.isNotEmpty() || overridePresent
}

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
    /** External document selected for this release, when any. */
    val external: String? = null,
    val externalApplied: Boolean = false,
    /** SAF URI of the selected document, for the run log's provenance line. */
    val externalUri: String? = null,
    val externalSha256: String? = null,
    /** Lineage an app export recorded in its comment header. */
    val externalParent: String? = null,
    /** Why the selected external document could not be used. */
    val externalError: String? = null,
) {
    /** True when something present was deliberately not applied. */
    val hasInactiveLayer: Boolean
        get() = (imported != null && !importedApplied) ||
            (overridesPresent && !overridesApplied) ||
            externalError != null

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
        external?.let { name ->
            add(
                if (externalApplied) {
                    "external=$name applied (uri=${externalUri ?: "?"} " +
                        "sha256=${externalSha256 ?: "unknown"})"
                } else {
                    "external=$name NOT APPLIED (${externalError ?: "unavailable"})"
                },
            )
        }
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

/** The external profile document the user selected for this release. */
data class ExternalProfileInfo(
    val name: String,
    val release: String,
    val sha256: String,
    /** Parent label/hash an app export recorded, when the document carries one. */
    val parent: String? = null,
)

/** One field where the current profile differs from the bundled document. */
data class ProfileDiffRow(
    /** Dotted profile path. */
    val path: String,
    val current: Long?,
    val bundled: Long?,
)

/** Resolved execution view for the advanced editor (controller-owned). */
/**
 * The active route's lock-anchor trio, as the resolved profile states it.
 * [bytes]/[stride] are null when the profile leaves them to the native
 * defaults (0x1000 / 0x20); [image] is the image-relative offset.
 */
data class AnchorGeometry(
    val image: Long,
    val bytes: Long? = null,
    val stride: Long? = null,
)

data class ProfileConfig(
    val release: String,
    val hasProfile: Boolean,
    /**
     * CPU pair this config was resolved for. The native document is resolved on
     * demand rather than cached, so it needs the pair the caller resolved with.
     */
    val pair: CpuPair = CpuPair(0, 0),
    /** Resolved physical pair; null when the profile carries none for this device. */
    val physLoad: Long? = null,
    val physOffset: Long? = null,
    /** Active route's anchor, when the profile states one (page-free routes). */
    val anchor: AnchorGeometry? = null,
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
        val Routes = listOf("tcp_zerocopy", "select_stack", "multicast_waiter", "sigreturn")

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

/** One route verdict from the extractor's `--feasible-out` report. */
data class RouteVerdict(
    val route: String,
    /** `feasible`, `infeasible` or `unknown`, as the extractor labels it. */
    val verdict: String,
    val reason: String,
    val numbers: Map<String, Long> = emptyMap(),
)

/** One candidate from the unprivileged mm_struct slab-stride probe. */
data class StrideCandidateOption(
    val value: Int,
    /** Rounds whose leaked offset is divisible by this stride. */
    val votes: Int,
    /** Nonzero-offset rounds: the denominator shown next to [votes]. */
    val samples: Int,
    /** `ORDER3_SIZE / value`, the spray shaping this candidate implies. */
    val objectsPerSlab: Int,
)

/**
 * The probe's evidence table. Candidates arrive sorted by votes (descending),
 * then value; no vote threshold has been applied — the user weighs the counts.
 */
data class StrideProbe(
    val candidates: List<StrideCandidateOption>,
    val rounds: Int,
    val samples: Int,
    val gcd: Long,
    /** One candidate holds every nonzero vote. */
    val decided: Boolean,
)

sealed interface ParseResult {
    /** Fields only an xbl_config/uefi sidecar can supply (e.g.
     * `kernel_phys_load`) that the parsed profile is still missing. */
    data class Parsed(
        val releases: List<String>,
        val missing: Set<String> = emptySet(),
        /** Suggested export name, not a stored document. */
        val documentName: String? = null,
        /** Route the extractor emitted, when its report names one. */
        val route: String? = null,
        /** The extractor's lock-anchor line (verdict and reason), if any. */
        val anchor: String? = null,
        /** The generated document carries a `lock_anchor_*` triple. */
        val hasAnchor: Boolean = false,
        /** Extractor's canonical phys source (`xbl_config FDT`, `uefi memory
         * map`, `vendor_boot …`, `MediaTek DRAM base`, `--phys`, `unset`). */
        val physSource: String? = null,
        /** The parsed document carries `kernel_phys_load`. */
        val physLoadPresent: Boolean = false,
        /** The parsed document carries `kernel_phys_offset`. */
        val physOffsetPresent: Boolean = false,
        /**
         * The generated document itself. The app stores no profile: the caller
         * probes it, applies the chosen stride in memory and requires an export
         * before it can be selected for a run.
         */
        val documentText: String? = null,
        /** The extractor's option superset (all routes/candidates/plans). */
        val options: OptionSuperset? = null,
    ) : ParseResult

    /**
     * More than one route is Feasible on this image. The extractor wrote the
     * verdicts and exited 7 without a profile; the caller asks the user which
     * route to generate and calls [parseSource] again with that route.
     */
    data class Ambiguous(
        val routes: List<RouteVerdict>,
        /** The option superset, when the extractor wrote one. */
        val options: OptionSuperset? = null,
    ) : ParseResult

    data class RequiresOverwrite(
        val releases: List<String>,
        val missing: Set<String> = emptySet(),
    ) : ParseResult

    data object AlreadyPresent : ParseResult

    data class Failed(val code: Int, val reason: String? = null) : ParseResult
}
