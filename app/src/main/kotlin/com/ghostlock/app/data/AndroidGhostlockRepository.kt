package com.ghostlock.app.data

import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Context
import android.net.IpSecAlgorithm
import android.net.IpSecManager
import android.net.IpSecTransform
import android.os.Build
import android.os.SystemClock
import android.provider.MediaStore
import android.system.Os
import android.util.Log
import androidx.core.content.edit
import androidx.core.net.toUri
import com.ghostlock.app.BuildConfig
import com.ghostlock.app.BuildInfo
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.DebugSettings
import com.ghostlock.app.domain.model.ExternalProfileInfo
import com.ghostlock.app.domain.model.KernelSnapshot
import com.ghostlock.app.domain.model.LegacyProfileState
import com.ghostlock.app.domain.model.physSourceFromLines
import com.ghostlock.app.domain.model.physicalPairUsable
import com.ghostlock.app.domain.model.MeasuredFactInfo
import com.ghostlock.app.domain.model.MeasuredKernelInfo
import com.ghostlock.app.domain.model.MeasurementMergeRow
import com.ghostlock.app.domain.model.OffsetCandidate
import com.ghostlock.app.data.ota.OtaPayloadExtractor
import com.ghostlock.app.data.profile.PerDevicePhys
import com.ghostlock.app.domain.model.OffsetImportResult
import com.ghostlock.app.domain.model.ParseResult
import com.ghostlock.app.domain.model.PreflightFailure
import com.ghostlock.app.domain.model.PreflightResult
import com.ghostlock.app.domain.model.ProfileConfig
import com.ghostlock.app.domain.model.ProfileDiffRow
import com.ghostlock.app.domain.model.RunLogEntry
import com.ghostlock.app.domain.model.RootManagerCandidate
import com.ghostlock.app.domain.model.RunLogState
import com.ghostlock.app.domain.model.StrideCandidateOption
import com.ghostlock.app.domain.model.StrideProbe
import com.ghostlock.app.domain.model.UserProfileFile
import com.ghostlock.app.domain.model.VrKoMode
import com.ghostlock.app.domain.repository.GhostlockRepository
import com.ghostlock.app.domain.repository.ProfileConfigController
import com.ghostlock.app.shizuku.ShizukuExploitRunner
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.SecureRandom
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Android implementation of the domain repository. All platform I/O lives here. */
class AndroidGhostlockRepository(context: Context) : GhostlockRepository {
    private companion object {
        const val OffsetsFileName = "offsets.conf"
        const val LegacyOffsetsFileName = "offsets.json"
        const val FeasibleReportFileName = "offsets_feasible.json"
        const val OptionsReportFileName = "offsets_options.json"
        const val UserProfilesDirectoryName = "user_profiles"
        const val EditSessionPreferences = "ghostlock_edit_session"
        const val ExtractBinaryName = "libextract.so"
        const val NativeBinaryName = "libghostlock.so"

        /* Measured database and the root phase's /proc/slabinfo capture. */
        const val MeasuredDbFileName = "measured_profiles.conf"
        const val SlabinfoCaptureFileName = ".ghostlock_slabinfo"

        /* The probe runs up to ten leak rounds plus the spray setup. */
        const val ProbeTimeoutSeconds = 900L
        val AnsiEscape = Regex("\u001B\\[[0-9;]*m")
        const val PrefForceAttackTest = "force_attack_test"
        /* Second way: W1-only run followed by the DirtyFrag page-cache stage. */
        const val PrefSecondWay = "second_way"
        /** Tri-state vr.ko choices, stored as auto/on/off (legacy booleans are migrated). */
        const val PrefVrKoTagClear = "vr_ko_tag_clear"
        const val PrefVrKoSelinuxBlock = "vrko_selinux_block"

        /** Build identity the layer-disable notice was last shown for. */
        const val PrefLayerNoticeAck = "profile_layer_notice_ack"
        const val PrefDebugKernelLogEnabled = "debug_kernel_log_enabled"
        const val PrefDebugProfileOverrides = "debug_profile_overrides"
        /** Root-manager choice (package name); absent means Auto. */
        const val PrefManagerPackage = "manager_package"

        /* U01-S14: per-run KernelSU log name; the resolved path travels to
         * the native process via GHOSTLOCK_KSU_LOG. */
        fun ksuLogName(runStamp: Long) = "ghostlock-ksu-$runStamp.log"

        /* Every run's stdout/stderr is redirected here (export or not), so the
         * previous run can be inspected on the next start-up. */
        const val NativeLogFileName = ".ghostlock_native.log"

        /* Attack step status persisted by the app. The native process reports
         * each step on stdout and waits for an ACK on stdin; the app owns the
         * file so a kernel panic still leaves the last in_progress step for the
         * next launch to read. HOCON/JSON. */
        const val RunStateFileName = ".ghostlock_run_state.json"
        const val StatusMarker = "\u001eGLK_STATUS"
        const val StatusAck = "\u001eGLK_STATUS_ACK\n"
        const val StatusDisabled = "\u001eGLK_STATUS_DISABLED"

        /* Native `config::anchor_state_file`: home_dir + "/.ghostlock_anchor".
         * The direct path's home is filesDir; the Shizuku service's is
         * /data/local/tmp/ghostlock-app, outside the app sandbox. */
        const val AnchorStateFileName = ".ghostlock_anchor"

        /* A pre-flight manager choice is reused only this soon, and only while
         * the chosen binary still exists. */
        const val PreflightManagerMaxAgeMs = 15_000L
    }

    private val appContext = context.applicationContext
    private val filesDir: File = appContext.filesDir
    private val preferences get() =
        appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
    private val offsetsFile get() = File(filesDir, OffsetsFileName)
    private val builtinProfiles = BuiltinProfileCatalog(appContext)
    private val assetConfigLoader = AssetConfigLoader(appContext)
    /** Legacy app-data documents; read only by the one-time cleanup flow. */
    private val userProfileStore = UserProfileStore(
        directory = File(filesDir, UserProfilesDirectoryName),
        assetLoader = assetConfigLoader,
    )
    /** Ground-truth facts; written only from a completed run's root phase. */
    private val measuredProfiles = MeasuredProfileStore(File(filesDir, MeasuredDbFileName))
    private val externalProfileStore = AndroidExternalProfileStore(appContext)
    private val profileController = AndroidProfileConfigController(
        appContext,
        externalProfileStore,
        preferences,
    )
    private val cpuPairs = mutableListOf<CpuPair>()
    private val cpuPairLabels = mutableListOf<String>()
    private var selectedCpuPair = 0
    private var safeModeEnabled = false
    private var forceAttackTest = false
    private var secondWay = false
    private var vrKoTagClear = VrKoMode.AUTO
    private var vrKoSelinuxBlock = VrKoMode.AUTO
    private var shizukuEnabled = false
    /** True once the user flipped the toggle; only then does it override the
     * profile suggestion (PROFILE-SUGGEST-01). */
    private var shizukuPreferenceSet = false
    private val shizukuRunner = ShizukuExploitRunner(appContext)

    init {
        buildCpuPairs()
        restoreCpuPair()
        restoreShizukuPreference()
        restoreForceAttackTest()
        restoreSecondWay()
        restoreVrKoTagClear()
        restoreVrKoSelinuxBlock()
        dropLegacyOffsetsCache()
        migrateLegacyOffsetsStore()
    }

    /** The old JSON offsets cache is not compatible and is discarded. */
    private fun dropLegacyOffsetsCache() {
        runCatching { File(filesDir, LegacyOffsetsFileName).delete() }
    }

    /**
     * Old builds kept imported offsets and parameter overrides in one HOCON
     * file. Split it: overrides move to preferences, the remaining entries
     * become verbatim user documents, then the legacy file is dropped.
     */
    private fun migrateLegacyOffsetsStore() {
        if (!offsetsFile.isFile) return
        runCatching {
            val entries = parseEntries(offsetsFile.readText()) ?: return@runCatching
            for (raw in entries) {
                val entry = raw.asValueMap() ?: continue
                val release = (entry["release"] as? String).orEmpty()
                if (release.isEmpty()) continue
                val overrides = valueMapOf()
                (entry.remove("execution") as? Map<*, *>)?.let { overrides["execution"] = it }
                (entry.remove("route") as? Map<*, *>)?.let { overrides["route"] = it }
                (entry.remove("fallback") as? Map<*, *>)?.let { overrides["fallback"] = it }
                if (overrides.isNotEmpty()) mergeLegacyOverrides(release, overrides)
                if (entry.size > 1) {
                    userProfileStore.save("$release.conf", HoconSupport.render(entry))
                }
            }
            offsetsFile.delete()
        }.onFailure {
            android.util.Log.e("GhostLock", "legacy offsets migration failed", it)
        }
    }

    private fun mergeLegacyOverrides(release: String, overrides: ValueMap) {
        val raw = preferences.getString(PrefDebugProfileOverrides, null)
        val all = runCatching { HoconSupport.parseValue(raw ?: "") }
            .getOrNull().asValueMap() ?: valueMapOf()
        deepMergeValues(all.mutableChild(release), overrides)
        preferences.edit {
            putString(PrefDebugProfileOverrides, HoconSupport.render(all))
            /* The migration is this build writing them, so they apply (§B.7);
             * leaving them unstamped would silently disable a user's own
             * offsets on the very update that carried them over. */
            putString(AndroidProfileConfigController.PrefOverridesBuildSha, BuildConfig.BUILD_IDENTITY)
        }
    }

    override suspend fun snapshot(): KernelSnapshot {
        val release = System.getProperty("os.version", "unknown").orEmpty()
        /* PROFILE-SUGGEST-01: recommend_shizuku is a suggestion. It seeds the
         * toggle until the user makes an explicit choice, which then overrides
         * it in both directions. */
        val recommendShizuku = release in builtinProfiles.recommendShizuku ||
            importedOffsetsRecommendShizuku(release)
        val shizukuActive = if (shizukuPreferenceSet) shizukuEnabled else recommendShizuku
        val socName = resolveSocName()
        val kernelKnown = isKernelSupported()
        /* A known kernel is not enough on MediaTek: the compiled pair there is
         * wrong on most of the fleet, so the resolved profile must carry the
         * bootloader-derived pair (from the device map or the parse flow). */
        val profile = if (kernelKnown) {
            runCatching { profileController.load(release, currentPairOrZero()) }.getOrNull()
        } else {
            null
        }
        val pairKnown = profile?.physLoad != null && profile.physOffset != null
        val usable = kernelKnown && physicalPairUsable(socName, pairKnown)
        return KernelSnapshot(
            deviceName = resolveDeviceName(),
            kernelRelease = release,
            socName = socName,
            kernelSupported = usable,
            devicePairMissing = kernelKnown && !usable,
            cpuPairs = cpuPairs.toList(),
            cpuPairLabels = cpuPairLabels.toList(),
            selectedCpuPair = selectedCpuPair,
            safeModeEnabled = safeModeEnabled,
            forceAttackTest = forceAttackTest,
            secondWay = secondWay,
            vrKoTagClear = vrKoTagClear,
            vrKoSelinuxBlock = vrKoSelinuxBlock,
            recommendShizuku = recommendShizuku,
            shizukuEnabled = shizukuActive,
            shizukuStatus = if (shizukuActive) shizukuRunner.status()
            else com.ghostlock.app.domain.model.ShizukuStatus.NOT_REQUIRED,
        )
    }

    override fun selectCpuPair(index: Int) {
        if (index !in cpuPairs.indices) return
        selectedCpuPair = index
        appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE).edit {
                putString("cpu_pair", cpuPairs[index].toString())
            }
    }

    override fun setSafeModeEnabled(enabled: Boolean) {
        safeModeEnabled = enabled
    }

    override fun setForceAttackTest(enabled: Boolean) {
        forceAttackTest = enabled
        preferences.edit { putBoolean(PrefForceAttackTest, enabled) }
    }

    override fun setSecondWay(enabled: Boolean) {
        secondWay = enabled
        preferences.edit { putBoolean(PrefSecondWay, enabled) }
    }

    override fun setVrKoTagClear(mode: VrKoMode) {
        vrKoTagClear = mode
        preferences.edit { putString(PrefVrKoTagClear, mode.wire) }
    }

    override fun setVrKoSelinuxBlock(mode: VrKoMode) {
        vrKoSelinuxBlock = mode
        preferences.edit { putString(PrefVrKoSelinuxBlock, mode.wire) }
    }

    override fun layerNoticeAcknowledged(): String? =
        preferences.getString(PrefLayerNoticeAck, null)?.takeIf { it.isNotEmpty() }

    override fun acknowledgeLayerNotice(build: String) {
        preferences.edit { putString(PrefLayerNoticeAck, build) }
    }

    override fun setShizukuEnabled(enabled: Boolean) {
        shizukuEnabled = enabled
        shizukuPreferenceSet = true
        appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
            .edit {
                putBoolean("shizuku_enabled", enabled)
                putBoolean("shizuku_explicit", true)
            }
        if (enabled) shizukuRunner.requestPermission()
    }

    override suspend fun managerCandidates(): List<RootManagerCandidate> = withContext(Dispatchers.IO) {
        ManagerScanner.scan(appContext).map {
            RootManagerCandidate(
                packageName = it.packageName,
                label = it.label,
                path = it.path,
                builtin = it.builtin,
                suitable = it.suitable,
                verdict = it.verdict,
            )
        }
    }

    override fun selectedManagerPackage(): String? =
        preferences.getString(PrefManagerPackage, null)?.takeIf { it.isNotBlank() }

    override fun setSelectedManagerPackage(packageName: String?) {
        preferences.edit {
            if (packageName.isNullOrBlank()) remove(PrefManagerPackage)
            else putString(PrefManagerPackage, packageName)
        }
    }

    override fun profileController(): ProfileConfigController = profileController

    override suspend fun measurements(): List<MeasuredKernelInfo> = withContext(Dispatchers.IO) {
        measuredProfiles.kernels().map { kernel ->
            MeasuredKernelInfo(
                release = kernel.release,
                updatedAt = kernel.updatedAt,
                facts = kernel.facts.map { fact ->
                    MeasuredFactInfo(
                        key = fact.key,
                        value = fact.value,
                        source = fact.source,
                        evidence = fact.evidence,
                        measuredAt = fact.measuredAt,
                    )
                },
            )
        }
    }

    /* debug-ui: preferences for the hidden debug screen. */
    override suspend fun debugSettings(): DebugSettings = DebugSettings(
        kernelLogEnabled = preferences.getBoolean(PrefDebugKernelLogEnabled, true),
    )

    override fun setDebugKernelLogEnabled(enabled: Boolean) {
        preferences.edit { putBoolean(PrefDebugKernelLogEnabled, enabled) }
    }

    override suspend fun listRunLogs(): List<RunLogEntry> = withContext(Dispatchers.IO) {
        RunLogStore.list(appContext)
    }

    override suspend fun exportRunLog(stamp: String, documentUri: String): Boolean =
        withContext(Dispatchers.IO) {
            RunLogStore.exportZip(appContext, stamp, documentUri.toUri())
        }

    override suspend fun clearRunLogs() = withContext(Dispatchers.IO) {
        RunLogStore.clear(appContext)
    }

    override suspend fun markInterruptedRunLogs(): Int = withContext(Dispatchers.IO) {
        RunLogStore.markInterrupted(appContext)
    }


    /* Profile configuration now lives in AndroidProfileConfigController: the
     * repository only wires it and forwards the native document. */

    override suspend fun parseSource(
        input: String,
        xblPath: String?,
        uefiPath: String?,
        vendorBootPath: String?,
        dtboPath: String?,
        overwrite: Boolean,
        route: String?,
        pipeline: String?,
        onLog: (String) -> Unit,
    ): ParseResult {
        val parsedFile = File(filesDir, "offsets_parse.tmp")
        val feasibleFile = File(filesDir, FeasibleReportFileName)
        val optionsFile = File(filesDir, OptionsReportFileName)
        var tempBootFile: File? = null
        var tempXblFile: File? = null
        return try {
            val binary = File(appContext.applicationInfo.nativeLibraryDir, ExtractBinaryName)
            if (!binary.isFile) return ParseResult.Failed(1, "missing native binary: ${binary.absolutePath}")

            /* Remote OTA URLs are resolved by the pure-Kotlin extractor so the
             * Android binary ships without the http stack; local files keep
             * going straight to the Rust extractor. */
            val isRemoteUrl = input.startsWith("http://", ignoreCase = true) ||
                input.startsWith("https://", ignoreCase = true)
            val (effectiveInput, effectiveXblPath) = if (isRemoteUrl) {
                val extracted = OtaPayloadExtractor.extractPartitions(
                    url = input,
                    workDir = filesDir,
                    onLog = onLog,
                )
                tempBootFile = extracted.bootFile
                tempXblFile = extracted.xblConfigFile
                Pair(extracted.bootFile.absolutePath, extracted.xblConfigFile?.absolutePath ?: xblPath)
            } else {
                Pair(input, xblPath)
            }

            parsedFile.delete()
            feasibleFile.delete()
            optionsFile.delete()
            /* The profile is generated for this phone. The v2 map key is the
             * first non-generic identity (Build.DEVICE, then the vendor, then
             * the boot image). When every identity is a mainline/vendor
             * placeholder there is no unique codename: write the legacy v1
             * all-device form instead of inventing a device key. */
            val deviceKey = DeviceIdentity.uniqueProfileKey()
            val deviceCandidates =
                DeviceIdentity.candidates(Build.DEVICE, DeviceIdentity.aliases())
            if (deviceKey == null) {
                onLog(
                    "identity: all candidates are generic " +
                        "(${deviceCandidates.joinToString(", ")}); " +
                        "writing a v1 all-device profile",
                )
            }
            val args = buildList {
                add(effectiveInput)
                if (effectiveXblPath != null) {
                    add("--xbl-config")
                    add(effectiveXblPath)
                }
                if (uefiPath != null) {
                    add("--uefi")
                    add(uefiPath)
                }
                if (vendorBootPath != null) {
                    add("--vendor-boot")
                    add(vendorBootPath)
                }
                if (dtboPath != null) {
                    add("--dtbo")
                    add(dtboPath)
                }
                if (deviceKey != null) {
                    add("--device")
                    add(deviceKey)
                }
                /* --format conf: the extractor output is already the flattened
                 * profile (no includes, credential template inlined), so the
                 * stored document needs no legacy conversion. */
                /* --anchor: the diting 5.10 line gets its lock-anchor triple
                 * derived from the image; other families warn and ignore it. */
                /* --feasible-out: written before an ambiguity exit, so the app
                 * can offer the routes the image actually supports. */
                addAll(
                    listOf(
                        "--format",
                        "conf",
                        "--anchor",
                        "--out",
                        parsedFile.absolutePath,
                        "--work-dir",
                        filesDir.absolutePath,
                        "--feasible-out",
                        feasibleFile.absolutePath,
                        "--options-out",
                        optionsFile.absolutePath,
                    ),
                )
                if (route != null) {
                    add("--route")
                    add(route)
                }
                if (pipeline != null) {
                    add("--pipeline")
                    add(pipeline)
                }
            }
            val captured = mutableListOf<String>()
            /* One generation log per extractor pass: the stderr decision lines,
             * the verdict JSON and a meta summary land in the app's crash-safe
             * run store and are exportable from the log screen. Exit 7 is a
             * completed pass (the choice moves to the user), not a failure. */
            val code = withDebugAttackLog("parse", onLog, completedCodes = setOf(0, 7)) {
                    archivedLog, _, _, writeSidecar ->
                val tee: (String) -> Unit = { line ->
                    captured += line
                    archivedLog(line)
                }
                tee("<k> extract: $effectiveInput")
                val exit = runProcess(
                    ProcessBuilder(listOf(binary.absolutePath) + args).directory(filesDir).redirectErrorStream(true).apply {
                            environment()["GHOSTLOCK_HOME"] = filesDir.absolutePath
                            environment()["TMPDIR"] = filesDir.absolutePath
                            environment()["HOME"] = filesDir.absolutePath
                        },
                    onLog = tee,
                    timeoutSeconds = 1800,
                )
                tee("<k> extract exit code=$exit")
                val reportText = feasibleFile.takeIf { it.isFile }?.readText()
                val report = reportText?.let(FeasibleReport::parse)
                if (reportText != null) {
                    writeSidecar("generation.json", reportText.toByteArray(StandardCharsets.UTF_8))
                }
                val optionsText = optionsFile.takeIf { it.isFile }?.readText()
                if (optionsText != null) {
                    writeSidecar("options.json", optionsText.toByteArray(StandardCharsets.UTF_8))
                }
                writeSidecar(
                    "generation.meta",
                    generationMeta(
                        input = input,
                        effectiveInput = effectiveInput,
                        requestedRoute = route,
                        exit = exit,
                        report = report,
                        captured = captured,
                    ).toByteArray(StandardCharsets.UTF_8),
                )
                exit
            }
            val report = feasibleFile.takeIf { it.isFile }?.readText()?.let(FeasibleReport::parse)
            val options = optionsFile.takeIf { it.isFile }?.readText()?.let(OptionSuperset::parse)
            if (code == 7) {
                val routes = report?.routes.orEmpty()
                if (routes.none { it.verdict == FeasibleReport.VerdictFeasible }) {
                    return ParseResult.Failed(7, "route ambiguity without a feasible-route report")
                }
                return ParseResult.Ambiguous(routes, options)
            }
            if (code != 0 || !parsedFile.isFile) return ParseResult.Failed(code)
            val document = parsedFile.readText()
            val fresh = parseEntries(document) ?: return ParseResult.Failed(code, "invalid extractor output")
            /* The document is returned, never stored: the app keeps no profile
             * documents (measured-db-plan §1). The caller probes it in memory,
             * applies the chosen stride, and an export is the only way it can
             * become selectable. */
            val filtered = fresh.mapNotNull { it.asValueMap() }
                .filter { (it["release"] as? String).orEmpty().isNotEmpty() }
            if (filtered.isEmpty()) return ParseResult.AlreadyPresent
            val releases = freshReleases(filtered)
            /* A v2 document carries the pair as a per-device map; the presence
             * checks must see this device's entry, not `getLongAt` on a map. */
            val resolved = filtered.map { resolvedForDevice(it, deviceCandidates) }
            val missing = missingSidecarFields(resolved)
            val name = parsedDocumentName(releases)
            ParseResult.Parsed(
                releases = releases,
                missing = missing,
                documentName = name,
                route = report?.chosen ?: route,
                anchor = anchorLine(captured),
                hasAnchor = document.contains("lock_anchor_image"),
                physSource = physSourceFromLines(captured),
                physLoadPresent = resolved.any { it.getLongAt("kernel_phys_load") != null },
                physOffsetPresent = resolved.any { it.getLongAt("kernel_phys_offset") != null },
                documentText = document,
                options = options,
            )
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            ParseResult.Failed(1, error.message)
        } finally {
            parsedFile.delete()
            feasibleFile.delete()
            optionsFile.delete()
            tempBootFile?.delete()
            tempXblFile?.delete()
        }
    }

    override suspend fun probeStride(
        release: String,
        documentText: String,
        pair: CpuPair,
        onLog: (String) -> Unit,
    ): StrideProbe? {
        /* The probe frame is the generated document, built in memory; nothing
         * is selected or stored (measured-db-plan §1). */
        val blob = profileController.nativeDocumentFor(documentText, release, pair)
            ?: return null
        val binary = File(appContext.applicationInfo.nativeLibraryDir, NativeBinaryName)
        if (!binary.isFile) return null
        val lines = mutableListOf<String>()
        val exit = runProcess(
            /* --enable-status-record selects the length-prefixed stdin frame
             * (`read_glk1_frame_stdin`); without it the native reads the bare
             * document and blocks on the app's length prefix. */
            ProcessBuilder(
                listOf(
                    binary.absolutePath,
                    "--ghostlock-app-call",
                    "--enable-status-record",
                    "--probe-stride",
                ),
            )
                .directory(filesDir)
                .redirectErrorStream(true)
                .apply {
                    environment()["GHOSTLOCK_HOME"] = filesDir.absolutePath
                    environment()["TMPDIR"] = filesDir.absolutePath
                    environment()["HOME"] = filesDir.absolutePath
                },
            onLog = { raw ->
                val line = raw.replace(AnsiEscape, "")
                lines += line
                onLog(line)
            },
            timeoutSeconds = ProbeTimeoutSeconds,
            /* captureOutput=true is what runs the reader that calls onLog; the
             * run path uses false because it redirects stdout to a file and
             * tails it instead. */
            captureOutput = true,
            stdin = blob,
            frameStdin = true,
        )
        onLog("stride: probe exit=$exit captured=${lines.size}")
        if (exit != 0) return null
        val probe = parseStrideProbe(lines)
        if (probe == null) onLog("stride: no candidate table")
        return probe
    }

    override fun applyLockSourceToDocument(
        documentText: String,
        keepAnchor: Boolean,
    ): String? = if (keepAnchor) documentText else stripLockAnchor(documentText)

    override fun applyStrideToDocument(
        documentText: String,
        release: String,
        stride: Int?,
    ): String? {
        val entries = ProfileDocumentParser.entries(documentText) ?: return null
        val targets = entries.filter { it["release"] == release }
        if (targets.isEmpty()) return null
        for (entry in targets) {
            val snitch = entry.mutableChild("kernelsnitch")
            if (stride != null) snitch["mm_struct_sz"] = stride.toLong() else snitch.remove("mm_struct_sz")
            if (snitch.isEmpty()) entry.remove("kernelsnitch")
        }
        val document = if (entries.size == 1) entries.first() else ValueList().apply { addAll(entries) }
        return HoconSupport.render(document)
    }

    private fun parseStrideProbe(lines: List<String>): StrideProbe? {
        val candidates = mutableListOf<StrideCandidateOption>()
        var rounds = 0
        var samples = 0
        var gcd = 0L
        var decided = false
        val candidateLine = Regex(
            """\[stride\] candidate value=(\d+) votes=(\d+)/(\d+) objects=(\d+)""",
        )
        val summaryLine = Regex(
            """\[stride\] summary rounds=(\d+) samples=(\d+) gcd=0x([0-9a-fA-F]+) """ +
                """candidates=\d+ decided=(\d+)""",
        )
        for (line in lines) {
            candidateLine.find(line)?.let { match ->
                candidates += StrideCandidateOption(
                    value = match.groupValues[1].toInt(),
                    votes = match.groupValues[2].toInt(),
                    samples = match.groupValues[3].toInt(),
                    objectsPerSlab = match.groupValues[4].toInt(),
                )
            }
            summaryLine.find(line)?.let { match ->
                rounds = match.groupValues[1].toInt()
                samples = match.groupValues[2].toInt()
                gcd = match.groupValues[3].toLong(16)
                decided = match.groupValues[4] == "1"
            }
        }
        if (candidates.isEmpty()) return null
        return StrideProbe(candidates, rounds, samples, gcd, decided)
    }

    /** The extractor's first anchor decision line, or null when none ran. */
    private fun anchorLine(lines: List<String>): String? = lines.firstOrNull {
        it.contains("lock anchor") && (it.startsWith("info:") || it.startsWith("warning:"))
    }

    /**
     * The generation record design 10 asks for: what the image is, which series
     * tier filled the shared fields, every route verdict, the route and why it
     * was chosen, the anchor verdict and how the pass ended. The raw stderr
     * (including every heuristic warning) is the log file itself; the lines
     * about heuristic values are copied here so the meta alone is enough to
     * see that a profile is not fully image-derived.
     */
    private fun generationMeta(
        input: String,
        effectiveInput: String,
        requestedRoute: String?,
        exit: Int,
        report: FeasibleReport?,
        captured: List<String>,
    ): String = buildString {
        val state = when (exit) {
            0 -> "completed"
            7 -> "ambiguous"
            3 -> "infeasible"
            -1 -> "timeout"
            else -> "failed"
        }
        appendLine("state=$state")
        appendLine("exit=$exit")
        appendLine("release=${report?.release.orEmpty()}")
        appendLine("input=$input")
        appendLine("input_sha256=${sha256Of(File(effectiveInput)) ?: "unavailable"}")
        appendLine("series=${captured.firstOrNull { it.contains("series ") }?.substringAfter("series ")?.trim() ?: "unknown"}")
        appendLine("route=${report?.chosen ?: requestedRoute.orEmpty()}")
        /* The extractor's own selection line distinguishes a derived choice
         * from the zero-feasible frame-rule fallback; the report alone cannot. */
        val selection = captured.firstOrNull {
            it.startsWith("info: route ") && it.contains(" selected (")
        }
        appendLine(
            "route_basis=" + when {
                requestedRoute != null -> "forced"
                selection?.contains("(Fallback)") == true -> "fallback"
                selection != null -> "derived"
                exit == 7 -> "ambiguous"
                else -> "none"
            },
        )
        appendLine("route_selection=${selection ?: "none"}")
        appendLine("feasible=${report?.feasible.orEmpty().joinToString(",") { it.route }}")
        report?.routes.orEmpty().forEach { verdict ->
            val numbers = if (verdict.numbers.isEmpty()) {
                ""
            } else {
                "; " + verdict.numbers.entries.joinToString(", ") { (key, value) -> "$key=$value" }
            }
            appendLine("verdict.${verdict.route}=${verdict.verdict}: ${verdict.reason}$numbers")
        }
        appendLine("anchor=${anchorLine(captured) ?: "none"}")
        val heuristics = captured.filter { it.contains("heuristic", ignoreCase = true) }
        appendLine("heuristic_count=${heuristics.size}")
        heuristics.forEachIndexed { index, line -> appendLine("heuristic.$index=$line") }
        val fieldSources = captured.filter { it.contains("field_source ") }
        appendLine("field_source_count=${fieldSources.size}")
        fieldSources.forEachIndexed { index, line -> appendLine("field_source.$index=$line") }
    }

    private fun sha256Of(file: File): String? = runCatching {
        if (!file.isFile) return@runCatching null
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        file.inputStream().use { stream ->
            val buffer = ByteArray(1 shl 20)
            while (true) {
                val read = stream.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }.getOrNull()

    /* --- run-start pre-flight (class 1 of the 2026-11-07 exit audit) ------ */

    /** Candidate the pre-flight selected; consumed once by [stageKsud]. */
    @Volatile
    private var preflightManager: Pair<Long, ManagerScanner.Candidate>? = null

    override suspend fun preflight(pair: CpuPair, useShizuku: Boolean): PreflightResult =
        withContext(Dispatchers.IO) {
            /* The anchor state file lives under GHOSTLOCK_HOME, and the CPU pin
             * runs in the native's process: for the Shizuku path that home is
             * /data/local/tmp/ghostlock-app and the process is the shell's, so
             * neither judgement is ours to make here. Both are deferred to the
             * service (or to the class-2 pattern). */
            if (!useShizuku) {
                anchorFailure(pair)?.let { return@withContext PreflightResult.Blocked(it) }
                if (!CpuPairProbe.usable(pair)) {
                    return@withContext PreflightResult.Blocked(
                        PreflightFailure.CPU_PAIR_UNAVAILABLE,
                    )
                }
            }
            /* A scan that throws is not proof of "no manager": fail open and
             * let stageKsud report it (the class-2 pattern covers that). */
            val candidates = runCatching { ManagerScanner.scan(appContext) }.getOrNull()
            if (candidates != null) {
                val chosen = ManagerScanner.resolve(candidates, selectedManagerPackage())
                    ?: return@withContext PreflightResult.Blocked(
                        PreflightFailure.NO_ROOT_MANAGER,
                    )
                preflightManager = SystemClock.elapsedRealtime() to chosen
            }
            PreflightResult.Passed
        }

    /**
     * Mirror of `lock_anchor.cpp`'s boot-scoped decision. Returns the blocking
     * failure, or null when a slot can be handed out (or there is no anchor to
     * check here).
     */
    private suspend fun anchorFailure(pair: CpuPair): PreflightFailure? {
        val config = runCatching { profileController.load(deviceRelease(), pair) }.getOrNull()
            ?: return null
        val anchor = config.anchor ?: return null
        val bytes = anchor.bytes ?: AnchorSlotState.DefaultBytes
        val stride = anchor.stride ?: AnchorSlotState.DefaultStride
        /* A contradictory geometry is the validator's job (class 1 P2); do not
         * guess a grid here. */
        if (bytes <= 0L || stride < AnchorSlotState.MinStride || bytes % stride != 0L) return null
        val slots = bytes / stride
        /* read_boot_id() falls back to "unknown-boot" natively; mirror it so the
         * gate and the native cannot disagree. */
        val bootId = runCatching {
            File("/proc/sys/kernel/random/boot_id").readText().trim()
        }.getOrNull().orEmpty().ifEmpty { "unknown-boot" }
        val state = runCatching { File(filesDir, AnchorStateFileName).readText() }.getOrNull()
        val trusted = InstallClock.installPredatesBoot(appContext)
        return when (AnchorSlotState.evaluate(bootId, state, slots, trusted)) {
            AnchorSlotState.Verdict.OK -> null
            AnchorSlotState.Verdict.MISSING_UNTRUSTED -> PreflightFailure.ANCHOR_STATE_UNCONFIRMED
            AnchorSlotState.Verdict.BUDGET_SPENT -> PreflightFailure.ANCHOR_BUDGET_SPENT
            AnchorSlotState.Verdict.GRID_MISMATCH -> PreflightFailure.ANCHOR_GRID_MISMATCH
        }
    }

    override suspend fun runExploit(pair: CpuPair, onLog: (String) -> Unit): Int =
        withDebugAttackLog("direct", onLog, measure = true) { archivedLog, debugDir, runDir, writeSidecar ->
            runExploitBinary(pair, "libghostlock.so", archivedLog, debugDir, runDir, writeSidecar)
        }

    override suspend fun probeDirtyfrag(): String = withContext(Dispatchers.IO) {
        val release = System.getProperty("os.version", "").orEmpty()
        val result = DirtyfragProbe.run(appContext, filesDir)
        val clear = result.outcome == DirtyfragProbe.Outcome.Pass ||
            result.outcome == DirtyfragProbe.Outcome.PrimitiveFailed
        val recorded = clear && measuredProfiles.recordDirtyfragProbe(
            release,
            result.outcome,
            Build.FINGERPRINT,
            result.evidence,
        )
        val line = "probe=${result.outcome} reason=${result.reason} " +
            "evidence=${result.evidence} db=$recorded"
        Log.i(DirtyfragProbe.Tag, line)
        line
    }

    override suspend fun preflightDirtyfrag(): String = withContext(Dispatchers.IO) {
        val preflight = DirtyfragPlan.preflight(appContext, File("/system/lib64/libc++.so"))
        val line = "preflight=${if (preflight.feasible) "Feasible" else "Rejected"} " +
            "reasons=${preflight.reasons.joinToString("; ")} details=${preflight.details}"
        Log.i(DirtyfragProbe.Tag, line)
        line
    }

    override suspend fun runExploitWithShizuku(pair: CpuPair, onLog: (String) -> Unit): Int {
        /* The Shizuku service runs as uid 2000 and cannot write the app's run
         * folder; the module sidecar is a direct-entry diagnostic. Its AIDL also
         * carries no vr.ko mode, so that entry runs Auto. */
        return withDebugAttackLog("shizuku", onLog, measure = true) { archivedLog, debugDir, _, writeSidecar ->
            archivedLog("<s> resolving profile")
            val release = System.getProperty("os.version", "").orEmpty()
            val config = profileController.load(release, pair)
            val profileBlob = profileController.nativeDocument(config)
            archivedLog(
                "<s> profile resolved hasProfile=${config.hasProfile} " +
                    "blob=${profileBlob?.size ?: 0} invalid=${config.invalidPaths.size}",
            )
            logProfileLayers(archivedLog, config)
            when {
                !config.hasProfile || profileBlob == null -> {
                    archivedLog("<s> error: profile is unavailable for $release")
                    1
                }

                config.invalidPaths.isNotEmpty() -> {
                    archivedLog(
                        "<s> error: profile has ${config.invalidPaths.size} invalid field(s): " +
                            config.invalidPaths.take(6).joinToString(),
                    )
                    1
                }

                else -> {
                    val pipeline = config.pipeline?.lowercase() ?: "ghostlock"
                    if (config.pipeline == null) {
                        archivedLog(
                            "<s> pipeline=ghostlock (legacy default; profile has no " +
                                "pipeline key)",
                        )
                    }
                    if (pipeline != "ghostlock") {
                        archivedLog(
                            "<s> error: profile pipeline=$pipeline; the Shizuku path " +
                                "does not carry the pipeline selection yet (use the direct path)",
                        )
                        return@withDebugAttackLog 1
                    }
                    /* Mirror the UserService patch so the dumped blob is the
                     * effective one native will actually receive. */
                    val runtimeBlob = if (safeModeEnabled) {
                        NativeProfileDocument.patchSafeMode(profileBlob) ?: profileBlob
                    } else {
                        profileBlob
                    }
                    logProfileDigest(archivedLog, runtimeBlob)
                    dumpRuntimeProfile(archivedLog, writeSidecar, release, pair, runtimeBlob)
                    archivedLog("<b> starting UserService")
                    resetRunState()
                    shizukuRunner.run(
                        pair, safeModeEnabled, forceAttackTest, profileBlob, debugDir,
                        selectedManagerPackage(), archivedLog,
                    ) { step, status ->
                        if (status == "disabled") clearRunState() else applyRunStatus(step, status)
                    }
                }
            }
        }
    }

    /* --- attack step status ------------------------------------------------
     * The native process reports each step over stdout and waits for an ACK on
     * stdin. The app persists the status here; a kernel panic leaves the last
     * in_progress step on disk for the next launch to read. */

    private val runStateLock = Any()
    private var runSteps: LinkedHashMap<String, String> = LinkedHashMap()

    private fun persistRunStateLocked() {
        val json = RunStateCodec.encode(runSteps, System.currentTimeMillis())
        runCatching {
            FileOutputStream(File(filesDir, RunStateFileName)).use { out ->
                out.write(json.toByteArray(StandardCharsets.UTF_8))
                out.flush()
                out.fd.sync()
            }
        }
    }

    private fun resetRunState() = synchronized(runStateLock) {
        runSteps = LinkedHashMap<String, String>().apply {
            RunStateCodec.Steps.forEach { put(it, RunStateCodec.NotStarted) }
        }
        persistRunStateLocked()
    }

    private fun applyRunStatus(step: String, status: String) = synchronized(runStateLock) {
        if (!runSteps.containsKey(step)) return@synchronized
        runSteps[step] = status
        persistRunStateLocked()
    }

    private fun clearRunState() = runCatching { File(filesDir, RunStateFileName).delete() }

    /** Handles one stdout line; true when it was a status event, not a log line. */
    private fun handleStatusLine(line: String, process: AtomicReference<Process?>): Boolean {
        if (!line.startsWith(StatusMarker)) return false
        if (line.contains(StatusDisabled)) {
            clearRunState()
            return true
        }
        val parts = line.removePrefix(StatusMarker).trim().split(' ')
        if (parts.size < 2) return true
        applyRunStatus(parts[0], parts[1])
        runCatching {
            process.get()?.outputStream?.apply {
                write(StatusAck.toByteArray(StandardCharsets.UTF_8))
                flush()
            }
        }
        return true
    }

    override suspend fun lastRunStuckStep(): String? = withContext(Dispatchers.IO) {
        runCatching {
            val file = File(filesDir, RunStateFileName)
            if (!file.isFile) return@runCatching null
            RunStateCodec.parseStuckStep(file.readText())
        }.getOrNull()
    }

    private suspend fun withDebugAttackLog(
        entry: String,
        onLog: (String) -> Unit,
        /** Exit codes that mean the pass ended cleanly for its kind (7 is the
         * ambiguity hand-off, not a failure). */
        completedCodes: Set<Int> = setOf(0),
        /**
         * Attack runs record the measured database. Parsing does not: its
         * exit codes are not a chain completion, and it has no root phase.
         */
        measure: Boolean = false,
        run: suspend ((String) -> Unit, String?, String?, (String, ByteArray) -> Boolean) -> Int,
    ): Int {
        val settings = debugSettings()
        /* Deleted before the run, so a capture present afterwards proves this
         * run's root phase wrote it, not a previous boot's. */
        if (measure) runCatching { File(filesDir, SlabinfoCaptureFileName).delete() }
        /* Unconditional: a run with no log is a run nobody can report, and the
         * user who most needs one is the one whose device just died. */
        val archive = DebugAttackLog.open(appContext, entry)
        if (archive == null) {
            onLog("<k> warning: cannot create the run log")
            return run(onLog, null, null) { _, _ -> false }
        }
        /* Every archived line carries a run-relative timestamp. The native's
         * own `[T+ms]` clock starts at the native process; the app-owned phases
         * (ksud staging, profile load, the DirtyFrag stage, the root-script
         * tailer) need the same run-relative scale or the full chain cannot be
         * measured. The UI copy stays unprefixed. */
        val runStartMs = SystemClock.elapsedRealtime()
        val archivedLog: (String) -> Unit = { line ->
            val elapsed = SystemClock.elapsedRealtime() - runStartMs
            runCatching { archive.append("[A+${elapsed}ms] $line") }
            onLog(line)
        }
        val writeSidecar: (String, ByteArray) -> Boolean = { name, bytes ->
            runCatching { archive.writeSidecar(name, bytes) }.getOrDefault(false)
        }
        return try {
            /* First line of every archived run log: which app build produced it. */
            archivedLog(
                "<k> GhostLock ${BuildConfig.VERSION_NAME}+${BuildConfig.VERSION_CODE} " +
                    "build ${BuildInfo.BUILD_TIME_LABEL}",
            )
            archivedLog(
                "<k> run log: ${archive.displayName} (retained on the device; " +
                    "export it from the log screen)",
            )
            archivedLog("<k> debug dump dir: ${archive.folderFile.absolutePath}")
            val code = run(
                archivedLog,
                if (settings.kernelLogEnabled) archive.folderFile.absolutePath else null,
                archive.folderFile.absolutePath,
                writeSidecar,
            )
            if (measure && code in completedCodes) {
                runCatching { ingestMeasuredFacts(writeSidecar, archivedLog) }
            }
            /* Recorded before the descriptor closes: a run that ends without a
             * terminal state reads as interrupted at the next start. */
            archive.finish(if (code in completedCodes) RunLogState.COMPLETED else RunLogState.FAILED)
            code
        } finally {
            runCatching { archive.close() }
        }
    }

    /**
     * Records the root phase's `/proc/slabinfo` measurement after a completed
     * run. The capture is the only root-written measurement text, so it is also
     * copied into the run folder as evidence. A capture that does not parse is
     * logged and dropped — the database only takes facts it can name.
     */
    private fun ingestMeasuredFacts(
        writeSidecar: (String, ByteArray) -> Boolean,
        log: (String) -> Unit,
    ) {
        val capture = File(filesDir, SlabinfoCaptureFileName)
        if (!capture.isFile) {
            log("<k> measured: no root slabinfo capture")
            return
        }
        val raw = runCatching { capture.readText(StandardCharsets.UTF_8) }.getOrNull()
        if (raw.isNullOrEmpty()) return
        val release = System.getProperty("os.version", "").orEmpty()
        val fact = MeasuredProfileStore.parseSlabinfo(release, raw)
        if (fact == null) {
            log("<k> measured: slabinfo capture did not parse for $release")
            return
        }
        val recorded = measuredProfiles.record(release, fact)
        if (recorded) {
            writeSidecar("slabinfo-mm_struct.txt", raw.toByteArray(StandardCharsets.UTF_8))
        }
        log(
            if (recorded) {
                "<k> measured: ${fact.key}=${fact.value} recorded (${fact.source})"
            } else {
                "<k> warning: measured database refused the write"
            },
        )
    }

    /**
     * States which profile layers this run used and which were skipped, and why
     * (PORT-PLAN Phase 8 §C.10-11). A skipped layer is the difference between
     * "the port is broken" and "what you imported is not being applied", which
     * is exactly the distinction a log has to make from someone else's phone.
     */
    private fun logProfileLayers(log: (String) -> Unit, config: ProfileConfig) {
        val layers = config.layers ?: return
        log("<k> profile layers: ${layers.describe()}")
        if (layers.overridesPresent && !layers.overridesApplied) {
            log(
                "<k> profile: stored overrides are present but disabled " +
                    "(written by build ${layers.overridesBuild ?: "unknown"}); " +
                    "re-save them in Parameters to re-enable",
            )
        }
        if (layers.imported != null && !layers.importedApplied) {
            log(
                "<k> profile: imported document ${layers.imported} is loaded but not " +
                    "applied; this kernel has a bundled profile",
            )
        }
        if (layers.uncarriedKeys.isNotEmpty()) {
            log(
                "<k> warning: profile carries keys no wire section declares: " +
                    layers.uncarriedKeys.joinToString(),
            )
        }
    }

    /**
     * The digest the app just put in the blob native receives (§E.18); native
     * recomputes and logs its own, and refuses the run on a mismatch.
     */
    private fun logProfileDigest(log: (String) -> Unit, blob: ByteArray) {
        val digest = NativeProfileDocument.digestOf(blob)
        log(
            if (digest == null) {
                "<k> profile digest: absent"
            } else {
                "<k> profile digest=0x%016x".format(digest.toLong())
            },
        )
    }

    /**
     * Writes the effective runtime profile into the attempt folder: the resolved
     * HOCON (`profile.conf`) and the exact GLK1 v2 bytes handed to native
     * (`profile.bin`). No-op when debug export is disabled.
     */
    private fun dumpRuntimeProfile(
        log: (String) -> Unit,
        writeSidecar: (String, ByteArray) -> Boolean,
        release: String,
        pair: CpuPair,
        blob: ByteArray?,
    ) {
        val conf = runCatching { profileController.renderResolvedForDebug(release, pair) }.getOrNull()
        val confWritten = conf?.let {
            writeSidecar("profile.conf", it.toByteArray(StandardCharsets.UTF_8))
        } ?: false
        val blobWritten = blob?.let { writeSidecar("profile.bin", it) } ?: false
        if (confWritten || blobWritten) {
            log("<k> runtime profile written: profile.conf/profile.bin")
        }
    }

    override fun requestShizukuPermission() = shizukuRunner.requestPermission()

    override fun setShizukuStatusListener(listener: (() -> Unit)?) =
        shizukuRunner.setStatusListener(listener)

    /* Second way (DirtyFrag hybrid): the W1-only native run has left SELinux
     * permissive. Create the IpSec transport transform, compute the page-cache
     * plan (the app owns every IV), and run the native stage that patches
     * libc++, triggers init, runs the root script over the init shell and
     * restores the blocks. */
    private suspend fun runDirtyfragStage(onLog: (String) -> Unit, debugDir: String?): Int {
        val ipsec = appContext.getSystemService(Context.IPSEC_SERVICE) as? IpSecManager
            ?: run {
                onLog("<-> second way: IpSecManager unavailable")
                return 1
            }
        val loopback = InetAddress.getByName("127.0.0.1")
        val encap = ipsec.openUdpEncapsulationSocket()
        val spiObj = ipsec.allocateSecurityParameterIndex(loopback)
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val senderProbe = DatagramSocket()
        val senderPort = senderProbe.localPort
        senderProbe.close()
        val transform = IpSecTransform.Builder(appContext)
            .setEncryption(IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, key))
            .setIpv4Encapsulation(encap, senderPort)
            .buildTransportModeTransform(loopback, spiObj)
        try {
            val random = SecureRandom()
            val alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
            val socketName = buildString {
                repeat(8) { append(alphabet[random.nextInt(alphabet.length)]) }
            }
            val plan = DirtyfragPlan.build(
                appContext,
                File("/system/lib64/libc++.so"),
                key,
                spiObj.spi,
                senderPort,
                encap.port,
                socketName,
                File(filesDir, "dirtyfrag.plan"),
            )
            onLog("<k> second way: plan ${plan.name} socket=@$socketName")
            /* Test hook: a debug file selects the native diagnostic mode
             * (noshell / noscript); anything else, or no file, is the product
             * path. The root script reads the same file for "noinstrument". */
            val modeText = runCatching { File(filesDir, "dirtyfrag.mode").readText() }.getOrDefault("")
            val dirtyfragMode = when {
                modeText.contains("noshell") -> "noshell"
                modeText.contains("noscript") -> "noscript"
                modeText.contains("laterestore") -> "laterestore"
                else -> "full"
            }
            onLog("<k> second way: mode=$dirtyfragMode")
            val binary = File(appContext.applicationInfo.nativeLibraryDir, NativeBinaryName)
            val command = ProcessBuilder(
                binary.absolutePath,
                "--dirtyfrag",
                plan.absolutePath,
                "--dirtyfrag-mode",
                dirtyfragMode,
            )
                .directory(filesDir)
                .redirectErrorStream(true)
                .apply {
                    environment()["GHOSTLOCK_HOME"] = filesDir.absolutePath
                    environment()["TMPDIR"] = filesDir.absolutePath
                    environment()["HOME"] = filesDir.absolutePath
                }
            val code = runProcess(command, onLog = onLog, captureOutput = true, timeoutSeconds = 120L)
            onLog("<b> second way: dirtyfrag exited code=$code")
            return code
        } finally {
            runCatching { transform.close() }
            runCatching { spiObj.close() }
            runCatching { encap.close() }
        }
    }

    private suspend fun runExploitBinary(
        pair: CpuPair,
        binaryName: String,
        onLog: (String) -> Unit,
        debugDir: String?,
        runDir: String?,
        writeSidecar: (String, ByteArray) -> Boolean,
    ): Int {
        val workDir = filesDir
        return try {
            val binary = File(appContext.applicationInfo.nativeLibraryDir, binaryName)
            require(binary.isFile) { "missing native binary: ${binary.absolutePath}" }
            if (!stageKsud(workDir, onLog)) return 1
            // U01-S14: a per-run KernelSU log path so a previous run's markers
            // can never satisfy the handoff probe; passed to the native process.
            val ksuLog = File(workDir, ksuLogName(System.currentTimeMillis()))
            val nativeLog = File(workDir, NativeLogFileName)
            nativeLog.writeText("")
            val release = System.getProperty("os.version", "").orEmpty()
            val config = profileController.load(release, pair)
            onLog(
                "<k> profile: hasProfile=${config.hasProfile} " +
                    "invalid=${config.invalidPaths.size} release=$release",
            )
            logProfileLayers(onLog, config)
            if (!config.hasProfile) {
                val reason = config.layers?.externalError?.let { " ($it)" } ?: ""
                error(
                    "no profile resolved for $release$reason; select a profile file, " +
                        "or pick a built-in release",
                )
            }
            if (config.invalidPaths.isNotEmpty()) {
                error(
                    "profile has ${config.invalidPaths.size} invalid field(s): " +
                        config.invalidPaths.take(6).joinToString(),
                )
            }
            /* The profile selects the pipeline; the Advanced toggle is a
             * debug-only override. A profile without the key predates the
             * selector and is refused, never defaulted. */
            val pipeline = run {
                val fromProfile = config.pipeline?.lowercase()
                if (BuildConfig.DEBUG && secondWay) {
                    onLog(
                        "<k> pipeline=dirtyfrag (debug override; profile=" +
                            "${fromProfile ?: "legacy default ghostlock"})",
                    )
                    "dirtyfrag"
                } else {
                    when (fromProfile) {
                        "ghostlock", "dirtyfrag" -> {
                            onLog("<k> pipeline=$fromProfile (profile)")
                            fromProfile
                        }
                        /* Every profile authored before the selector was a
                         * GhostLock plan; the default preserves that intent. */
                        null -> "ghostlock".also {
                            onLog(
                                "<k> pipeline=ghostlock (legacy default; profile has " +
                                    "no pipeline key)",
                            )
                        }
                        else -> error("profile has unknown pipeline '$fromProfile'")
                    }
                }
            }
            var profileBlob = profileController.nativeDocument(config)
                ?: error("profile is unavailable for $release")
            // v2: safe_mode lives in the meta section; there is no fixed slot
            // offset, so the blob is rescanned and rewritten.
            if (safeModeEnabled) {
                profileBlob = NativeProfileDocument.patchSafeMode(profileBlob) ?: profileBlob
            }
            logProfileDigest(onLog, profileBlob)
            dumpRuntimeProfile(onLog, writeSidecar, release, pair, profileBlob)
            val ksuOffset = AtomicLong()
            val nativeOffset = AtomicLong()
            val processRef = AtomicReference<Process?>(null)
            // tag root-script lines so they cannot be read as the native stages'
            val ksuSink: (String) -> Unit = { onLog("[ksu] $it") }
            // status events are consumed here (persisted + ACKed); plain lines are logs
            val nativeSink: (String) -> Unit = { line ->
                if (!handleStatusLine(line, processRef)) onLog(line)
            }
            val tailer = Thread {
                try {
                    while (!Thread.currentThread().isInterrupted) {
                        tailKsuLog(nativeLog, nativeOffset, nativeSink)
                        tailKsuLog(ksuLog, ksuOffset, ksuSink)
                        Thread.sleep(200)
                    }
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }.apply {
                name = "ksu-log-tailer"
                isDaemon = true
                start()
            }
            val argv = mutableListOf(
                binary.absolutePath,
                "--ghostlock-app-call",
                "--enable-status-record",
            )
            if (forceAttackTest) {
                argv += "--force-attack"
            }
            if (pipeline == "dirtyfrag") {
                /* Stop after W1 (SELinux permissive) and run the DirtyFrag stage. */
                argv += "--w1-only"
            }
            if (!debugDir.isNullOrEmpty()) {
                argv += listOf("--dump-kernel-log", debugDir)
            }
            val command = ProcessBuilder(argv)
                .directory(workDir)
                .redirectErrorStream(true)
                .redirectOutput(nativeLog)
                .apply {
                    environment()["GHOSTLOCK_HOME"] = workDir.absolutePath
                    environment()["TMPDIR"] = workDir.absolutePath
                    environment()["HOME"] = workDir.absolutePath
                    environment()["GHOSTLOCK_KSU_LOG"] = ksuLog.absolutePath
                    /* The user-authoritative vr.ko choices; the native resolves Auto. */
                    environment()["GHOSTLOCK_VRKO_TAG_CLEAR"] = vrKoTagClear.wire
                    environment()["GHOSTLOCK_VRKO_SELINUX_BLOCK"] = vrKoSelinuxBlock.wire
                    /* The run folder the exporter zips whole: the native writes
                     * the vr.ko diagnostic sidecar next to the log. */
                    if (!runDir.isNullOrEmpty()) {
                        environment()["GHOSTLOCK_RUN_DIR"] = runDir
                    }
                    /* Only when it is provable: a missing anchor state file is
                     * then known to mean "no run since the reboot" instead of
                     * "cannot tell", which is what let a clean install never
                     * run at all. See InstallClock. */
                    if (InstallClock.installPredatesBoot(appContext)) {
                        environment()["GHOSTLOCK_ANCHOR_TRUSTED"] = "1"
                    }
                }
            onLog("<b> starting native: ${binary.absolutePath}")
            resetRunState()
            try {
                val nativeCode = runProcess(
                    command,
                    onLog = {},
                    captureOutput = false,
                    stdin = profileBlob,
                    frameStdin = true,
                    onProcess = { processRef.set(it) },
                )
                onLog("<b> native exited code=$nativeCode")
                if (pipeline == "dirtyfrag" && nativeCode == 0) {
                    onLog("<b> pipeline=dirtyfrag: W1 done; starting the DirtyFrag stage")
                    runDirtyfragStage(onLog, debugDir)
                } else {
                    nativeCode
                }
            } finally {
                withContext(Dispatchers.IO) {
                    tailer.interrupt()
                    tailer.join(1000)
                    tailKsuLog(nativeLog, nativeOffset, onLog)
                    tailKsuLog(ksuLog, ksuOffset, ksuSink)
                }
            }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            onLog("<-> error: ${error::class.simpleName}: ${error.message}")
            1
        }
    }

    override suspend fun readDocument(uri: String): String =
        appContext.contentResolver.openInputStream(uri.toUri())?.bufferedReader()?.use { it.readText() } ?: throw IOException("cannot open $uri")

    override suspend fun cacheDocument(uri: String, fileName: String): String {
        val target = File(filesDir, fileName)
        appContext.contentResolver.openInputStream(uri.toUri())?.use { input ->
            target.outputStream().use(input::copyTo)
        } ?: throw IOException("cannot open $uri")
        return target.absolutePath
    }

    override suspend fun userProfiles(): List<UserProfileFile> =
        withContext(Dispatchers.IO) {
            userProfileStore.list().map { stored ->
                UserProfileFile(
                    name = stored.name,
                    releases = stored.releases,
                    importedAt = stored.importedAt,
                    sizeBytes = stored.sizeBytes,
                    parseError = stored.parseError,
                    version = stored.version,
                )
            }
        }

    /* ---- profile sources (measured-db storage model) ---- */

    override fun activeExternalProfile(): ExternalProfileInfo? =
        profileController.activeExternalProfile()

    override suspend fun selectExternalProfile(uri: String): ProfileConfig? =
        withContext(Dispatchers.IO) {
            val release = deviceRelease()
            val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext null
            runCatching {
                profileController.selectExternalProfile(uri, release, pair)
            }.getOrNull()
        }

    override suspend fun clearExternalProfile(): ProfileConfig = withContext(Dispatchers.IO) {
        profileController.clearExternalProfile(deviceRelease(), currentPairOrZero())
    }

    override fun liveProfileDocument(): String? {
        val release = deviceRelease()
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return null
        val text = profileController.renderResolved(release, pair) ?: return null
        return withLineage(
            text,
            profileController.currentSelectionLabel(release),
            profileController.activeExternalProfile()?.sha256,
        )
    }

    override suspend fun writeProfileDocument(uri: String, text: String): Boolean =
        withContext(Dispatchers.IO) {
            runCatching {
                val resolver = appContext.contentResolver
                val target = uri.toUri()
                /* Some DocumentsProviders reject the "wt" mode even though the
                 * file was created; "w" truncates too, so try it first. */
                val stream = runCatching { resolver.openOutputStream(target, "w") }.getOrNull()
                    ?: resolver.openOutputStream(target, "wt")
                    ?: return@runCatching false
                stream.use { it.write(text.toByteArray(StandardCharsets.UTF_8)) }
                true
            }.onFailure { Log.w("GhostLock", "profile write failed: $uri", it) }
                .getOrDefault(false)
        }

    /* ---- editing session: in-memory, export-only ---- */

    private var editSession: AndroidProfileConfigController? = null
    private var editSessionTargetName: String? = null
    private var editSessionTargetRelease: String? = null

    override suspend fun beginEditSession(): ProfileConfig? = withContext(Dispatchers.IO) {
        endEditSession()
        val release = deviceRelease()
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext null
        val live = runCatching { profileController.load(release, pair) }.getOrNull()
        if (live?.hasProfile != true) return@withContext null
        val session = AndroidProfileConfigController(
            context = appContext,
            externalProfiles = externalProfileStore,
            preferences = preferences,
            overrideStore = MemoryOverrideStore(),
            forcedSelection = profileController.currentSelection(release),
        )
        editSession = session
        editSessionTargetName = profileController.currentSelectionLabel(release)
        editSessionTargetRelease = release
        runCatching { session.load(release, pair) }.getOrNull()
    }

    override fun editSessionController(): ProfileConfigController? = editSession

    override fun editSessionTarget(): String? = editSessionTargetName

    override fun editSessionRelease(): String? = editSessionTargetRelease

    override fun editSessionDocument(): String? {
        val session = editSession ?: return null
        val release = editSessionTargetRelease ?: return null
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return null
        val text = session.renderResolved(release, pair) ?: return null
        return withLineage(text, editSessionTargetName, session.activeExternalProfile()?.sha256)
    }

    override fun editSessionDiff(): List<ProfileDiffRow> {
        val session = editSession ?: return emptyList()
        val release = editSessionTargetRelease ?: return emptyList()
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return emptyList()
        return session.diffAgainstBundle(release, pair)
    }

    override suspend fun rebaseEditSession(): ProfileConfig? = withContext(Dispatchers.IO) {
        val session = editSession ?: return@withContext null
        val release = editSessionTargetRelease ?: return@withContext null
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext null
        val config = runCatching { session.rebaseToBundle(release, pair) }.getOrNull()
        if (config != null) editSessionTargetName = session.currentSelectionLabel(release)
        config
    }

    override fun endEditSession() {
        editSession = null
        editSessionTargetName = null
        editSessionTargetRelease = null
    }

    /* ---- measured database merge ---- */

    override suspend fun measurementMergeDiff(): List<MeasurementMergeRow> =
        withContext(Dispatchers.IO) {
            val release = deviceRelease()
            val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return@withContext emptyList()
            val numbers = profileController.resolvedNumbers(release, pair)
                ?: return@withContext emptyList()
            measuredProfiles.kernel(release)?.facts.orEmpty().map { fact ->
                MeasurementMergeRow(
                    path = fact.key,
                    profileValue = numbers[fact.key],
                    measuredValue = fact.value,
                    source = fact.source,
                    evidence = fact.evidence,
                    measuredAt = fact.measuredAt,
                )
            }.filter { it.profileValue != it.measuredValue }
        }

    override fun mergedProfileDocument(): String? {
        val release = deviceRelease()
        val pair = cpuPairs.getOrNull(selectedCpuPair) ?: return null
        val facts = measuredProfiles.kernel(release)?.facts.orEmpty()
        if (facts.isEmpty()) return null
        val text = profileController.renderMerged(
            release,
            pair,
            facts.associate { it.key to it.value },
        ) ?: return null
        return withLineage(
            text,
            profileController.currentSelectionLabel(release),
            profileController.activeExternalProfile()?.sha256,
        )
    }

    /* ---- legacy app-data cleanup ---- */

    override suspend fun legacyState(): LegacyProfileState = withContext(Dispatchers.IO) {
        val profiles = userProfileStore.list().map { stored ->
            UserProfileFile(
                name = stored.name,
                releases = stored.releases,
                importedAt = stored.importedAt,
                sizeBytes = stored.sizeBytes,
                parseError = stored.parseError,
                version = stored.version,
            )
        }
        LegacyProfileState(profiles, legacyOverridePresent())
    }

    override fun legacyProfileDocument(name: String, applyOverride: Boolean): String? {
        val text = userProfileStore.rawText(name) ?: return null
        val entries = runCatching { userProfileStore.parseEntries(text) }.getOrNull() ?: return null
        if (entries.isEmpty()) return null
        /* Export in the current layout: the stored text may still be v1. */
        entries.forEach { LegacyProfileConverter.convertValue(it) }
        if (applyOverride) {
            val overrides = readLegacyOverrides()
            entries.forEach { entry ->
                val release = entry["release"] as? String ?: return@forEach
                overrides[release].asValueMap()?.let { applyLegacyOverride(entry, it) }
            }
        }
        entries.forEach { it["schema_version"] = if (hasPhysMaps(it)) 2 else 1 }
        val document = if (entries.size == 1) entries.first() else ValueList().apply { addAll(entries) }
        return HoconSupport.render(document)
    }

    private fun hasPhysMaps(entry: ValueMap): Boolean =
        entry["kernel_phys_load"] is Map<*, *> || entry["kernel_phys_offset"] is Map<*, *>

    override suspend fun finishLegacyCleanup(): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            userProfileStore.list().forEach { userProfileStore.delete(it.name) }
            /* Old builds also kept one resolved snapshot per release in
             * filesDir. Delete only files that parse as a profile, and never
             * the measured database. */
            filesDir.listFiles { file -> file.isFile && file.name.endsWith(".conf") }
                ?.forEach { file ->
                    if (file.name == MeasuredDbFileName) return@forEach
                    val text = runCatching { file.readText() }.getOrNull() ?: return@forEach
                    val isProfile = runCatching {
                        HoconSupport.parseValue(text).asValueMap()?.containsKey("release") == true
                    }.getOrDefault(false)
                    if (isProfile) file.delete()
                }
            preferences.edit {
                remove(AndroidProfileConfigController.PrefDebugProfileOverrides)
                remove(AndroidProfileConfigController.PrefOverridesBuildSha)
            }
            true
        }.getOrDefault(false)
    }

    private fun deviceRelease(): String = System.getProperty("os.version", "").orEmpty()

    private fun currentPairOrZero(): CpuPair = cpuPairs.getOrNull(selectedCpuPair) ?: CpuPair(0, 0)

    private fun withLineage(text: String, parentLabel: String?, parentSha256: String?): String {
        val parent = parentLabel?.let { ProfileLineage.Parent(it, parentSha256) }
        return ProfileLineage.header(parent) + "\n" + text
    }

    private fun legacyOverridePresent(): Boolean {
        val raw = preferences.getString(
            AndroidProfileConfigController.PrefDebugProfileOverrides,
            null,
        ) ?: return false
        return runCatching {
            HoconSupport.parseValue(raw).asValueMap()?.isNotEmpty() == true
        }.getOrDefault(false)
    }

    private fun readLegacyOverrides(): ValueMap {
        val raw = preferences.getString(
            AndroidProfileConfigController.PrefDebugProfileOverrides,
            null,
        ) ?: return valueMapOf()
        return runCatching { HoconSupport.parseValue(raw).asValueMap() ?: valueMapOf() }
            .getOrDefault(valueMapOf())
    }

    /**
     * Applies a stored legacy override to one document entry. The branch rule
     * (same branch merges, a different branch replaces) lives in
     * [LegacyProfileExport] so the export is testable.
     */
    private fun applyLegacyOverride(entry: ValueMap, override: ValueMap) {
        LegacyProfileExport.applyOverride(entry, override)
    }

    override fun close() {
        shizukuRunner.close()
        synchronized(processes) {
            processes.forEach(Process::destroyForcibly)
            processes.clear()
        }
    }

    /**
     * Legacy/parse helper: reads HOCON or JSON text into a list of entries.
     * Stored user documents are parsed by [UserProfileStore] instead.
     */
    private fun parseEntries(text: String): ValueList? {
        if (text.isBlank()) return null
        return try {
            when (val value = HoconSupport.parseValue(text)) {
                is List<*> -> value.asValueList()
                is Map<*, *> -> ValueList().apply { value.asValueMap()?.let(::add) }
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Fields a parsed profile still lacks that only an xbl_config FDT or uefi
     * memory map can fill. Used to prompt for the optional sidecars.
     */
    /** Resolve a schema-v2 per-device pair for the running device, if present. */
    private fun resolvedForDevice(entry: ValueMap, candidates: List<String>): ValueMap =
        runCatching { PerDevicePhys.resolveFor(entry, candidates).document }.getOrDefault(entry)

    private fun missingSidecarFields(entries: List<ValueMap>): Set<String> =
        if (entries.isNotEmpty() && entries.all { it.getLongAt("kernel_phys_load") == null }) {
            setOf("kernel_phys_load")
        } else {
            emptySet()
        }

    private fun parsedDocumentName(releases: List<String>): String {
        val stem = releases.firstOrNull().orEmpty()
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .ifEmpty { "parsed" }
        return "$stem.conf"
    }

    private fun freshReleases(entries: List<*>): List<String> =
        entries.mapNotNull { (it.asValueMap()?.get("release") as? String) }.distinct()

    private fun isKernelSupported(): Boolean {
        val version = System.getProperty("os.version", "").orEmpty()
        return releaseSupportedByProfileSources(
            version,
            builtinProfiles.unames,
            profileController.activeExternalProfile()?.release,
        ) || importedOffsetsMatch(version)
    }

    private fun importedOffsetsMatch(version: String): Boolean =
        userProfileStore.containsRelease(version)

    private fun importedOffsetsRecommendShizuku(version: String): Boolean =
        userProfileStore.recommendsShizuku(version)

    private fun buildCpuPairs() {
        cpuPairs.clear()
        cpuPairLabels.clear()
        val online = parseCpuList(readSysFile("/sys/devices/system/cpu/online"))
        online.groupBy { readMaxFreq(it) }.filterKeys { it > 0 }.toSortedMap(compareByDescending { it }).forEach { (freq, cluster) ->
                cluster.sorted().chunked(2).filter { it.size == 2 }.forEach { pair ->
                    cpuPairs += CpuPair(pair[0], pair[1])
                    cpuPairLabels += "${pair[0]},${pair[1]} · ${formatFreq(freq)}"
                }
            }
        if (CpuPair(0, 1) !in cpuPairs) {
            cpuPairs += CpuPair(0, 1)
            val freq = readMaxFreq(0)
            cpuPairLabels += "0,1" + if (freq > 0) " · ${formatFreq(freq)}" else ""
        }
    }

    private fun restoreCpuPair() {
        val saved = appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE).getString("cpu_pair", null) ?: return
        val pair = saved.split(',').mapNotNull { it.trim().toIntOrNull() }
        if (pair.size == 2) cpuPairs.indexOf(CpuPair(pair[0], pair[1])).takeIf { it >= 0 }?.let { selectedCpuPair = it }
    }

    private fun restoreShizukuPreference() {
        val prefs = appContext.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
        shizukuPreferenceSet = prefs.getBoolean("shizuku_explicit", false)
        shizukuEnabled = prefs.getBoolean("shizuku_enabled", false)
    }

    private fun restoreForceAttackTest() {
        forceAttackTest = preferences.getBoolean(PrefForceAttackTest, false)
    }

    private fun restoreSecondWay() {
        secondWay = preferences.getBoolean(PrefSecondWay, false)
    }

    private fun restoreVrKoTagClear() {
        vrKoTagClear = readVrKoMode(PrefVrKoTagClear)
    }

    private fun restoreVrKoSelinuxBlock() {
        vrKoSelinuxBlock = readVrKoMode(PrefVrKoSelinuxBlock)
    }

    /**
     * Reads a tri-state preference. The unreleased v2 build stored a boolean:
     * true maps to Auto (never a forced On) and false to Off.
     */
    private fun readVrKoMode(key: String): VrKoMode =
        when (val raw = preferences.all[key]) {
            is Boolean -> if (raw) VrKoMode.AUTO else VrKoMode.OFF
            is String -> VrKoMode.fromWire(raw)
            else -> VrKoMode.AUTO
        }

    private fun parseCpuList(value: String): List<Int> = value.split(',').flatMap { part ->
        val range = part.trim().split('-').mapNotNull { it.toIntOrNull() }
        when (range.size) {
            1 -> range
            2 -> (range[0]..range[1]).toList()
            else -> emptyList()
        }
    }

    private fun readMaxFreq(cpu: Int): Long = readSysFile("/sys/devices/system/cpu/cpu$cpu/cpufreq/cpuinfo_max_freq").toLongOrNull() ?: -1L

    private fun formatFreq(khz: Long): String =
        if (khz >= 1_000_000L) "%.2f GHz".format(Locale.ROOT, khz / 1_000_000.0) else "%.0f MHz".format(Locale.ROOT, khz / 1000.0)

    private fun readSysFile(path: String): String = File(path).takeIf { it.isFile }?.useLines { it.firstOrNull()?.trim().orEmpty() } ?: ""

    @SuppressLint("PrivateApi")
    private fun systemProperty(key: String): String = try {
        val properties = Class.forName("android.os.SystemProperties")
        properties.getMethod("get", String::class.java).invoke(null, key) as? String ?: ""
    } catch (_: Throwable) {
        ""
    }

    private fun validDeviceName(value: String?): String? =
        value?.trim()?.takeIf { it.isNotEmpty() && !it.contains("unknown", true) && !it.contains("null", true) }

    private fun resolveDeviceName(): String {
        val manufacturer = Build.MANUFACTURER.orEmpty()
        val marketName = when (manufacturer.lowercase(Locale.ROOT)) {
            "xiaomi" -> firstValidProperty("ro.product.marketname")
            "oppo", "oneplus", "realme", "oplus" -> {
                val cn = Locale.getDefault().country.equals("CN", true)
                firstValidProperty(
                    *(if (cn) arrayOf(
                        "ro.vendor.oplus.market.name", "ro.vendor.oplus.market.enname"
                    ) else arrayOf("ro.vendor.oplus.market.enname", "ro.vendor.oplus.market.name"))
                )
            }

            "vivo" -> firstValidProperty("ro.vivo.market.name")
            "honor", "huawei" -> firstValidProperty("ro.config.marketing_name")
            "zte", "nubia" -> firstValidProperty("ro.vendor.product.ztename")
            else -> null
        }
        return marketName ?: listOfNotNull(
            manufacturer, Build.BRAND.orEmpty().takeIf { !it.equals(manufacturer, true) }, Build.MODEL.orEmpty()
        ).filter { it.isNotBlank() }.joinToString(" ")
    }

    private fun resolveSocName(): String = listOf(
        systemProperty("ro.soc.manufacturer"),
        systemProperty("ro.soc.model"),
    ).mapNotNull(::validDeviceName).joinToString(" ").ifBlank { "unknown" }

    private fun firstValidProperty(vararg keys: String): String? = keys.asSequence().firstNotNullOfOrNull { validDeviceName(systemProperty(it)) }

    /**
     * Find a late-load-capable ksud and stage it into [workDir]/ksud.
     *
     * Returns false when no suitable manager exists; the caller must then
     * refuse to start the exploit (and say why in the run log).
     */
    private suspend fun stageKsud(workDir: File, onLog: (String) -> Unit): Boolean = withContext(Dispatchers.IO) {
        val preflight = preflightManager.also { preflightManager = null }
        val chosen = if (preflight != null &&
            SystemClock.elapsedRealtime() - preflight.first <= PreflightManagerMaxAgeMs &&
            File(preflight.second.path).isFile
        ) {
            /* The pre-flight just ran the same scan; reuse its choice instead of
             * paying the package/ELF scan twice per run. The freshness and
             * existence checks above fall back to a fresh scan. */
            onLog(
                "<k> ksud: using pre-flight selection ${preflight.second.packageName} " +
                    "${preflight.second.path} [${preflight.second.verdict}]",
            )
            preflight.second
        } else {
            val candidates = runCatching { ManagerScanner.scan(appContext) }.getOrElse {
                onLog("<k> error: ksud scan failed: ${it.message}")
                return@withContext false
            }
            val suitable = candidates.filter { it.suitable }
            onLog("<k> ksud scan: ${candidates.size} candidate(s), ${suitable.size} suitable")
            candidates.forEach {
                onLog("<k>   ${it.packageName}: ${it.path} [${it.verdict}]")
            }
            val resolved = ManagerScanner.resolve(candidates, selectedManagerPackage())
            if (resolved == null) {
                onLog("<k> error: no suitable ksud found; refusing to start the exploit")
                return@withContext false
            }
            if (suitable.size > 1) {
                onLog(
                    "<k> ksud: ${suitable.size} suitable; using ${resolved.packageName} " +
                        "(Advanced -> Root manager to change)",
                )
            }
            resolved
        }
        val output = File(workDir, "ksud")
        runCatching {
            output.delete()
            File(chosen.path).inputStream().use { input ->
                output.outputStream().use { input.copyTo(it) }
            }
            Os.chmod(output.absolutePath, 448)
        }.onFailure {
            onLog("<k> error: cannot stage ksud from ${chosen.path}: ${it.message}")
            return@withContext false
        }
        onLog("<k> ksud selected: ${chosen.packageName} ${chosen.path} [${chosen.verdict}]")
        true
    }

    private suspend fun runProcess(
        builder: ProcessBuilder,
        onLog: (String) -> Unit = {},
        timeoutSeconds: Long = 300,
        captureOutput: Boolean = true,
        stdin: ByteArray? = null,
        frameStdin: Boolean = false,
        onProcess: ((Process) -> Unit)? = null,
    ): Int = runInterruptible(Dispatchers.IO) {
        val process = builder.start()
        synchronized(processes) { processes += process }
        if (stdin != null) {
            if (frameStdin) {
                /* 4-byte big-endian length + payload, stdin kept open for the
                 * status-record ACK channel. */
                runCatching {
                    val out = process.outputStream
                    val length = stdin.size
                    out.write(
                        byteArrayOf(
                            (length ushr 24).toByte(),
                            (length ushr 16).toByte(),
                            (length ushr 8).toByte(),
                            length.toByte(),
                        ),
                    )
                    out.write(stdin)
                    out.flush()
                }
            } else {
                runCatching { process.outputStream.use { it.write(stdin) } }
            }
        }
        onProcess?.invoke(process)
        val reader = if (captureOutput) Thread {
            try {
                process.inputStream.bufferedReader(StandardCharsets.UTF_8).useLines { lines -> lines.forEach(onLog) }
            } catch (_: IOException) {
            }
        }.apply {
            name = "process-output-reader"
            isDaemon = true
        } else null
        try {
            reader?.start()
            val finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!finished) {
                process.destroy()
                if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly()
            }
            reader?.let(::joinReader)
            if (finished) process.exitValue() else -1
        } finally {
            if (process.isAlive) process.destroyForcibly()
            reader?.interrupt()
            runCatching { process.inputStream.close() }
            reader?.let(::joinReader)
            synchronized(processes) { processes -= process }
        }
    }

    private fun joinReader(reader: Thread) {
        try {
            reader.join(3000)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun tailKsuLog(logFile: File, offset: AtomicLong, onLog: (String) -> Unit) {
        if (!logFile.isFile) return
        synchronized(offset) {
            runCatching {
                RandomAccessFile(logFile, "r").use { file ->
                    val position = offset.get().takeIf { it <= file.length() } ?: 0L
                    file.seek(position)
                    var lastComplete = position
                    val pending = StringBuilder()
                    while (true) {
                        val byte = file.read()
                        if (byte == -1) break
                        if (byte == '\n'.code) {
                            if (pending.isNotEmpty()) onLog(pending.toString())
                            pending.clear()
                            lastComplete = file.filePointer
                        } else {
                            pending.append(byte.toChar())
                        }
                    }
                    offset.set(lastComplete)
                }
            }
        }
    }

    private val processes = mutableSetOf<Process>()

}

/**
 * Whether the release is covered by a profile source the app can trust: a
 * bundled asset naming it, or an SD-card document the user selected for it.
 * The measured-db model keeps no copy in app data, so the selection reference
 * is the only place to ask; an unreadable file surfaces in the resolution as
 * an error, never a silent fallback.
 */
internal fun releaseSupportedByProfileSources(
    release: String,
    bundledReleases: Set<String>,
    externalSelectionRelease: String?,
): Boolean = release in bundledReleases || externalSelectionRelease == release
