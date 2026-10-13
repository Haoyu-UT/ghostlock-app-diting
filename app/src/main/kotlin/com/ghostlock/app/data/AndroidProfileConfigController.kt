package com.ghostlock.app.data

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import androidx.core.net.toUri
import com.ghostlock.app.BuildConfig
import com.ghostlock.app.data.profile.CpuPairView
import com.ghostlock.app.data.profile.ProfileMerger
import com.ghostlock.app.data.profile.ProfileResolver
import com.ghostlock.app.data.route.RouteKind
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ExecutionFieldValue
import com.ghostlock.app.domain.model.ProfileConfig
import com.ghostlock.app.domain.model.ProfileFieldNode
import com.ghostlock.app.domain.model.ProfileLayers
import com.ghostlock.app.domain.repository.ProfileConfigController
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * Controller-centered profile architecture. HOCON is the persistence format
 * and the value model (Map/List/scalars) is the in-memory representation,
 * while this class is the single authority for loading it, merging
 * builtin/imported/override layers, persisting sparse edits and producing the
 * document handed to the native process.
 *
 * Imported profiles come verbatim from [userProfiles]; every edit (general,
 * route/fallback and advanced) persists as a sparse override in preferences,
 * so stored user documents are never rewritten.
 *
 * Layer policy (PORT-PLAN Phase 8 §B): a **bundled** profile is authoritative
 * for the device's own release, so a loaded import does not shadow it, and the
 * override layer applies only when it was written by the build that is running.
 * Both rules only decide what is *applied*; nothing on disk is moved or
 * deleted, and the disabled layers stay exportable.
 */
internal class AndroidProfileConfigController(
    context: Context,
    private val filesDir: File,
    private val userProfiles: UserProfileStore,
    private val preferences: SharedPreferences,
    /**
     * Editing sessions pin the imported document instead of consulting the
     * live selection, and keep their overrides in [preferences] (a private
     * session store), so they never touch the attack controller.
     */
    private val forcedUserProfile: String? = null,
    /** Editing sessions also pin the builtin source of the live controller. */
    private val forcedBuiltinRelease: String? = null,
    /** Build identity compared against the one that wrote the overrides. */
    private val buildIdentity: String = BuildConfig.BUILD_IDENTITY,
) : ProfileConfigController {
    private val appContext = context.applicationContext
    private val assetLoader = AssetConfigLoader(appContext)
    private val lock = Any()

    override suspend fun load(release: String, pair: CpuPair): ProfileConfig {
        val deviceRelease = release
        val stored = readAdvancedOverride(deviceRelease).takeIf { it.isNotEmpty() }
        val applied = effectiveOverrides(deviceRelease)
        val resolution = resolveCurrent(deviceRelease, pair, applied, includeImported = true)
        val full = resolution.profile
        if (full == null) {
            return ProfileConfig(release = deviceRelease, hasProfile = false, pair = pair)
        }
        val appliedRoute = routeNameOf(full)
        val appliedFallback = fallbackTargetOf(full)
        val invalidPaths = validateProfileFields(full, appliedRoute, appliedFallback) +
            ProfileResolver.validateMerged(full, appliedRoute, appliedFallback)
                .mapTo(mutableSetOf()) { it.fieldPath }
        /* The editor renders the *stored* layer even when the policy keeps it
         * out of the run, so a disabled override is visible and saving it
         * re-enables the layer instead of silently dropping values the user
         * cannot see (§B.7). What runs is `full`. */
        val view = if (stored != null && stored != applied) {
            resolveCurrent(deviceRelease, pair, stored, includeImported = true).profile ?: full
        } else {
            full
        }
        val route = routeNameOf(view)
        val fallbackTo = fallbackTargetOf(view)
        /* Invalid fields missing from the resolved document still get a row,
         * otherwise the run stays blocked with no red field to fix. */
        materializeInvalidPaths(view, invalidPaths)
        /* The editor shows every field of the active route plus the shared
         * geometry, so a field the profile did not carry appears as an
         * editable `null` row instead of being invisible. */
        val complete = completeProfileFields(view, route, fallbackTo)
        val baseline = resolveCurrent(deviceRelease, pair, null, includeImported = false).profile ?: full
        val roots = buildTree(complete, "", baseline, stored ?: valueMapOf())
        return ProfileConfig(
            release = deviceRelease,
            hasProfile = true,
            pair = pair,
            layers = resolution.layers.copy(
                uncarriedKeys = uncarriedRouteKeys(full, appliedRoute),
            ),
            roots = roots,
            general = generalFields(view, baseline, route, fallbackTo),
            route = route,
            fallbackTo = fallbackTo,
            invalidPaths = invalidPaths,
        )
    }

    /**
     * Kotlin-side geometry/credential validation. The profile declares its
     * route explicitly; fields that belong to other routes may stay absent.
     */
    private fun validateProfileFields(
        profile: ValueMap,
        explicitRoute: String?,
        fallbackTo: String?,
    ): Set<String> {
        val invalid = mutableSetOf<String>()
        fun value(path: String): Long? = profile.getLongAt(path)
        fun requireNonZero(vararg paths: String) {
            paths.forEach { path ->
                val current = value(path)
                if (current == null || current == 0L) invalid += path
            }
        }

        /* The route is profile-controlled: a missing or unknown branch is
         * invalid. Legacy documents get their route from the converter, so an
         * unresolved route here means the profile is genuinely broken. */
        val route = explicitRoute?.takeIf { it in ProfileConfig.Routes }
        if (route == null) invalid += "route"

        requireNonZero(*RouteCommonRequired.toTypedArray())
        val major = value("kernel_major")
        if (major != 5L && major != 6L) invalid += "kernel_major"

        val copySize = value("cred.copy_size")
        if (copySize == null || copySize == 0L) invalid += "cred.copy_size"
        /* Absent cred.usage_offset decodes as 0 and passes, exactly like native. */
        val usageOffset = value("cred.usage_offset") ?: 0L
        if (copySize != null && usageOffset + SizeofU32 > copySize) {
            invalid += "cred.usage_offset"
        }

        val capsCount = value("cred.caps_count")
        val capsOffset = value("cred.caps_offset")
        if (capsCount == null || capsCount == 0L) invalid += "cred.caps_count"
        if (copySize != null && capsCount != null && capsOffset != null &&
            capsOffset + capsCount * SizeofU64 > copySize
        ) {
            invalid += "cred.caps_offset"
            invalid += "cred.caps_count"
        }

        val refCount = value("cred.ref_count") ?: 0L
        if (refCount > 4) invalid += "cred.ref_count"
        for (index in 0 until 4) {
            if (index >= refCount) break
            val image = value("cred.ref${index}_image")
            if (image == null || image == 0L) invalid += "cred.ref${index}_image"
            val offset = value("cred.ref${index}_offset")
            if (copySize != null && offset != null && offset + SizeofU64 > copySize) {
                invalid += "cred.ref${index}_offset"
            }
        }

        val routePrefix = route?.let { "route.$it" } ?: "route"
        val fallbackPrefix = fallbackTo?.takeIf { it != "none" }
            ?.let { "fallback.route.$it" }
        when (route) {
            "tcp_zerocopy" -> {
                val compact = value("$routePrefix.compact_waiter")
                if (compact == null || compact == 0L) {
                    invalid += "$routePrefix.compact_waiter"
                } else if (compact < 0L || compact > 0xffL) {
                    invalid += "$routePrefix.compact_waiter"
                }
            }

            "select_stack" -> {
                val shift = value("$routePrefix.waiter_shift")
                if (shift == null ||
                    shift < Int.MIN_VALUE.toLong() || shift > Int.MAX_VALUE.toLong()
                ) {
                    invalid += "$routePrefix.waiter_shift"
                }
            }

            "multicast_waiter" -> {
                for (field in RouteMulticastFields) {
                    val current = value("$routePrefix.$field")
                    if (current == null || current == 0L) {
                        invalid += "$routePrefix.$field"
                    } else if (current < 0L || current > UInt.MAX_VALUE.toLong()) {
                        invalid += "$routePrefix.$field"
                    }
                }
                val compact = value("$routePrefix.compact_waiter")
                if (compact == null || compact == 0L) {
                    invalid += "$routePrefix.compact_waiter"
                } else if (compact < 0L || compact > 0xffL) {
                    invalid += "$routePrefix.compact_waiter"
                }
                requireNonZero(
                    "kernelsnitch.mm_struct_sz",
                    "offset.empty_zero_page",
                    "cred.ref_count",
                )
                if (copySize != null && copySize < 0xa0L) invalid += "cred.copy_size"
                val waiterOff = value("$routePrefix.waiter_off")
                if (waiterOff == null || waiterOff <= 0L || waiterOff > Int.MAX_VALUE.toLong()) {
                    invalid += "$routePrefix.waiter_off"
                }
                val bufferSize = value("$routePrefix.buffer_size")
                val lockOffset = value("$routePrefix.lock_offset")
                if (waiterOff != null && waiterOff > 0L && waiterOff <= Int.MAX_VALUE.toLong() &&
                    bufferSize != null && bufferSize in 0L..UInt.MAX_VALUE.toLong() &&
                    lockOffset != null && lockOffset in 0L..UInt.MAX_VALUE.toLong() &&
                    waiterOff + lockOffset + SizeofU64 > bufferSize
                ) {
                    invalid += "$routePrefix.waiter_off"
                    invalid += "$routePrefix.lock_offset"
                    invalid += "$routePrefix.buffer_size"
                }
            }
        }
        if (fallbackTo != null && fallbackTo != "none" && fallbackTo !in ProfileConfig.Routes) {
            invalid += "fallback.to"
        } else if (fallbackPrefix != null) {
            when (fallbackTo) {
                "tcp_zerocopy" -> {
                    val compact = value("$fallbackPrefix.compact_waiter")
                    if (compact == null || compact == 0L) {
                        invalid += "$fallbackPrefix.compact_waiter"
                    } else if (compact < 0L || compact > 0xffL) {
                        invalid += "$fallbackPrefix.compact_waiter"
                    }
                }

                "select_stack" -> {
                    val shift = value("$fallbackPrefix.waiter_shift")
                    if (shift == null ||
                        shift < Int.MIN_VALUE.toLong() || shift > Int.MAX_VALUE.toLong()
                    ) {
                        invalid += "$fallbackPrefix.waiter_shift"
                    }
                }

                "multicast_waiter" -> {
                    for (field in RouteMulticastFields) {
                        val current = value("$fallbackPrefix.$field")
                        if (current == null || current == 0L) {
                            invalid += "$fallbackPrefix.$field"
                        } else if (current < 0L || current > UInt.MAX_VALUE.toLong()) {
                            invalid += "$fallbackPrefix.$field"
                        }
                    }
                }
            }
        }
        return invalid
    }

    /** The single branch key declared under "route" (string legacy allowed). */
    private fun routeNameOf(profile: ValueMap): String? {
        return when (val value = profile["route"]) {
            is String -> value.takeIf { it.isNotEmpty() && it != "null" }
            is Map<*, *> -> value.keys.filterIsInstance<String>()
                .firstOrNull { it in ProfileConfig.Routes }
            else -> null
        }
    }

    private fun fallbackTargetOf(profile: ValueMap): String? {
        profile["fallback"].asValueMap()?.let { fallback ->
            val to = fallback["to"] as? String ?: ""
            if (to.isNotEmpty() && to != "null") return to
        }
        /* Legacy flat spelling from transition builds. */
        return (profile["fallback_to"] as? String)
            ?.takeIf { it.isNotEmpty() && it != "null" }
    }

    override suspend fun updateRoute(
        release: String,
        pair: CpuPair,
        route: String?,
    ): ProfileConfig {
        val override = readAdvancedOverride(release)
        if (route.isNullOrBlank()) {
            override.remove("route")
        } else {
            val existingBranch = override["route"].asValueMap()?.get(route).asValueMap()
                ?: routeBranchTemplate(route)
            override["route"] = valueMapOf(route to existingBranch)
            pruneOverrideBranches(override, "route", route)
        }
        writeAdvancedOverride(release, override)
        persistSnapshot(release, pair)
        return load(release, pair)
    }

    override suspend fun updateFallback(
        release: String,
        pair: CpuPair,
        fallbackTo: String?,
    ): ProfileConfig {
        val override = readAdvancedOverride(release)
        if (fallbackTo.isNullOrBlank()) {
            override.remove("fallback")
        } else {
            val fallback = override["fallback"].asValueMap() ?: valueMapOf()
            fallback["to"] = fallbackTo
            if (fallbackTo in ProfileConfig.Routes) {
                val branch = fallback["route"].asValueMap()?.get(fallbackTo).asValueMap()
                    ?: routeBranchTemplate(fallbackTo)
                fallback["route"] = valueMapOf(fallbackTo to branch)
            } else {
                fallback.remove("route")
            }
            override["fallback"] = fallback
            pruneOverrideBranches(override, "fallback", fallbackTo.takeIf { it in ProfileConfig.Routes })
        }
        writeAdvancedOverride(release, override)
        persistSnapshot(release, pair)
        return load(release, pair)
    }

    override suspend fun updateGeneral(
        release: String,
        pair: CpuPair,
        values: Map<String, Long>,
    ): ProfileConfig {
        val override = readAdvancedOverride(release)
        val execution = override.mutableChild("execution")
        for ((path, value) in values) {
            if (path.startsWith("execution.")) {
                execution.setValueAt(path.removePrefix("execution."), value)
            } else {
                override.setValueAt(path, value)
            }
        }
        writeAdvancedOverride(release, override)
        persistSnapshot(release, pair)
        return load(release, pair)
    }

    override suspend fun updateAdvanced(
        release: String,
        pair: CpuPair,
        values: Map<String, Long>,
    ): ProfileConfig {
        /* Rebuild the sparse override from scratch: only values that differ from
         * the baseline survive, so untouched fields (including stale entries
         * from older builds) can never stay highlighted. */
        val baseline = resolveCurrent(release, pair, null, includeImported = true).profile
        if (baseline != null) {
            val rebuilt = valueMapOf()
            for ((path, value) in values) {
                if (path.isEmpty() || path == "release" ||
                    path.startsWith("execution.selected_cpus")
                ) {
                    continue
                }
                if (value != baseline.getLongAt(path)) rebuilt.setValueAt(path, value)
            }
            /* The advanced editor carries neither the fallback choice nor the
             * selected CPUs (and may drop a route branch the baseline already
             * matches); keep all three. */
            val current = readAdvancedOverride(release)
            current["route"].asValueMap()?.let { route -> rebuilt.putIfAbsent("route", route) }
            current["execution"].asValueMap()?.get("selected_cpus")?.let { cpus ->
                rebuilt.mutableChild("execution")["selected_cpus"] = cpus
            }
            current["fallback"].asValueMap()?.let { fallback ->
                val rebuiltFallback = rebuilt["fallback"].asValueMap()
                if (rebuiltFallback == null) {
                    rebuilt["fallback"] = fallback
                } else {
                    fallback["to"]?.let { rebuiltFallback["to"] = it }
                }
            }
            writeAdvancedOverride(release, rebuilt)
            persistSnapshot(release, pair)
        }
        return load(release, pair)
    }

    override suspend fun reset(release: String, pair: CpuPair): ProfileConfig {
        writeAdvancedOverride(release, valueMapOf())
        return load(release, pair)
    }

    override suspend fun resetGeneral(release: String, pair: CpuPair): ProfileConfig {
        val override = readAdvancedOverride(release)
        override.remove("execution")
        writeAdvancedOverride(release, override)
        return load(release, pair)
    }

    override suspend fun resetAdvanced(release: String, pair: CpuPair): ProfileConfig {
        val override = readAdvancedOverride(release)
        override.keys.toList().filter { it != "execution" }.forEach(override::remove)
        writeAdvancedOverride(release, override)
        return load(release, pair)
    }

    override suspend fun clearSelectedCpus(release: String, pair: CpuPair): ProfileConfig {
        val override = readAdvancedOverride(release)
        val execution = override["execution"].asValueMap()
        execution?.remove("selected_cpus")
        if (execution != null && execution.isEmpty()) override.remove("execution")
        writeAdvancedOverride(release, override)
        return load(release, pair)
    }

    override suspend fun export(
        release: String,
        pair: CpuPair,
        documentUri: String,
    ): Boolean = try {
        persistSnapshot(release, pair)
        val snapshot = File(filesDir, snapshotName(release))
        if (!snapshot.isFile) return false
        val resolver = appContext.contentResolver
        val output = resolver.openOutputStream(documentUri.toUri(), "wt") ?: return false
        output.use { stream -> snapshot.inputStream().use { it.copyTo(stream) } }
        true
    } catch (_: Exception) {
        false
    }

    override suspend fun saveModified(release: String, pair: CpuPair): Boolean =
        saveResolved(release, pair, modifiedName(release))

    /** Renders the resolved profile (built-in + imported + overrides) as HOCON. */
    fun renderResolved(release: String, pair: CpuPair): String? {
        val resolved = resolveCurrent(
            release, pair, effectiveOverrides(release), includeImported = true,
        ).profile ?: return null
        val view = resolved.copyValue().asValueMap() ?: return null
        view["schema_version"] = 1
        view["release"] = release
        /* The CPU choice follows the device pair, it must not be frozen here. */
        view["execution"].asValueMap()?.remove("selected_cpus")
        fillRouteExecutionDefaults(view)
        trimRouteTuning(view)
        return HoconSupport.render(view)
    }

    /** Renders the resolved profile verbatim (no trimming) for debug dumps. */
    fun renderResolvedForDebug(release: String, pair: CpuPair): String? {
        val resolved = resolveCurrent(
            release, pair, effectiveOverrides(release), includeImported = true,
        ).profile ?: return null
        val view = resolved.copyValue().asValueMap() ?: return null
        return HoconSupport.render(view)
    }

    /** Stores the rendered resolved profile under [fileName]. */
    fun saveResolved(release: String, pair: CpuPair, fileName: String): Boolean {
        val text = renderResolved(release, pair) ?: return false
        return runCatching { userProfiles.save(fileName, text) }.isSuccess
    }

    /**
     * Sparse overrides stored for [release], applied or not; seeds an editing
     * session, which must show the stored values rather than the effective ones.
     */
    fun overridesSnapshot(release: String): ValueMap =
        readAdvancedOverride(release).copyValue().asValueMap() ?: valueMapOf()

    /** Build that wrote the stored overrides, for a session that seeds them. */
    fun overridesBuildStamp(): String? = storedOverridesBuild()

    /** Replaces the sparse overrides stored for [release]. */
    fun replaceOverrides(release: String, override: ValueMap) {
        writeAdvancedOverride(release, override.copyValue().asValueMap() ?: valueMapOf())
    }

    private fun modifiedName(release: String): String =
        "${release.replace(Regex("[^A-Za-z0-9._-]"), "_")}-modified.conf"

    override suspend fun builtinReleases(): List<String> {
        val index = readIndex() ?: return emptyList()
        val profiles = index["profiles"].asValueList() ?: return emptyList()
        return profiles
            .mapNotNull { entry -> (entry.asValueMap()?.get("release") as? String) }
            .filter { it.isNotEmpty() }
            .sorted()
    }

    override fun activeBuiltinRelease(): String? =
        forcedBuiltinRelease
            ?: preferences.getString(PrefBuiltinRelease, null)?.takeIf { it.isNotEmpty() }

    override fun activeUserProfile(): String? =
        forcedUserProfile
            ?: preferences.getString(PrefActiveUserProfile, null)?.takeIf { it.isNotEmpty() }

    override suspend fun selectUserProfile(
        name: String?,
        deviceRelease: String,
        pair: CpuPair,
    ): ProfileConfig {
        preferences.edit {
            if (name.isNullOrBlank()) remove(PrefActiveUserProfile)
            else putString(PrefActiveUserProfile, name)
        }
        return load(deviceRelease, pair)
    }

    override fun onUserProfileRenamed(oldName: String, newName: String) {
        if (activeUserProfile() == oldName) {
            preferences.edit { putString(PrefActiveUserProfile, newName) }
        }
    }

    override fun onUserProfileDeleted(name: String) {
        if (activeUserProfile() == name) {
            preferences.edit { remove(PrefActiveUserProfile) }
        }
    }

    override suspend fun selectBuiltin(
        release: String?,
        deviceRelease: String,
        pair: CpuPair,
    ): ProfileConfig {
        preferences.edit {
            if (release.isNullOrBlank()) remove(PrefBuiltinRelease)
            else putString(PrefBuiltinRelease, release)
        }
        return load(deviceRelease, pair)
    }

    /**
     * Resolved on demand: a cached document was keyed on the release alone
     * while the result also depends on the imported layer, the overrides and
     * the CPU pair (PORT-PLAN Phase 8 §F). [ProfileConfig] carries the pair for
     * exactly this reason.
     */
    override fun nativeDocument(config: ProfileConfig): ByteArray? = synchronized(lock) {
        val resolved = resolveCurrent(
            config.release, config.pair, effectiveOverrides(config.release),
            includeImported = true,
        ).profile ?: return@synchronized null
        buildNativeDocument(config.release, resolved)?.toBinary()
    }

    /** Builds the single resolved authority native consumes at run time. */
    private fun buildNativeDocument(release: String, profile: ValueMap): Profile? {
        val route = routeNameOf(profile)
        val fallbackTo = fallbackTargetOf(profile)
        return Profile.fromValueMap(
            release = release,
            route = RouteKind.fromToken(route),
            fallbackTo = RouteKind.fromToken(fallbackTo),
        ) { path -> ProfileResolver.nativeValue(profile, route, fallbackTo, path) }
    }

    // ---- resolution (migrated from ProfileConfiguration) ----

    /** One resolve: the merged document plus which layers went into it. */
    private data class Resolution(val profile: ValueMap?, val layers: ProfileLayers)

    /** Resolves through the currently selected builtin release (if any). */
    private fun resolveCurrent(
        deviceRelease: String,
        pair: CpuPair,
        overrides: ValueMap?,
        includeImported: Boolean,
    ): Resolution {
        val profileRelease = activeBuiltinRelease() ?: deviceRelease
        return resolve(deviceRelease, profileRelease, pair, overrides, includeImported)
    }

    private fun resolve(
        deviceRelease: String,
        profileRelease: String,
        pair: CpuPair,
        overrides: ValueMap?,
        includeImported: Boolean,
    ): Resolution {
        val nothing = ProfileLayers(build = buildIdentity)
        return runCatching {
            val index = readIndex() ?: return@runCatching Resolution(null, nothing)
            require((index["schema_version"] as? Number)?.toInt() == 1) {
                "unsupported profile schema"
            }
            val profiles = index["profiles"].asValueList()
            val builtinEntry = findProfile(profiles, profileRelease)
            /* §B.5: a bundled profile for the device's own release is
             * authoritative, so a loaded import does not shadow it. A builtin
             * selected by hand (the escape hatch) is not the bundled match, and
             * leaves the older behaviour in place. */
            val selectedBuiltin = activeBuiltinRelease()
            val bundledAuthoritative =
                selectedBuiltin == null && findProfile(profiles, deviceRelease) != null
            val importedName = activeUserProfile()
            val importedApplied = includeImported && !bundledAuthoritative && importedName != null
            val imported = if (importedApplied) {
                userProfiles.loadEntry(deviceRelease, importedName)
            } else {
                null
            }
            val layers = ProfileLayers(
                builtinRelease = builtinEntry?.get("release") as? String,
                bundledAuthoritative = bundledAuthoritative,
                builtinSelected = selectedBuiltin != null,
                imported = importedName,
                importedApplied = importedApplied,
                overridesPresent = readAdvancedOverride(deviceRelease).isNotEmpty(),
                overridesApplied = overrides != null,
                overridesBuild = storedOverridesBuild()?.takeIf { it != buildIdentity },
                build = buildIdentity,
            )
            LegacyProfileConverter.convertValue(overrides)
            if (builtinEntry == null && imported == null) {
                return@runCatching Resolution(null, layers)
            }
            val builtin = builtinEntry?.let { entry ->
                val path = (entry["file"] as? String).orEmpty()
                (HoconSupport.parseValue(readAsset("$BuiltinDirectory/$path")).asValueMap()
                    ?: error("profile is not an object"))
                    .also {
                        require((it["schema_version"] as? Number)?.toInt() == 1) {
                            "unsupported profile schema"
                        }
                        require(it["release"] == entry["release"]) {
                            "profile index release mismatch"
                        }
                    }
            }
            val tuningExecution = readExecutionTuning()?.get("execution").asValueMap()
            val routePresets = ProfileConfig.Routes
                .mapNotNull { route -> readExecutionRoute(route)?.let { route to it } }
                .toMap()
            Resolution(
                ProfileMerger.resolveMerged(
                    deviceRelease = deviceRelease,
                    builtin = builtin,
                    imported = imported,
                    overrides = overrides,
                    tuningExecution = tuningExecution,
                    pair = CpuPairView(pair.primary, pair.consumer),
                    routePresets = routePresets,
                ),
                layers,
            )
        }.getOrElse { Resolution(null, nothing) }
    }

    /**
     * Keys the resolved profile states in its **active route branch** that no
     * wire section declares: settings the profile asks for and the transport
     * cannot deliver. This is the check that would have caught the lock anchor
     * vanishing between the resolved document and the wire. The fallback branch
     * is excluded on purpose — its geometry belongs to another route's section
     * and never crosses the transport either way.
     */
    private fun uncarriedRouteKeys(profile: ValueMap, route: String?): List<String> {
        val release = profile["release"] as? String ?: return emptyList()
        val known = buildNativeDocument(release, profile)?.document?.wireKeys() ?: return emptyList()
        val branch = route?.let { name -> profile["route"].asValueMap()?.get(name).asValueMap() }
            ?: return emptyList()
        return branch.keys.filterIsInstance<String>().filterNot { it in known }.sorted()
    }

    /**
     * Sparse overrides as they apply to a run: the stored map, or null when a
     * different build wrote it (§B.7). Any upgrade, downgrade or reinstall
     * disables the layer; writing from the editor stamps the running build and
     * re-enables it. Nothing is deleted, so the editor and the exported
     * documents still carry the values.
     */
    private fun effectiveOverrides(release: String): ValueMap? {
        val stored = readAdvancedOverride(release)
        if (stored.isEmpty()) return null
        return if (storedOverridesBuild() == buildIdentity) stored else null
    }

    private fun storedOverridesBuild(): String? =
        preferences.getString(PrefOverridesBuildSha, null)?.takeIf { it.isNotEmpty() }

    /**
     * Native decodes one complete `execution.routes` object, while profiles only
     * include the route they use (plus their fallback). Missing groups are
     * filled from the shared `execution-<route>.conf` files.
     */
    private fun fillRouteExecutionDefaults(profile: ValueMap) {
        val presets = ProfileConfig.Routes
            .mapNotNull { route -> readExecutionRoute(route)?.let { route to it } }
            .toMap()
        ProfileMerger.fillRouteExecutionDefaults(profile, presets)
    }

    private fun readExecutionRoute(route: String): ValueMap? = runCatching {
        HoconSupport.parseValue(
            readAsset("$BuiltinDirectory/execution-${route.replace('_', '-')}.conf"),
        ).asValueMap()?.get("execution").asValueMap()?.get("routes").asValueMap()?.get(route).asValueMap()
    }.getOrNull()

    private fun readIndex(): ValueMap? = runCatching {
        HoconSupport.parseValue(readAsset("$BuiltinDirectory/index.conf")).asValueMap()
            ?: error("index.conf is not an object")
    }.getOrNull()

    private fun findProfile(profiles: List<*>?, release: String): ValueMap? =
        profiles.orEmpty().asSequence()
            .mapNotNull { it.asValueMap() }
            .firstOrNull { it["release"] == release }

    private fun readAsset(path: String): String = assetLoader.load(path)

    /** Shared execution tuning every profile includes ("execution-tuning.conf"). */
    private fun readExecutionTuning(): ValueMap? = runCatching {
        HoconSupport.parseValue(readAsset("$BuiltinDirectory/execution-tuning.conf")).asValueMap()
    }.getOrNull()

    /** Creates null placeholders for invalid fields the document does not carry. */
    private fun materializeInvalidPaths(profile: ValueMap, invalidPaths: Set<String>) {
        invalidPaths.forEach { path ->
            val segments = path.split('.')
            var node: ValueMap = profile
            for (index in 0 until segments.size - 1) {
                node = node.mutableChild(segments[index])
            }
            if (!node.containsKey(segments.last())) node[segments.last()] = null
        }
    }

    /** Initialises a switched-to branch with its fields so they can be filled. */
    private fun routeBranchTemplate(route: String): ValueMap {
        val template = valueMapOf()
        RouteBranchFields[route].orEmpty().forEach { template[it] = null }
        return template
    }

    /**
     * After a route/fallback switch only the selected branch survives in the
     * advanced override; edits of the previous branch would otherwise pull the
     * choice back or shadow the new branch's fields.
     */
    private fun pruneOverrideBranches(entry: ValueMap, key: String, keep: String?) {
        val container = if (key == "fallback") {
            entry["fallback"].asValueMap()?.get("route").asValueMap()
        } else {
            entry[key].asValueMap()
        }
        if (container != null) {
            container.keys.toList()
                .filter { it != keep }
                .forEach(container::remove)
            if (container.isEmpty()) {
                if (key == "fallback") {
                    entry["fallback"].asValueMap()?.remove("route")
                } else {
                    entry.remove(key)
                }
            }
        }
        if (key == "fallback") {
            entry["fallback"].asValueMap()?.let { fallback ->
                if (fallback.isEmpty()) entry.remove("fallback")
            }
        }
    }

    // ---- controller model helpers ----

    private fun generalFields(
        profile: ValueMap,
        baseline: ValueMap,
        route: String?,
        fallbackTo: String?,
    ): List<ExecutionFieldValue> {
        fun read(root: ValueMap, path: String): Long? = if (path.startsWith("execution.")) {
            root["execution"].asValueMap()?.getLongAt(path.removePrefix("execution."))
        } else {
            root.getLongAt(path)
        }
        /* Route tuning is appended from the resolved document itself: only the
         * active route's leaves (sorted, so the order is stable), plus the
         * declared fallback's, so the editor never offers another route's
         * knobs. Both route groups are filled into `execution.routes` during
         * resolution, so the keys come straight from the HOCON. */
        val paths = ProfileConfig.GeneralPaths +
            routeTuningPaths(profile, route) +
            routeTuningPaths(profile, fallbackTo?.takeIf { it != "none" && it != route })
        return paths.map { path ->
            val value = read(profile, path) ?: 0L
            ExecutionFieldValue(
                path = path,
                value = value,
                overridden = read(baseline, path)?.let { baselineValue -> value != baselineValue } == true,
            )
        }
    }

    private fun routeTuningPaths(profile: ValueMap, route: String?): List<String> {
        if (route == null || route !in ProfileConfig.Routes) return emptyList()
        val group = profile["execution"].asValueMap()?.get("routes").asValueMap()
            ?.get(route).asValueMap() ?: return emptyList()
        return group.keys.filterIsInstance<String>().sorted()
            .map { "execution.routes.$route.$it" }
    }

    /**
     * Fills every field of the shared geometry and the active route with an
     * explicit `null` when the resolved profile omitted it, so the advanced
     * editor always presents the complete editable surface.
     */
    private fun completeProfileFields(
        profile: ValueMap,
        route: String?,
        fallbackTo: String?,
    ): ValueMap {
        val out = profile.copyValue().asValueMap() ?: return profile
        if (!out.containsKey("kernel_phys_load")) out["kernel_phys_load"] = null
        if (!out.containsKey("kernel_phys_offset")) out["kernel_phys_offset"] = null
        completeSection(out, "task_struct", TaskStructFieldNames)
        completeSection(out, "cred", CredFieldNames)
        completeSection(out, "offset", OffsetFieldNames)
        completeSection(out, "kernelsnitch", KernelsnitchFieldNames)
        route?.let { completeRouteBranch(out["route"].asValueMap(), it) }
        if (fallbackTo != null && fallbackTo != "none") {
            completeRouteBranch(
                out["fallback"].asValueMap()?.get("route").asValueMap(),
                fallbackTo,
            )
        }
        return out
    }

    private fun completeSection(out: ValueMap, section: String, fields: List<String>) {
        val target = out[section].asValueMap() ?: valueMapOf().also { out[section] = it }
        for (field in fields) if (!target.containsKey(field)) target[field] = null
    }

    private fun completeRouteBranch(container: ValueMap?, route: String) {
        val fields = RouteBranchFields[route] ?: return
        val containerMap = container ?: return
        val branch = containerMap[route].asValueMap()
            ?: valueMapOf().also { containerMap[route] = it }
        for (field in fields) if (!branch.containsKey(field)) branch[field] = null
    }

    private fun buildTree(
        node: ValueMap,
        prefix: String,
        baseline: ValueMap,
        override: ValueMap,
    ): List<ProfileFieldNode> {
        val groups = mutableListOf<ProfileFieldNode>()
        val leaves = mutableListOf<ProfileFieldNode>()
        for ((key, value) in node) {
            val path = if (prefix.isEmpty()) key else "$prefix.$key"
            when {
                value is Map<*, *> -> {
                    /* Execution tuning is edited on the general page
                     * (ProfileOverrideScreen / ExecutionEditor), not here. */
                    if (key == "execution") continue
                    val children = buildTree(value.asValueMap() ?: valueMapOf(), path, baseline, override)
                    if (children.isNotEmpty()) {
                        groups += ProfileFieldNode(
                            path = path,
                            name = key,
                            overridden = children.any { it.overridden },
                            children = children,
                        )
                    }
                }

                value is Number -> if (path != "schema_version" && path != "release" &&
                    path != "recommend_shizuku"
                ) {
                    val overrideValue = override.getLongAt(path)
                    leaves += ProfileFieldNode(
                        path = path,
                        name = key,
                        value = value.toLong(),
                        overridden = overrideValue != null &&
                            overrideValue != baseline.getLongAt(path),
                    )
                }

                value == null -> if (path != "schema_version" && path != "release" &&
                    path != "recommend_shizuku"
                ) {
                    leaves += ProfileFieldNode(
                        path = path,
                        name = key,
                        value = null,
                        overridden = override.getValueAt(path) != null,
                    )
                }
            }
        }
        return groups.sortedBy { it.name } + leaves.sortedBy { it.name }
    }

    // ---- persistence ----

    private fun readDebugOverrides(): ValueMap {
        val raw = preferences.getString(PrefDebugProfileOverrides, null) ?: return valueMapOf()
        return runCatching { HoconSupport.parseValue(raw).asValueMap() ?: valueMapOf() }
            .getOrDefault(valueMapOf())
    }

    /** Sparse overrides for [release]: general, route/fallback and advanced. */
    private fun readAdvancedOverride(release: String): ValueMap =
        readDebugOverrides()[release].asValueMap() ?: valueMapOf()

    private fun writeAdvancedOverride(release: String, override: ValueMap) {
        val all = readDebugOverrides()
        if (override.isEmpty()) all.remove(release) else all[release] = override
        preferences.edit {
            putString(PrefDebugProfileOverrides, HoconSupport.render(all))
            /* The stamp is what keeps an override alive across a restart and
             * not across a rebuild: writing one re-enables the layer for the
             * running build (§B.7). Nothing persists `versionCode` — it is
             * always readable from the installed package (§D.14). */
            if (all.isEmpty()) remove(PrefOverridesBuildSha)
            else putString(PrefOverridesBuildSha, buildIdentity)
        }
    }

    /* profile-export: the merged profile also lives as a plain HOCON file in the
     * app-private directory, so an export is a copy, never a re-merge. */
    private fun persistSnapshot(release: String, pair: CpuPair) {
        runCatching {
            val resolved = resolveCurrent(
                release, pair, effectiveOverrides(release), includeImported = true,
            ).profile ?: return
            val exportView = resolved.copyValue().asValueMap() ?: return
            /* Renderer-side completeness: pull in the tuning of the selected
             * route and its fallback, then drop the groups that are not used. */
            fillRouteExecutionDefaults(exportView)
            trimRouteTuning(exportView)
            File(filesDir, snapshotName(release))
                .writeText(HoconSupport.render(exportView), StandardCharsets.UTF_8)
        }.onFailure {
            android.util.Log.e("GhostLock", "persistSnapshot failed for $release", it)
        }
    }

    private fun snapshotName(release: String): String =
        "${release.replace(Regex("[^A-Za-z0-9._-]"), "_")}.conf"

    /** The exported document keeps only the selected route's tuning (+ fallback). */
    private fun trimRouteTuning(profile: ValueMap) {
        val routes = profile["execution"].asValueMap()?.get("routes").asValueMap() ?: return
        val keep = buildSet {
            routeNameOf(profile)?.let(::add)
            fallbackTargetOf(profile)?.takeIf { it != "none" }?.let(::add)
        }
        routes.keys.toList().filter { it !in keep }.forEach(routes::remove)
    }

    internal companion object {
        private const val BuiltinDirectory = "kernel_profiles"
        private val RouteCommonRequired = listOf(
            "offset.init_task", "offset.init_cred", "offset.root_task_group", "offset.selinux_enforcing",
            "task_struct.prio", "task_struct.pi_lock", "task_struct.pi_waiters", "task_struct.pi_blocked_on",
            "task_struct.cred", "task_struct.seccomp",
        )
        /** Full shared-geometry field universes (native `kTask`/`kCred`/`kOffset`). */
        private val TaskStructFieldNames = listOf(
            "prio", "normal_prio", "sched_task_group", "pi_lock", "pi_waiters", "pi_top_task",
            "pi_blocked_on", "pid", "tgid", "atomic_flags", "real_cred", "cred", "comm", "tasks",
            "seccomp",
        )
        private val CredFieldNames = listOf(
            "copy_size", "usage_offset", "usage_value", "caps_offset", "caps_count", "caps_value",
            "ref_count", "ref0_offset", "ref1_offset", "ref2_offset", "ref3_offset",
            "ref0_image", "ref1_image", "ref2_image", "ref3_image",
        )
        private val OffsetFieldNames = listOf(
            "init_task", "init_cred", "empty_zero_page", "root_task_group", "selinux_enforcing",
            "selinux_blob_sizes", "security_hook_heads", "slide_nfulnl_logger", "slide_loggers_0_1",
            "slide_boot_id",
        )
        private val KernelsnitchFieldNames = listOf("collisions", "mm_struct_sz")

        /** Fields each route branch carries, used to seed a switched-to route. */
        private val RouteBranchFields = mapOf(
            "tcp_zerocopy" to listOf("compact_waiter"),
            "select_stack" to listOf("waiter_shift"),
            "multicast_waiter" to listOf(
                "waiter_off", "buffer_size", "task_offset", "lock_offset",
                "compact_waiter",
            ),
        )
        private val RouteMulticastFields = listOf(
            "buffer_size", "task_offset", "lock_offset",
        )
        private const val SizeofU32 = 4L
        private const val SizeofU64 = 8L
        private const val PrefBuiltinRelease = "debug_builtin_release"
        private const val PrefActiveUserProfile = "active_user_profile"
        const val PrefDebugProfileOverrides = "debug_profile_overrides"

        /** Build identity that wrote [PrefDebugProfileOverrides]; §B.7 gate. */
        const val PrefOverridesBuildSha = "debug_profile_overrides_build"
    }
}
