package com.ghostlock.app.data

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import androidx.core.content.edit
import com.ghostlock.app.BuildConfig
import com.ghostlock.app.data.profile.CpuPairView
import com.ghostlock.app.data.profile.ProfileMerger
import com.ghostlock.app.data.profile.ProfileResolver
import com.ghostlock.app.data.route.RouteKind
import com.ghostlock.app.domain.model.CpuPair
import com.ghostlock.app.domain.model.ExecutionFieldValue
import com.ghostlock.app.domain.model.ExternalProfileInfo
import com.ghostlock.app.domain.model.ProfileConfig
import com.ghostlock.app.domain.model.ProfileDiffRow
import com.ghostlock.app.domain.model.ProfileFieldNode
import com.ghostlock.app.domain.model.ProfileLayers
import com.ghostlock.app.domain.repository.ProfileConfigController

/**
 * Controller-centered profile architecture, measured-db model (2026-10-25).
 *
 * A profile is a **document**: a bundled asset, a hand-picked builtin asset, or
 * an external file the user selected through SAF. App data holds only the
 * reference to the external selection; there is no imported copy and no
 * persisted override layer. Resolution order is external > builtin > bundled.
 *
 * Live runs resolve the selection with no sparse edits. An editor session gets
 * a private [MemoryOverrideStore] and a pinned [ProfileSelection]; its edits
 * live only as long as the session, and rendering an exported document is its
 * only save. See `docs/analysis/measured-db-plan.md`.
 */
internal class AndroidProfileConfigController(
    context: Context,
    private val externalProfiles: ExternalProfileStore,
    private val preferences: SharedPreferences,
    private val buildIdentity: String = BuildConfig.BUILD_IDENTITY,
    /**
     * Device codename for the device-tuning preset. The measured route timing
     * is a property of this phone, not of the kernel image, so a generated
     * profile must not carry it; the app merges it here instead. Injectable so
     * the host tests can pin it.
     */
    private val deviceCodename: String? = Build.DEVICE,
    /** Live runs: empty. Editor sessions: their private in-memory map. */
    private val overrideStore: OverrideStore = EmptyOverrideStore,
    /** Pins the source for an editor session; null follows the stored choice. */
    forcedSelection: ProfileSelection? = null,
) : ProfileConfigController {
    private val appContext = context.applicationContext
    private val assetLoader = AssetConfigLoader(appContext)
    private val lock = Any()
    private var forcedSelection: ProfileSelection? = forcedSelection

    override suspend fun load(release: String, pair: CpuPair): ProfileConfig {
        val overrides = activeOverrides(release)
        val resolution = resolve(release, pair, overrides)
        val full = resolution.profile
        if (full == null) {
            return ProfileConfig(
                release = release,
                hasProfile = false,
                pair = pair,
                layers = resolution.layers,
            )
        }
        val route = routeNameOf(full)
        val fallbackTo = fallbackTargetOf(full)
        val invalidPaths = validateProfileFields(full, route, fallbackTo) +
            ProfileResolver.validateMerged(full, route, fallbackTo)
                .mapTo(mutableSetOf()) { it.fieldPath }
        /* Invalid fields missing from the resolved document still get a row,
         * otherwise the run stays blocked with no red field to fix. */
        materializeInvalidPaths(full, invalidPaths)
        /* The editor shows every field of the active route plus the shared
         * geometry, so a field the profile did not carry appears as an
         * editable `null` row instead of being invisible. */
        val complete = completeProfileFields(full, route, fallbackTo)
        val baseline = if (overrides == null) {
            full
        } else {
            resolve(release, pair, null).profile ?: full
        }
        val roots = buildTree(complete, "", baseline, overrides ?: valueMapOf())
        return ProfileConfig(
            release = release,
            hasProfile = true,
            pair = pair,
            layers = resolution.layers.copy(
                uncarriedKeys = uncarriedRouteKeys(full, route),
            ),
            roots = roots,
            general = generalFields(full, baseline, route, fallbackTo),
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

        val stride = value("kernelsnitch.mm_struct_sz")
        if (stride != null && (stride < MinSlabStride || stride > MaxSlabStride)) {
            invalid += "kernelsnitch.mm_struct_sz"
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
                /* The AArch32 compat carrier places the stamp from the
                 * measured geometry (waiter_home / select_dst_depth), not from
                 * the 64-bit fd_set word shift; a compat profile legitimately
                 * omits waiter_shift and must state both depths instead. */
                val compat = value("$routePrefix.compat_carrier") ?: 0L
                if (compat != 0L) {
                    for (field in listOf("waiter_home", "select_dst_depth")) {
                        val current = value("$routePrefix.$field")
                        if (current == null || current <= 0L ||
                            current > UInt.MAX_VALUE.toLong()
                        ) {
                            invalid += "$routePrefix.$field"
                        }
                    }
                } else {
                    val shift = value("$routePrefix.waiter_shift")
                    if (shift == null ||
                        shift < Int.MIN_VALUE.toLong() || shift > Int.MAX_VALUE.toLong()
                    ) {
                        invalid += "$routePrefix.waiter_shift"
                    }
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
        val override = overrideStore.read(release)
        if (route.isNullOrBlank()) {
            override.remove("route")
        } else {
            val existingBranch = override["route"].asValueMap()?.get(route).asValueMap()
                ?: routeBranchTemplate(route)
            override["route"] = valueMapOf(route to existingBranch)
            pruneOverrideBranches(override, "route", route)
        }
        overrideStore.write(release, override)
        return load(release, pair)
    }

    override suspend fun updateFallback(
        release: String,
        pair: CpuPair,
        fallbackTo: String?,
    ): ProfileConfig {
        val override = overrideStore.read(release)
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
        overrideStore.write(release, override)
        return load(release, pair)
    }

    override suspend fun updateGeneral(
        release: String,
        pair: CpuPair,
        values: Map<String, Long>,
    ): ProfileConfig {
        val override = overrideStore.read(release)
        val execution = override.mutableChild("execution")
        for ((path, value) in values) {
            if (path.startsWith("execution.")) {
                execution.setValueAt(path.removePrefix("execution."), value)
            } else {
                override.setValueAt(path, value)
            }
        }
        overrideStore.write(release, override)
        return load(release, pair)
    }

    override suspend fun updateAdvanced(
        release: String,
        pair: CpuPair,
        values: Map<String, Long>,
    ): ProfileConfig {
        /* Rebuild the sparse map from scratch: only values that differ from
         * the base survive, so untouched fields can never stay highlighted. */
        val baseline = resolve(release, pair, null).profile
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
            val current = overrideStore.read(release)
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
            overrideStore.write(release, rebuilt)
        }
        return load(release, pair)
    }

    override suspend fun reset(release: String, pair: CpuPair): ProfileConfig {
        overrideStore.write(release, valueMapOf())
        return load(release, pair)
    }

    override suspend fun resetGeneral(release: String, pair: CpuPair): ProfileConfig {
        val override = overrideStore.read(release)
        override.remove("execution")
        overrideStore.write(release, override)
        return load(release, pair)
    }

    override suspend fun resetAdvanced(release: String, pair: CpuPair): ProfileConfig {
        val override = overrideStore.read(release)
        override.keys.toList().filter { it != "execution" }.forEach(override::remove)
        overrideStore.write(release, override)
        return load(release, pair)
    }

    override suspend fun clearSelectedCpus(release: String, pair: CpuPair): ProfileConfig {
        val override = overrideStore.read(release)
        val execution = override["execution"].asValueMap()
        execution?.remove("selected_cpus")
        if (execution != null && execution.isEmpty()) override.remove("execution")
        overrideStore.write(release, override)
        return load(release, pair)
    }

    /**
     * Renders the resolved profile as the document an export writes. The
     * caller adds the lineage header and the user picks the destination; this
     * class never writes a profile into app data.
     */
    override fun renderResolved(release: String, pair: CpuPair): String? =
        renderMerged(release, pair, emptyMap())

    /**
     * [extraValues] are facts applied to the resolved document — the measured
     * database's merge path. They are validated with everything else, so a bad
     * fact cannot produce an exportable profile.
     */
    fun renderMerged(
        release: String,
        pair: CpuPair,
        extraValues: Map<String, Long>,
    ): String? {
        val resolved = resolve(release, pair, activeOverrides(release)).profile ?: return null
        val view = resolved.copyValue().asValueMap() ?: return null
        for ((path, value) in extraValues) view.setValueAt(path, value)
        val route = routeNameOf(view)
        val fallbackTo = fallbackTargetOf(view)
        val invalid = validateProfileFields(view, route, fallbackTo) +
            ProfileResolver.validateMerged(view, route, fallbackTo).map { it.fieldPath }
        if (invalid.isNotEmpty()) return null
        view["schema_version"] = 1
        view["release"] = release
        /* The CPU choice follows the device pair, it must not be frozen here. */
        view["execution"].asValueMap()?.remove("selected_cpus")
        fillRouteExecutionDefaults(view)
        trimRouteTuning(view)
        return HoconSupport.render(view)
    }

    /** Renders the resolved profile verbatim (no trimming) for debug dumps. */
    override fun renderResolvedForDebug(release: String, pair: CpuPair): String? {
        val resolved = resolve(release, pair, activeOverrides(release)).profile ?: return null
        val view = resolved.copyValue().asValueMap() ?: return null
        return HoconSupport.render(view)
    }

    /** Numeric leaves of the resolved profile, the measured merge's comparison. */
    fun resolvedNumbers(release: String, pair: CpuPair): Map<String, Long>? {
        val resolved = resolve(release, pair, activeOverrides(release)).profile ?: return null
        return numericLeaves(resolved)
    }

    /** Values of [release]'s active profile that differ from the bundle. */
    override fun diffAgainstBundle(release: String, pair: CpuPair): List<ProfileDiffRow> {
        val current = resolve(release, pair, activeOverrides(release)).profile ?: return emptyList()
        val bundled = resolveFor(
            release, pair, null, ProfileSelection.Bundled(release),
        ).profile ?: return emptyList()
        return numericDiff(current, bundled)
    }

    /** Moves the session's base to the bundled document, keeping its edits. */
    override suspend fun rebaseToBundle(release: String, pair: CpuPair): ProfileConfig {
        if (forcedSelection != null) forcedSelection = ProfileSelection.Bundled(release)
        return load(release, pair)
    }

    /** The selection a resolution of [release] would use right now. */
    fun currentSelection(release: String): ProfileSelection? =
        forcedSelection ?: liveSelection(release)

    /** Test seam: the session's in-memory edit map; never persisted. */
    internal fun overrideSnapshot(release: String): ValueMap = overrideStore.read(release)

    /** Human label of the source, for the editor banner. */
    fun currentSelectionLabel(release: String): String? = when (val source = currentSelection(release)) {
        is ProfileSelection.External -> source.name
        is ProfileSelection.Builtin -> source.release
        is ProfileSelection.Bundled -> source.release
        null -> null
    }

    /**
     * Builds the native document from an in-memory profile text (the generator's
     * output before it is exported). Nothing is stored: the probe needs the
     * document, not a saved copy.
     */
    fun nativeDocumentFor(text: String, release: String, pair: CpuPair): ByteArray? {
        val entry = ProfileDocumentParser.entryForRelease(text, release, ::loadBundledInclude)
            ?: return null
        val merged = runCatching { merge(release, pair, entry, null) }.getOrNull() ?: return null
        val route = routeNameOf(merged)
        val fallbackTo = fallbackTargetOf(merged)
        val invalid = validateProfileFields(merged, route, fallbackTo) +
            ProfileResolver.validateMerged(merged, route, fallbackTo).map { it.fieldPath }
        if (invalid.isNotEmpty()) return null
        return buildNativeDocument(release, merged)?.toBinary()
    }

    override suspend fun builtinReleases(): List<String> {
        val index = readIndex() ?: return emptyList()
        val profiles = index["profiles"].asValueList() ?: return emptyList()
        return profiles
            .mapNotNull { entry -> (entry.asValueMap()?.get("release") as? String) }
            .filter { it.isNotEmpty() }
            .sorted()
    }

    override fun activeBuiltinRelease(): String? {
        forcedSelection?.let { return (it as? ProfileSelection.Builtin)?.release }
        return preferences.getString(PrefBuiltinRelease, null)?.takeIf { it.isNotEmpty() }
    }

    override fun activeExternalProfile(): ExternalProfileInfo? {
        val external = (forcedSelection ?: storedExternalSelection()) as? ProfileSelection.External
            ?: return null
        return ExternalProfileInfo(
            name = external.name,
            release = external.release,
            sha256 = external.sha256,
            parent = external.parent,
        )
    }

    /**
     * Selects [uri] as the external profile for [deviceRelease]. The document
     * must parse and carry that release, or nothing is stored. The selection
     * wins over the bundled asset; a hand-picked builtin is cleared because the
     * last explicit choice wins.
     */
    override suspend fun selectExternalProfile(
        uri: String,
        deviceRelease: String,
        pair: CpuPair,
    ): ProfileConfig? {
        val text = externalProfiles.read(uri) ?: return null
        ProfileDocumentParser.entryForRelease(text, deviceRelease, ::loadBundledInclude) ?: return null
        externalProfiles.persistReadPermission(uri)
        val parent = ProfileLineage.parse(text)
        preferences.edit {
            putString(PrefExternalUri, uri)
            putString(PrefExternalName, externalProfiles.displayName(uri))
            putString(PrefExternalRelease, deviceRelease)
            putString(PrefExternalSha256, sha256Of(text))
            if (parent == null) {
                remove(PrefExternalParent)
                remove(PrefExternalParentSha256)
            } else {
                putString(PrefExternalParent, parent.label)
                if (parent.sha256 == null) remove(PrefExternalParentSha256)
                else putString(PrefExternalParentSha256, parent.sha256)
            }
            remove(PrefBuiltinRelease)
        }
        forcedSelection = null
        return load(deviceRelease, pair)
    }

    override suspend fun clearExternalProfile(deviceRelease: String, pair: CpuPair): ProfileConfig {
        preferences.edit {
            remove(PrefExternalUri)
            remove(PrefExternalName)
            remove(PrefExternalRelease)
            remove(PrefExternalSha256)
            remove(PrefExternalParent)
            remove(PrefExternalParentSha256)
        }
        forcedSelection = null
        return load(deviceRelease, pair)
    }

    override suspend fun selectBuiltin(
        release: String?,
        deviceRelease: String,
        pair: CpuPair,
    ): ProfileConfig {
        preferences.edit {
            if (release.isNullOrBlank()) remove(PrefBuiltinRelease)
            else putString(PrefBuiltinRelease, release)
            /* An explicit builtin choice is a choice; the stored external
             * reference would otherwise silently outrank it. */
            remove(PrefExternalUri)
            remove(PrefExternalName)
            remove(PrefExternalRelease)
            remove(PrefExternalSha256)
            remove(PrefExternalParent)
            remove(PrefExternalParentSha256)
        }
        forcedSelection = null
        return load(deviceRelease, pair)
    }

    /**
     * Resolved on demand: the result depends on the selection, the CPU pair and
     * the session's edits, so a cached document would go stale.
     */
    override fun nativeDocument(config: ProfileConfig): ByteArray? = synchronized(lock) {
        val resolved = resolve(config.release, config.pair, activeOverrides(config.release)).profile
            ?: return@synchronized null
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

    // ---- resolution ----

    private data class Source(val document: ValueMap?, val error: String?)

    private data class Resolution(
        val profile: ValueMap?,
        val layers: ProfileLayers,
        val selection: ProfileSelection?,
    )

    private fun activeOverrides(release: String): ValueMap? =
        overrideStore.read(release).takeIf { it.isNotEmpty() }

    /** External > builtin > bundled. A stored external selection is the user's
     * statement: it stays the source even when its release names another image,
     * and the identity check then refuses instead of silently using the bundle. */
    private fun liveSelection(release: String): ProfileSelection? {
        val external = storedExternalSelection()
        if (external != null) return external
        val builtin = preferences.getString(PrefBuiltinRelease, null)?.takeIf { it.isNotEmpty() }
        if (builtin != null) return ProfileSelection.Builtin(builtin)
        return if (bundledDocument(release) != null) ProfileSelection.Bundled(release) else null
    }

    private fun storedExternalSelection(): ProfileSelection.External? {
        val uri = preferences.getString(PrefExternalUri, null)?.takeIf { it.isNotEmpty() }
            ?: return null
        val name = preferences.getString(PrefExternalName, null)?.takeIf { it.isNotEmpty() }
            ?: return null
        val release = preferences.getString(PrefExternalRelease, null)?.takeIf { it.isNotEmpty() }
            ?: return null
        val sha = preferences.getString(PrefExternalSha256, null)?.takeIf { it.isNotEmpty() }
            ?: return null
        return ProfileSelection.External(
            uri = uri,
            name = name,
            release = release,
            sha256 = sha,
            parent = preferences.getString(PrefExternalParent, null)?.takeIf { it.isNotEmpty() },
            parentSha256 = preferences.getString(PrefExternalParentSha256, null)
                ?.takeIf { it.isNotEmpty() },
        )
    }

    private fun resolve(release: String, pair: CpuPair, overrides: ValueMap?): Resolution =
        resolveFor(release, pair, overrides, forcedSelection ?: liveSelection(release))

    private fun resolveFor(
        release: String,
        pair: CpuPair,
        overrides: ValueMap?,
        selection: ProfileSelection?,
    ): Resolution {
        val source = loadSource(release, selection)
        val document = source.document
            ?: return Resolution(null, layersFor(selection, source.error), selection)
        val merged = runCatching { merge(release, pair, document, overrides) }
        val layers = layersFor(selection, source.error ?: merged.exceptionOrNull()?.message)
        return Resolution(merged.getOrNull(), layers, selection)
    }

    private fun merge(
        release: String,
        pair: CpuPair,
        document: ValueMap,
        overrides: ValueMap?,
    ): ValueMap {
        val tuningExecution = readExecutionTuning()
        val routePresets = ProfileConfig.Routes
            .mapNotNull { route -> readExecutionRoute(route)?.let { route to it } }
            .toMap()
        return ProfileMerger.resolveMerged(
            deviceRelease = release,
            builtin = document,
            imported = null,
            overrides = overrides,
            tuningExecution = tuningExecution,
            pair = CpuPairView(pair.primary, pair.consumer),
            routePresets = routePresets,
        )
    }

    /** Reads the selected source. An external read failure is an error, never
     * a silent fallback to the bundle: the user's selection is a statement. */
    private fun loadSource(release: String, selection: ProfileSelection?): Source {
        if (selection == null) return Source(null, null)
        return when (selection) {
            is ProfileSelection.Bundled -> {
                val document = bundledDocument(selection.release)
                Source(
                    document,
                    if (document == null) "bundled profile ${selection.release} is unavailable" else null,
                )
            }

            is ProfileSelection.Builtin -> {
                val document = bundledDocument(selection.release)
                Source(
                    document,
                    if (document == null) "built-in profile ${selection.release} is unavailable" else null,
                )
            }

            is ProfileSelection.External -> {
                val text = externalProfiles.read(selection.uri)
                    ?: return Source(null, "cannot read ${selection.name}")
                val document = ProfileDocumentParser.entryForRelease(
                    text, release, ::loadBundledInclude,
                )
                Source(
                    document,
                    if (document == null) "${selection.name} has no entry for $release" else null,
                )
            }
        }
    }

    private fun loadBundledInclude(path: String): String? =
        readAsset("$BuiltinDirectory/$path").takeIf { it.isNotBlank() }

    private fun bundledDocument(release: String): ValueMap? = runCatching {
        val index = readIndex() ?: return null
        require((index["schema_version"] as? Number)?.toInt() == 1) {
            "unsupported profile schema"
        }
        val entry = findProfile(index["profiles"].asValueList(), release) ?: return null
        val path = (entry["file"] as? String).orEmpty()
        val document = HoconSupport.parseValue(readAsset("$BuiltinDirectory/$path")).asValueMap()
            ?: error("profile is not an object")
        require((document["schema_version"] as? Number)?.toInt() == 1) {
            "unsupported profile schema"
        }
        require(document["release"] == entry["release"]) {
            "profile index release mismatch"
        }
        document
    }.getOrNull()

    private fun layersFor(selection: ProfileSelection?, error: String?): ProfileLayers {
        val external = selection as? ProfileSelection.External
        val builtinRelease = when (selection) {
            is ProfileSelection.Bundled -> selection.release
            is ProfileSelection.Builtin -> selection.release
            else -> null
        }
        return ProfileLayers(
            builtinRelease = builtinRelease,
            bundledAuthoritative = selection is ProfileSelection.Bundled,
            builtinSelected = selection is ProfileSelection.Builtin,
            build = buildIdentity,
            external = external?.name,
            externalApplied = external != null && error == null,
            externalUri = external?.uri,
            externalSha256 = external?.sha256,
            externalParent = external?.parent,
            externalError = error,
        )
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

    /** The exported document keeps only the selected route's tuning (+ fallback). */
    private fun trimRouteTuning(profile: ValueMap) {
        val routes = profile["execution"].asValueMap()?.get("routes").asValueMap() ?: return
        val keep = buildSet {
            routeNameOf(profile)?.let(::add)
            fallbackTargetOf(profile)?.takeIf { it != "none" }?.let(::add)
        }
        routes.keys.toList().filter { it !in keep }.forEach(routes::remove)
    }

    private fun readIndex(): ValueMap? = runCatching {
        HoconSupport.parseValue(readAsset("$BuiltinDirectory/index.conf")).asValueMap()
            ?: error("index.conf is not an object")
    }.getOrNull()

    private fun findProfile(profiles: List<*>?, release: String): ValueMap? =
        profiles.orEmpty().asSequence()
            .mapNotNull { it.asValueMap() }
            .firstOrNull { it["release"] == release }

    private fun readAsset(path: String): String = assetLoader.load(path)

    /**
     * Shared execution tuning every profile includes ("execution-tuning.conf"),
     * with the device preset merged under it on a diting. The preset exists
     * because the extractor no longer emits `execution`: a generated profile
     * must still run with the measured 30/10000/5000 values rather than the
     * shared 1000/50000/50000 defaults.
     */
    internal fun readExecutionTuning(): ValueMap? = runCatching {
        val common = HoconSupport.parseValue(readAsset("$BuiltinDirectory/execution-tuning.conf"))
            .asValueMap()?.get("execution").asValueMap()
        val devicePreset = if (isDitingDevice()) {
            HoconSupport.parseValue(readAsset("$BuiltinDirectory/execution-diting.conf"))
                .asValueMap()?.get("execution").asValueMap()
        } else {
            null
        }
        when {
            common == null -> devicePreset
            devicePreset == null -> common
            else -> deepMergeValues(common, devicePreset)
        }
    }.getOrNull()

    /** The measured route timing belongs to this phone, not to a kernel. */
    private fun isDitingDevice(): Boolean =
        deviceCodename.equals("diting", ignoreCase = true)

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
     * sparse edit map; edits of the previous branch would otherwise pull the
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

    // ---- diff helpers ----

    private fun numericDiff(current: ValueMap, bundled: ValueMap): List<ProfileDiffRow> {
        val left = numericLeaves(current)
        val right = numericLeaves(bundled)
        return (left.keys + right.keys).sorted().mapNotNull { path ->
            if (path == "schema_version" || path == "release" || path == "recommend_shizuku") {
                return@mapNotNull null
            }
            val currentValue = left[path]
            val bundledValue = right[path]
            if (currentValue == bundledValue) null
            else ProfileDiffRow(path, currentValue, bundledValue)
        }
    }

    private fun numericLeaves(root: ValueMap): Map<String, Long> {
        val out = linkedMapOf<String, Long>()
        fun walk(prefix: String, node: Map<*, *>) {
            for ((rawKey, value) in node) {
                val key = rawKey.toString()
                val path = if (prefix.isEmpty()) key else "$prefix.$key"
                when (value) {
                    is Map<*, *> -> walk(path, value)
                    is Number -> out[path] = value.toLong()
                }
            }
        }
        walk("", root)
        return out
    }

    // ---- persistence ----

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

        /** Native's spray clamp (`MM_STRUCT_SZ` sanity range in `main.cpp`). */
        private const val MinSlabStride = 64L
        private const val MaxSlabStride = 32768L

        const val PrefBuiltinRelease = "debug_builtin_release"
        const val PrefExternalUri = "external_profile_uri"
        const val PrefExternalName = "external_profile_name"
        const val PrefExternalRelease = "external_profile_release"
        const val PrefExternalSha256 = "external_profile_sha256"
        const val PrefExternalParent = "external_profile_parent"
        const val PrefExternalParentSha256 = "external_profile_parent_sha256"

        /* Legacy storage keys, read only by the one-time cleanup flow. */
        const val PrefDebugProfileOverrides = "debug_profile_overrides"
        const val PrefOverridesBuildSha = "debug_profile_overrides_build"
    }
}
