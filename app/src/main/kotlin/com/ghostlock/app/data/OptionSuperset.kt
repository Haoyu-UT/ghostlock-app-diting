package com.ghostlock.app.data

/**
 * The extractor's `--options-out` document: every route, anchor candidate and
 * page-free plan for one image, plus the common profile blocks. One parse
 * produces it; a runnable profile is a **cut** of it.
 *
 * The extractor omits nothing. The UI applies the display rules over the full
 * list ([RoutePlans.safeOptions] / [RoutePlans.conditionalOptions]): a single
 * safe option is taken automatically, several safe options are offered without
 * a page row, and page is offered only when no safe option exists.
 */
data class OptionAnchor(
    val image: Long,
    val bytes: Long,
    val stride: Long,
)

data class OptionScratch(
    val image: Long,
    val window: Long,
    val reservedFirst: Long?,
    val reservedLast: Long?,
) {
    /** The window lies inside the anchor region and reserves lock slots. */
    val inAnchor: Boolean get() = reservedFirst != null
}

/** The `scratchSource` spelling for a scratch inside the anchor's own region. */
const val ScratchInAnchor = "in-anchor"

data class OptionPlan(
    val route: String,
    val anchor: OptionAnchor?,
    val scratch: OptionScratch?,
    val pageFree: Boolean,
    val conditioned: Boolean,
    val anchorName: String?,
    val scratchSource: String?,
    val reason: String,
) {
    /** A short technical label (logs and tests): the anchor region and, when it
     * is not in-anchor, the scratch region. */
    val label: String
        get() {
            val anchor = anchorName ?: "page"
            val scratch = scratchSource?.takeIf { it != ScratchInAnchor }
            return if (scratch == null) anchor else "$anchor + $scratch"
        }
}

data class OptionRoute(
    val route: String,
    val verdict: String,
    val reason: String,
    val anchorCapable: Boolean,
    val geometry: Map<String, Long>,
)

data class RoutePlans(
    val route: String,
    val page: OptionPlan,
    /** The safe anchor with a page W1, when no page-free plan is selected. */
    val anchorOnly: OptionPlan?,
    /** Every page-free plan: safe first, then conditioned. */
    val pageFree: List<OptionPlan>,
) {
    /** Options the UI may auto-take or offer; page is not shown when non-empty. */
    val safeOptions: List<OptionPlan>
        get() = pageFree.filter { !it.conditioned }

    /** The needs-review options, offered only when no safe option exists. */
    val conditionalOptions: List<OptionPlan>
        get() = pageFree.filter { it.conditioned }
}

/** The UI's display rule over the full option list (operator decision). */
sealed interface OptionDecision {
    /** Exactly one safe page-free option: take it without asking. */
    data class Auto(val plan: OptionPlan) : OptionDecision

    /** Offer these plans. When [pageOffered] is true the UI adds a page row. */
    data class Offer(val options: List<OptionPlan>, val pageOffered: Boolean) : OptionDecision

    /** Nothing page-free; the page-based path (and the lock-source choice). */
    data object NoPageFree : OptionDecision
}

fun RoutePlans.decision(): OptionDecision = when {
    safeOptions.size == 1 -> OptionDecision.Auto(safeOptions.single())
    safeOptions.isNotEmpty() -> OptionDecision.Offer(safeOptions, pageOffered = false)
    conditionalOptions.isNotEmpty() -> OptionDecision.Offer(conditionalOptions, pageOffered = true)
    else -> OptionDecision.NoPageFree
}

data class OptionSuperset(
    val release: String,
    val kernelMajor: Int?,
    val physLoad: Long?,
    val physOffset: Long?,
    val physSource: String,
    val routes: List<OptionRoute>,
    val plans: List<RoutePlans>,
    /** `profile[block][key]` from the route-less common render; values keep
     * their HOCON spelling (`"null"`, quoted strings, decimals). */
    val profile: Map<String, Map<String, String>>,
) {
    fun route(name: String): OptionRoute? = routes.firstOrNull { it.route == name }

    fun plansFor(name: String): RoutePlans? = plans.firstOrNull { it.route == name }

    /**
     * Materialize a runnable profile: the common blocks (rendered once by the
     * extractor) plus the selected route, anchor and scratch. No derivation
     * happens here.
     */
    fun cut(route: String, plan: OptionPlan): String? {
        val routeOption = routes.firstOrNull { it.route == route && it.verdict == Feasible }
            ?: return null
        val top = profile[""] ?: return null
        val document = linkedMapOf<String, Any?>()
        for (key in TopLevelKeys) {
            top[key]?.let { document[key] = literal(it) }
        }
        val block = linkedMapOf<String, Any?>()
        routeOption.geometry.forEach { (key, value) -> block[key] = value }
        plan.anchor?.let { anchor ->
            block["lock_anchor_image"] = anchor.image
            block["lock_anchor_bytes"] = anchor.bytes
            block["lock_anchor_stride"] = anchor.stride
        }
        document["route"] = linkedMapOf(route to block)
        profile["fallback"]?.let { fallback ->
            document["fallback"] = fallback.mapValues { literal(it.value) }
        }
        profile["selinux"]?.let { selinux ->
            document["selinux"] = selinux.mapValues { literal(it.value) }
        }
        plan.scratch?.let { scratch ->
            document["w1_scratch"] = linkedMapOf<String, Any?>("image" to scratch.image)
        }
        for (name in CommonBlocks) {
            profile[name]?.let { entries ->
                document[name] = entries.mapValues { literal(it.value) }
            }
        }
        return HoconSupport.render(document) + "\n"
    }

    companion object {
        const val Feasible = "feasible"

        private val TopLevelKeys = listOf(
            "release",
            "schema_version",
            "kernel_major",
            "recommend_shizuku",
            "kernel_phys_load",
            "kernel_phys_offset",
        )

        private val CommonBlocks = listOf(
            "kernelsnitch",
            "task_struct",
            "cred",
            "offset",
            "waiter_layout",
        )

        fun parse(text: String): OptionSuperset? = runCatching {
            val root = HoconSupport.parseValue(text).asValueMap() ?: return@runCatching null
            val profile = (root["profile"].asValueMap() ?: return@runCatching null)
                .mapValues { (_, block) ->
                    block.asValueMap().orEmpty()
                        .mapValues { (_, value) -> value?.toString() ?: "null" }
                }
            val routes = root["routes"].asValueList().orEmpty().mapNotNull { entry ->
                val map = entry.asValueMap() ?: return@mapNotNull null
                val route = map["route"] as? String ?: return@mapNotNull null
                OptionRoute(
                    route = route,
                    verdict = map["verdict"] as? String ?: "",
                    reason = map["reason"] as? String ?: "",
                    anchorCapable = map["anchor_capable"] as? Boolean ?: false,
                    geometry = map["geometry"].asValueMap().orEmpty()
                        .mapNotNull { (key, value) ->
                            (value as? Number)?.let { key to it.toLong() }
                        }
                        .toMap(),
                )
            }
            val plans = root["plans"].asValueList().orEmpty().mapNotNull { entry ->
                val map = entry.asValueMap() ?: return@mapNotNull null
                val route = map["route"] as? String ?: return@mapNotNull null
                val page = plan(map["page"]) ?: return@mapNotNull null
                RoutePlans(
                    route = route,
                    page = page,
                    anchorOnly = plan(map["anchor_only"]),
                    pageFree = map["page_free"].asValueList().orEmpty()
                        .mapNotNull { plan(it) },
                )
            }
            OptionSuperset(
                release = root["release"] as? String ?: return@runCatching null,
                kernelMajor = (root["kernel_major"] as? Number)?.toInt(),
                physLoad = (root["kernel_phys_load"] as? Number)?.toLong(),
                physOffset = (root["kernel_phys_offset"] as? Number)?.toLong(),
                physSource = root["phys_source"] as? String ?: "unset",
                routes = routes,
                plans = plans,
                profile = profile,
            )
        }.getOrNull()

        private fun plan(value: Any?): OptionPlan? {
            val map = value.asValueMap() ?: return null
            return OptionPlan(
                route = map["route"] as? String ?: return null,
                anchor = map["anchor"].asValueMap()?.let { anchor ->
                    OptionAnchor(
                        image = (anchor["image"] as? Number)?.toLong() ?: return@let null,
                        bytes = (anchor["bytes"] as? Number)?.toLong() ?: return@let null,
                        stride = (anchor["stride"] as? Number)?.toLong() ?: return@let null,
                    )
                },
                scratch = map["scratch"].asValueMap()?.let { scratch ->
                    OptionScratch(
                        image = (scratch["image"] as? Number)?.toLong() ?: return@let null,
                        window = (scratch["window"] as? Number)?.toLong() ?: 0,
                        reservedFirst = (scratch["reserved_first"] as? Number)?.toLong(),
                        reservedLast = (scratch["reserved_last"] as? Number)?.toLong(),
                    )
                },
                pageFree = map["page_free"] as? Boolean ?: false,
                conditioned = map["conditioned"] as? Boolean ?: false,
                anchorName = map["anchor_name"] as? String,
                scratchSource = map["scratch_source"] as? String,
                reason = map["reason"] as? String ?: "",
            )
        }

        /** Turn a rendered-profile value back into a HOCON literal. */
        private fun literal(value: String): Any? = when {
            value == "null" -> null
            value.length >= 2 && value.startsWith("\"") && value.endsWith("\"") ->
                value.substring(1, value.length - 1)
            value.toLongOrNull() != null -> value.toLong()
            else -> value
        }
    }
}
