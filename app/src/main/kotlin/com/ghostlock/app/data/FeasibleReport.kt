package com.ghostlock.app.data

import com.ghostlock.app.domain.model.RouteVerdict

/**
 * The extractor's `--feasible-out` report: every 5.10 route's verdict plus the
 * route that pass chose (null when the routes are ambiguous).
 *
 * Parsed with [HoconSupport] because JSON is a subset of HOCON, so this is a
 * pure-JVM unit and the app needs no second parser.
 */
internal data class FeasibleReport(
    val release: String,
    val routes: List<RouteVerdict>,
    val chosen: String?,
) {
    val feasible: List<RouteVerdict>
        get() = routes.filter { it.verdict == VerdictFeasible }

    companion object {
        const val VerdictFeasible = "feasible"

        fun parse(text: String): FeasibleReport? = runCatching {
            val root = HoconSupport.parseValue(text).asValueMap() ?: return@runCatching null
            if (root.isEmpty()) return@runCatching null
            val routes = root["routes"].asValueList().orEmpty().mapNotNull { entry ->
                val map = entry.asValueMap() ?: return@mapNotNull null
                val route = map["route"] as? String ?: return@mapNotNull null
                val verdict = map["verdict"] as? String ?: return@mapNotNull null
                RouteVerdict(
                    route = route,
                    verdict = verdict,
                    reason = map["reason"] as? String ?: "",
                    numbers = map["numbers"].asValueMap().orEmpty().mapNotNull { (key, value) ->
                        (value as? Number)?.let { key to it.toLong() }
                    }.toMap(),
                )
            }
            FeasibleReport(
                release = root["release"] as? String ?: "",
                routes = routes,
                chosen = root["chosen"] as? String,
            )
        }.getOrNull()
    }
}
