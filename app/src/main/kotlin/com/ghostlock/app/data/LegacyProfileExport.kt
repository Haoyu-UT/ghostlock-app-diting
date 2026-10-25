package com.ghostlock.app.data

import com.ghostlock.app.domain.model.ProfileConfig

/**
 * Applying a stored legacy override to one document entry, for the one-time
 * cleanup export.
 *
 * Route branches follow the merger's rule: an override naming the *same*
 * branch merges field-wise into it (a null value keeps the document's value —
 * nulls were the editor's "not edited" placeholders), while an override naming
 * a different branch replaces the whole branch, because the old geometry
 * belongs to the old route. Everything else is a deep merge.
 */
internal object LegacyProfileExport {
    fun applyOverride(entry: ValueMap, override: ValueMap) {
        val copy = override.copyValue().asValueMap() ?: return
        LegacyProfileConverter.convertValue(copy)
        copy["route"].asValueMap()?.let { incoming ->
            val incomingName = incoming.keys.firstOrNull { it in ProfileConfig.Routes }
            val current = entry["route"].asValueMap()
            val currentName = current?.keys?.firstOrNull { it in ProfileConfig.Routes }
            if (incomingName != null && incomingName == currentName) {
                val target = current!!.mutableChild(incomingName)
                deepMergeValues(target, incoming[incomingName].asValueMap())
            } else {
                entry["route"] = incoming.copyValue()
            }
            copy.remove("route")
        }
        copy["fallback"].asValueMap()?.let { fallback ->
            deepMergeValues(entry.mutableChild("fallback"), fallback)
            copy.remove("fallback")
        }
        deepMergeValues(entry, copy)
    }
}
