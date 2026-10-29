package com.ghostlock.app.data

/**
 * Removes the lock-anchor triple from a generated profile so the route falls
 * back to the reclaimed payload page. This is the user's "page" choice at
 * profile generation; the rest of the document is unchanged.
 *
 * Every route branch is cleaned (the selected route and the fallback), so a
 * triple cannot survive under a branch the native later switches to.
 */
internal fun stripLockAnchor(documentText: String): String? {
    val entries = ProfileDocumentParser.entries(documentText) ?: return null
    for (entry in entries) {
        stripAnchorFromBranches(entry["route"])
        val fallback = entry["fallback"]
        if (fallback is Map<*, *>) {
            stripAnchorFromBranches(fallback["route"])
        }
    }
    return HoconSupport.render(if (entries.size == 1) entries.first() else entries)
}

private fun stripAnchorFromBranches(branches: Any?) {
    val map = branches as? Map<*, *> ?: return
    for (branch in map.values) {
        @Suppress("UNCHECKED_CAST")
        val route = branch as? MutableMap<String, Any?> ?: continue
        route.remove("lock_anchor_image")
        route.remove("lock_anchor_bytes")
        route.remove("lock_anchor_stride")
    }
}
