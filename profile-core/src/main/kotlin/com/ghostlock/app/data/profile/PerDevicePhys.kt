package com.ghostlock.app.data.profile

import com.ghostlock.app.data.ValueMap
import com.ghostlock.app.data.asValueMap
import com.ghostlock.app.data.copyValue

/**
 * Resolves the schema-v2 per-device physical pair.
 *
 * A v2 document may write `kernel_phys_load` / `kernel_phys_offset` as maps
 * keyed by a device identity (`{ diting = 2818572288 }`). This selects the
 * entry for the running device, leaving a number in place of each map. The
 * rest of the pipeline therefore sees the same scalar/null shape it always
 * did.
 *
 * A map that names no identity of the running device is a **refusal**, not a
 * null pair: the v2 pair is per-device by construction, and falling back to
 * the native default would run a profile that was never authored for this
 * device. A whole-null field (both keys absent) stays the native default.
 *
 * The caller passes the device identities in priority order. `Build.DEVICE`
 * is normally first, but it is not always the unique codename: on MediaTek
 * mainline builds the system/product partitions are generic and the hardware
 * codename is the vendor device. [resolveFor] therefore tries every candidate
 * and returns the map key that matched, while [resolve] keeps the single
 * identity entry point for callers that already know it.
 *
 * A v1 scalar is still accepted as a legacy all-device value. A map in a v1
 * document, a non-number entry, or two maps naming different devices is a
 * structural error; the caller fails the resolution rather than guessing.
 *
 * One field may be a whole `null` while the other is a map: a sidecar that
 * carries only the load (the common Qualcomm `uefi` case) leaves the offset to
 * the native default. The atomic-key-set rule applies when both fields are
 * maps; a map mixed with a scalar is still rejected.
 */
object PerDevicePhys {
    private val Keys = listOf("kernel_phys_load", "kernel_phys_offset")

    /** The resolved document and the map key that supplied the pair, if any. */
    data class PhysResolution(val document: ValueMap, val device: String?)

    fun resolve(document: ValueMap, device: String?): ValueMap =
        resolveFor(document, listOfNotNull(device)).document

    /**
     * Device-neutral resolution for exporters and model tools: the map is
     * validated and left empty (the native default), never refused. The run
     * path uses [resolveFor], which refuses a map that does not name the
     * running device.
     */
    fun resolveNeutral(document: ValueMap): ValueMap =
        resolveFor(document, emptyList(), requireMatch = false).document

    fun resolveFor(
        document: ValueMap,
        devices: List<String>,
        requireMatch: Boolean = true,
    ): PhysResolution {
        val schema = (document["schema_version"] as? Number)?.toInt()
        if (schema != null && schema !in 1..2) {
            throw IllegalArgumentException("unsupported profile schema $schema")
        }
        val resolved = document.copyValue().asValueMap() ?: ValueMap()
        val maps = Keys.map { key -> key to (resolved[key] as? Map<*, *>) }
        if (maps.all { it.second == null }) return PhysResolution(resolved, null)
        if (schema != 2) {
            throw IllegalArgumentException("per-device physical maps require schema_version = 2")
        }
        val entriesByKey = LinkedHashMap<String, ValueMap>()
        val keySets = mutableListOf<Set<String>>()
        for ((key, rawMap) in maps) {
            if (rawMap == null) {
                /* A whole-null field is the native default; a scalar is not a
                 * per-device value and would silently apply to every device. */
                if (resolved[key] != null) {
                    throw IllegalArgumentException("$key must be a per-device map or null")
                }
                continue
            }
            val entries = rawMap.asValueMap()
                ?: throw IllegalArgumentException("$key is not an object")
            val names = mutableSetOf<String>()
            for ((rawName, rawValue) in entries) {
                val name = rawName
                if (name.isBlank()) throw IllegalArgumentException("$key has an empty device key")
                if (!names.add(name.lowercase())) {
                    throw IllegalArgumentException("$key has duplicate device keys")
                }
                if (rawValue !is Number) {
                    throw IllegalArgumentException("$key.$name is not a number")
                }
            }
            keySets += names
            entriesByKey[key] = entries
        }
        if (entriesByKey.size == Keys.size && keySets[0] != keySets[1]) {
            throw IllegalArgumentException(
                "kernel_phys_load and kernel_phys_offset name different devices",
            )
        }
        val candidates = devices.asSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
        // Take the first candidate present in any map; the other map, when it
        // exists, carries the same key set up to case.
        val matched = candidates.firstNotNullOfOrNull { candidate ->
            entriesByKey.values.asSequence()
                .mapNotNull { entries ->
                    entries.keys.firstOrNull { it.equals(candidate, ignoreCase = true) }
                }
                .firstOrNull()
        }
        /* A v2 map is per-device by construction: when none of this device's
         * identities is named, the profile was not authored for it, and a null
         * pair would silently fall back to the native default. Refuse instead —
         * the merge reports the reason and the run never starts on a guessed
         * pair. */
        if (matched == null) {
            if (requireMatch) {
                val names = devices.map { it.trim() }.filter { it.isNotEmpty() }
                    .distinct().joinToString("/").ifEmpty { "this device" }
                throw IllegalArgumentException(
                    "the profile's kernel_phys_* map does not name $names",
                )
            }
        }
        for ((key, entries) in entriesByKey) {
            val selected = matched?.let { name ->
                entries.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value
            } as? Number
            resolved[key] = selected?.toLong()
        }
        return PhysResolution(resolved, matched)
    }
}
