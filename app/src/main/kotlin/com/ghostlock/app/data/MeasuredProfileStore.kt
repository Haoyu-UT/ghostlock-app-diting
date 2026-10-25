package com.ghostlock.app.data

import java.io.File
import java.nio.charset.StandardCharsets

/** One root-measured fact about one kernel. */
internal data class MeasuredFact(
    /** Dotted profile path the fact belongs to (`kernelsnitch.mm_struct_sz`). */
    val key: String,
    val value: Long,
    /** Who measured it: only [MeasuredProfileStore.SourceRootSlabinfo] today. */
    val source: String,
    /** The raw line the value came from, kept so the UI can show its basis. */
    val evidence: String,
    val measuredAt: Long,
)

internal data class MeasuredKernel(
    val release: String,
    val updatedAt: Long,
    val facts: List<MeasuredFact>,
) {
    fun fact(key: String): MeasuredFact? = facts.firstOrNull { it.key == key }
}

/**
 * The measured database: per-kernel ground truth, never behaviour.
 *
 * Written only from the root phase's `/proc/slabinfo` read (the root script
 * leaves `$HOME_DIR/.ghostlock_slabinfo`; the app ingests it after a completed
 * run) and only through [record]. The run path never reads this store — a fact
 * reaches a run only when the user merges it into a profile and selects that
 * document. Format and rationale: `docs/analysis/measured-db-plan.md`.
 */
internal class MeasuredProfileStore(private val file: File) {
    companion object {
        const val SchemaVersion = 1L
        const val SourceRootSlabinfo = "root-slabinfo"
        const val KeyMmStructSz = "kernelsnitch.mm_struct_sz"

        /** Slab sizes this app will believe; a garbled read is refused, not stored. */
        private val PlausibleObjectSize = 64L..65536L
        private val PlausibleObjectsPerSlab = 1L..4096L

        /**
         * Parses the root script's capture:
         *
         * ```
         * # 5.10.236-…
         * mm_struct 1234 1300 960 34 8 : tunables …
         * ```
         *
         * The release must match the running kernel exactly: a stale capture
         * from another boot/kernel is not a fact about this one.
         */
        fun parseSlabinfo(
            expectedRelease: String,
            raw: String,
            now: Long = System.currentTimeMillis(),
        ): MeasuredFact? {
            val lines = raw.lineSequence().map(String::trim).filter(String::isNotEmpty).toList()
            val header = lines.firstOrNull()?.takeIf { it.startsWith("#") } ?: return null
            if (header.removePrefix("#").trim() != expectedRelease) return null
            val line = lines.firstOrNull { it.startsWith("mm_struct ") } ?: return null
            val columns = line.split(Regex("\\s+"))
            /* name active_objs num_objs objsize objperslab pagesperslab */
            if (columns.size < 6) return null
            val objectSize = columns[3].toLongOrNull() ?: return null
            val objectsPerSlab = columns[4].toLongOrNull() ?: return null
            if (objectSize !in PlausibleObjectSize) return null
            if (objectsPerSlab !in PlausibleObjectsPerSlab) return null
            return MeasuredFact(
                key = KeyMmStructSz,
                value = objectSize,
                source = SourceRootSlabinfo,
                evidence = line,
                measuredAt = now,
            )
        }
    }

    private data class Loaded(val kernels: List<MeasuredKernel>, val readable: Boolean)

    /** Per-kernel facts, sorted by release; empty when nothing was measured. */
    @Synchronized
    fun kernels(): List<MeasuredKernel> = load().kernels

    @Synchronized
    fun kernel(release: String): MeasuredKernel? =
        load().kernels.firstOrNull { it.release == release }

    /**
     * Records [fact] for [release], replacing the entry with the same key.
     * Returns false when the existing file cannot be understood — a newer
     * schema is not overwritten with this build's idea of it.
     */
    @Synchronized
    fun record(release: String, fact: MeasuredFact): Boolean {
        if (release.isEmpty() || fact.key.isEmpty()) return false
        val loaded = load()
        if (!loaded.readable) return false
        val kernels = loaded.kernels.toMutableList()
        val index = kernels.indexOfFirst { it.release == release }
        val current = if (index >= 0) kernels[index].facts else emptyList()
        val facts = current.filterNot { it.key == fact.key } + fact
        val updated = MeasuredKernel(release, fact.measuredAt, facts.sortedBy { it.key })
        if (index >= 0) kernels[index] = updated else kernels += updated
        return write(kernels)
    }

    private fun load(): Loaded {
        if (!file.isFile) return Loaded(emptyList(), true)
        val root = runCatching {
            HoconSupport.parseValue(file.readText(StandardCharsets.UTF_8)).asValueMap()
        }.getOrNull() ?: return Loaded(emptyList(), false)
        val schema = (root["schema_version"] as? Number)?.toLong()
        if (schema != SchemaVersion) return Loaded(emptyList(), false)
        val kernels = root["kernels"].asValueList().orEmpty().mapNotNull { raw ->
            val kernel = raw.asValueMap() ?: return@mapNotNull null
            val release = kernel["release"] as? String ?: return@mapNotNull null
            if (release.isEmpty()) return@mapNotNull null
            val updatedAt = (kernel["updated_at"] as? Number)?.toLong() ?: 0L
            val facts = kernel["facts"].asValueList().orEmpty().mapNotNull { factRaw ->
                val fact = factRaw.asValueMap() ?: return@mapNotNull null
                val key = fact["key"] as? String ?: return@mapNotNull null
                val value = (fact["value"] as? Number)?.toLong() ?: return@mapNotNull null
                val source = fact["source"] as? String ?: return@mapNotNull null
                val evidence = fact["evidence"] as? String ?: ""
                val measuredAt = (fact["measured_at"] as? Number)?.toLong() ?: 0L
                if (key.isEmpty() || source.isEmpty()) return@mapNotNull null
                MeasuredFact(key, value, source, evidence, measuredAt)
            }
            MeasuredKernel(release, updatedAt, facts.sortedBy { it.key })
        }.sortedBy { it.release }
        return Loaded(kernels, true)
    }

    private fun write(kernels: List<MeasuredKernel>): Boolean = runCatching {
        val root = linkedMapOf<String, Any?>(
            "schema_version" to SchemaVersion,
            "kernels" to kernels.map { kernel ->
                linkedMapOf<String, Any?>(
                    "release" to kernel.release,
                    "updated_at" to kernel.updatedAt,
                    "facts" to kernel.facts.map { fact ->
                        linkedMapOf<String, Any?>(
                            "key" to fact.key,
                            "value" to fact.value,
                            "source" to fact.source,
                            "evidence" to fact.evidence,
                            "measured_at" to fact.measuredAt,
                        )
                    },
                )
            },
        )
        val directory = file.parentFile ?: return@runCatching false
        if (!directory.isDirectory && !directory.mkdirs()) return@runCatching false
        val temp = File(directory, "${file.name}.new")
        temp.writeText(HoconSupport.render(root), StandardCharsets.UTF_8)
        if (!temp.renameTo(file)) {
            temp.delete()
            return@runCatching false
        }
        true
    }.getOrDefault(false)
}
