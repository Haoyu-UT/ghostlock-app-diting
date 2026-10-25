package com.ghostlock.app.data

/**
 * Where the sparse edit map of one resolution comes from.
 *
 * The live attack controller always gets [EmptyOverrideStore]: since the
 * measured-db model there is no persisted override layer at all (an override
 * written by an old build is legacy data the cleanup flow exports, never
 * applies). An editor session gets its own [MemoryOverrideStore], which lives
 * exactly as long as the session and is lost with it — exporting a document is
 * the only save (measured-db-plan §4).
 */
internal interface OverrideStore {
    fun read(release: String): ValueMap
    fun write(release: String, override: ValueMap)
}

internal object EmptyOverrideStore : OverrideStore {
    override fun read(release: String): ValueMap = valueMapOf()
    override fun write(release: String, override: ValueMap) = Unit
}

internal class MemoryOverrideStore : OverrideStore {
    private val entries = linkedMapOf<String, ValueMap>()

    @Synchronized
    override fun read(release: String): ValueMap =
        entries[release]?.copyValue()?.asValueMap() ?: valueMapOf()

    @Synchronized
    override fun write(release: String, override: ValueMap) {
        if (override.isEmpty()) {
            entries.remove(release)
        } else {
            entries[release] = override.copyValue().asValueMap() ?: valueMapOf()
        }
    }
}

/** One resolution source, in precedence order (external > builtin > bundled). */
internal sealed interface ProfileSelection {
    data class Bundled(val release: String) : ProfileSelection
    data class Builtin(val release: String) : ProfileSelection
    data class External(
        val uri: String,
        val name: String,
        val release: String,
        val sha256: String,
        val parent: String? = null,
        val parentSha256: String? = null,
    ) : ProfileSelection
}
