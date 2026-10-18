package com.ghostlock.app.data.route

/** The anchor keys are here because a document never merges another route's section. */
data class SigreturnConfig(
    val waiterOffSve: ULong?,
    val waiterOffPlain: ULong?,
    val lockAnchorImage: ULong? = null,
    val lockAnchorBytes: ULong? = null,
    val lockAnchorStride: ULong? = null,
) : RouteConfig {
    override fun entries(): List<Pair<String, ULong>> = buildList {
        waiterOffSve?.let { add("waiter_off_sve" to it) }
        waiterOffPlain?.let { add("waiter_off_plain" to it) }
        lockAnchorImage?.let { add("lock_anchor_image" to it) }
        lockAnchorBytes?.let { add("lock_anchor_bytes" to it) }
        lockAnchorStride?.let { add("lock_anchor_stride" to it) }
    }

    override fun apply(key: String, value: ULong): RouteConfig = when (key) {
        "waiter_off_sve" -> copy(waiterOffSve = value)
        "waiter_off_plain" -> copy(waiterOffPlain = value)
        "lock_anchor_image" -> copy(lockAnchorImage = value)
        "lock_anchor_bytes" -> copy(lockAnchorBytes = value)
        "lock_anchor_stride" -> copy(lockAnchorStride = value)
        else -> this
    }

    companion object {
        val EMPTY = SigreturnConfig(null, null)

        fun from(value: (String) -> Long?): SigreturnConfig = SigreturnConfig(
            waiterOffSve = value("sig.waiter_off_sve")?.toULong(),
            waiterOffPlain = value("sig.waiter_off_plain")?.toULong(),
            lockAnchorImage = value("lock_anchor_image")?.toULong(),
            lockAnchorBytes = value("lock_anchor_bytes")?.toULong(),
            lockAnchorStride = value("lock_anchor_stride")?.toULong(),
        )
    }
}
