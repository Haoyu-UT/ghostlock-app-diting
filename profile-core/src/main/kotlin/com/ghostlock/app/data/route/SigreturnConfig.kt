package com.ghostlock.app.data.route

/**
 * `route.sigreturn` section. Mirrors native `SigreturnLayout`.
 *
 * The two offsets are the route's geometry: where waiter byte 0 sits inside the
 * 0x200 bytes `rt_sigreturn` copies out of a signal frame's fpsimd record, one
 * per restore helper (SVE copies at sp+0x10, plain at sp+0x00). Both are
 * per-build values derived as `waiter_off = chain_sum - dst_offset -
 * waiter_depth`; absence makes the native route refuse at prepare() rather than
 * stamp at an unverified depth.
 *
 * The lock-anchor keys are the same three the select route carries. The anchor
 * region is one shared kernel object and a document never merges another
 * route's section, so a profile that selects this route has to be able to state
 * it here.
 */
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

    /** Mirrors native `kRouteSigreturn`; the order is not significant. */
    override fun keys(): List<String> = SchemaKeys

    override fun apply(key: String, value: ULong): RouteConfig = when (key) {
        "waiter_off_sve" -> copy(waiterOffSve = value)
        "waiter_off_plain" -> copy(waiterOffPlain = value)
        "lock_anchor_image" -> copy(lockAnchorImage = value)
        "lock_anchor_bytes" -> copy(lockAnchorBytes = value)
        "lock_anchor_stride" -> copy(lockAnchorStride = value)
        else -> this
    }

    companion object {
        private val SchemaKeys = listOf(
            "waiter_off_sve", "waiter_off_plain", "lock_anchor_image", "lock_anchor_bytes",
            "lock_anchor_stride",
        )

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
