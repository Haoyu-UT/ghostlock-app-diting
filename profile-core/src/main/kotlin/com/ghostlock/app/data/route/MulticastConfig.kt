package com.ghostlock.app.data.route

/**
 * `route.multicast_waiter` section. Mirrors native `MulticastWaiterLayout`.
 *
 * The lock-anchor keys are the same three the select and sigreturn routes
 * carry. The anchor region is one shared kernel object and a document never
 * merges another route's section, so a profile that selects this route has to
 * be able to state it here (the sigreturn section does the same).
 */
data class MulticastConfig(
    val geometry: MulticastGeometry,
) : RouteConfig {
    override fun entries(): List<Pair<String, ULong>> = buildList {
        geometry.waiterOff?.let { add("waiter_off" to it.toLong().toULong()) }
        geometry.bufferSize?.let { add("buffer_size" to it.toULong()) }
        geometry.taskOffset?.let { add("task_offset" to it.toULong()) }
        geometry.lockOffset?.let { add("lock_offset" to it.toULong()) }
        geometry.compatCarrier?.let { add("compat_carrier" to it.toULong()) }
        geometry.compatWaiterOff?.let { add("compat_waiter_off" to it.toLong().toULong()) }
        geometry.compatBufferSize?.let { add("compat_buffer_size" to it.toULong()) }
        geometry.compatFutexAbi?.let { add("compat_futex_abi" to it.toULong()) }
        geometry.lockAnchorImage?.let { add("lock_anchor_image" to it) }
        geometry.lockAnchorBytes?.let { add("lock_anchor_bytes" to it) }
        geometry.lockAnchorStride?.let { add("lock_anchor_stride" to it) }
    }

    /** Mirrors native `kRouteMulticast`; all eleven are optional. */
    override fun keys(): List<String> = SchemaKeys

    override fun apply(key: String, value: ULong): RouteConfig = when (key) {
        "waiter_off" -> copy(geometry = geometry.copy(waiterOff = value.toLong().toInt()))
        "buffer_size" -> copy(geometry = geometry.copy(bufferSize = value.toUInt()))
        "task_offset" -> copy(geometry = geometry.copy(taskOffset = value.toUInt()))
        "lock_offset" -> copy(geometry = geometry.copy(lockOffset = value.toUInt()))
        "compat_carrier" -> copy(geometry = geometry.copy(compatCarrier = value.toUByte()))
        "compat_waiter_off" -> copy(geometry = geometry.copy(compatWaiterOff = value.toLong().toInt()))
        "compat_buffer_size" -> copy(geometry = geometry.copy(compatBufferSize = value.toUInt()))
        "compat_futex_abi" -> copy(geometry = geometry.copy(compatFutexAbi = value.toUByte()))
        "lock_anchor_image" -> copy(geometry = geometry.copy(lockAnchorImage = value))
        "lock_anchor_bytes" -> copy(geometry = geometry.copy(lockAnchorBytes = value))
        "lock_anchor_stride" -> copy(geometry = geometry.copy(lockAnchorStride = value))
        else -> this
    }

    companion object {
        private val SchemaKeys = listOf(
            "waiter_off", "buffer_size", "task_offset", "lock_offset",
            "compat_carrier", "compat_waiter_off", "compat_buffer_size", "compat_futex_abi",
            "lock_anchor_image", "lock_anchor_bytes", "lock_anchor_stride",
        )

        val EMPTY = MulticastConfig(
            geometry = MulticastGeometry(null, null, null, null),
        )

        fun from(value: (String) -> Long?): MulticastConfig = MulticastConfig(
            geometry = MulticastGeometry(
                waiterOff = value("mcast.waiter_off")?.toInt(),
                bufferSize = value("mcast.buffer_size")?.toUInt(),
                taskOffset = value("mcast.task_offset")?.toUInt(),
                lockOffset = value("mcast.lock_offset")?.toUInt(),
                compatCarrier = value("mcast.compat_carrier")?.toUByte(),
                compatWaiterOff = value("mcast.compat_waiter_off")?.toInt(),
                compatBufferSize = value("mcast.compat_buffer_size")?.toUInt(),
                compatFutexAbi = value("mcast.compat_futex_abi")?.toUByte(),
                /* Branch-relative, like the select route's anchor keys:
                 * `ProfileResolver.nativeValue` maps these onto
                 * `route.multicast_waiter.*` (and the fallback branch). */
                lockAnchorImage = value("lock_anchor_image")?.toULong(),
                lockAnchorBytes = value("lock_anchor_bytes")?.toULong(),
                lockAnchorStride = value("lock_anchor_stride")?.toULong(),
            ),
        )
    }
}

/** Mirrors native `RouteGeometry`'s multicast members (all `std::optional`). */
data class MulticastGeometry(
    val waiterOff: Int?,
    val bufferSize: UInt?,
    val taskOffset: UInt?,
    val lockOffset: UInt?,
    /**
     * The AArch32 compat variant (docs/analysis/compat-multicast-carrier-plan.md):
     * when the 64-bit `group_source_req` copy cannot reach the waiter, the
     * armv7 helper's `MCAST_BLOCK_SOURCE` copy carries the strip.
     * `compatWaiterOff` is the derived strip offset inside the compat copy,
     * `compatBufferSize` the compat struct size, `compatFutexAbi` 0/time32,
     * 1/time64. Absent `compatCarrier` (or 0) keeps the 64-bit route.
     */
    val compatCarrier: UByte? = null,
    val compatWaiterOff: Int? = null,
    val compatBufferSize: UInt? = null,
    val compatFutexAbi: UByte? = null,
    /**
     * Image-relative offset of a zero, writable, reference-free kernel region
     * used as the walk's fake `rt_mutex` instead of the reclaimed payload page.
     * Absent => the reclaimed page is used, i.e. the previous behaviour.
     * See `docs/analysis/payload-page-option2-plan.md`.
     */
    val lockAnchorImage: ULong? = null,
    /**
     * Length of the verified-safe part of the anchor region, and the slot
     * stride within it. Both are per-kernel-build facts and there is no
     * inherited default: the anchored route needs all three keys, and the
     * diting grid (0x1000 / 0x20) must not be assumed for another kernel.
     * Native refuses a geometry where `bytes` is not a non-zero multiple of
     * `stride`, or `stride` is below the fake `rt_mutex`'s own size.
     * See `docs/analysis/anchor-slot-persistence-plan.md`.
     */
    val lockAnchorBytes: ULong? = null,
    val lockAnchorStride: ULong? = null,
)
