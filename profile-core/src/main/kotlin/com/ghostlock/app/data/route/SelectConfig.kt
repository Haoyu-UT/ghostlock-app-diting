package com.ghostlock.app.data.route

/**
 * `route.select_stack` section. Mirrors native `SelectStackLayout` plus the
 * select route's `compact_waiter` key (native also reads it from `kernel`).
 * Every field is optional: absence means "not provided".
 */
data class SelectConfig(
    val waiterShift: Int?,
    val compactWaiter: UByte?,
    val enterDelayUs: UInt?,
    val timeoutUs: UInt?,
    /**
     * Image-relative offset of a zero, writable, reference-free kernel region
     * used as the walk's fake rt_mutex instead of the reclaimed payload page.
     * Absent => the reclaimed page is used, i.e. the previous behaviour.
     * See `docs/analysis/payload-page-option2-plan.md`.
     */
    val lockAnchorImage: ULong? = null,
) : RouteConfig {
    override fun entries(): List<Pair<String, ULong>> = buildList {
        waiterShift?.let { add("waiter_shift" to it.toLong().toULong()) }
        compactWaiter?.let { add("compact_waiter" to it.toULong()) }
        lockAnchorImage?.let { add("lock_anchor_image" to it) }
        enterDelayUs?.let { add("enter_delay_us" to it.toULong()) }
        timeoutUs?.let { add("timeout_us" to it.toULong()) }
    }

    override fun apply(key: String, value: ULong): RouteConfig = when (key) {
        "waiter_shift" -> copy(waiterShift = value.toLong().toInt())
        "compact_waiter" -> copy(compactWaiter = value.toUByte())
        "lock_anchor_image" -> copy(lockAnchorImage = value)
        "enter_delay_us" -> copy(enterDelayUs = value.toUInt())
        "timeout_us" -> copy(timeoutUs = value.toUInt())
        else -> this
    }

    companion object {
        val EMPTY = SelectConfig(null, null, null, null)

        fun from(value: (String) -> Long?): SelectConfig = SelectConfig(
            waiterShift = value("pselect_waiter_shift")?.toInt(),
            compactWaiter = value("compact_waiter")?.toUByte(),
            enterDelayUs = value("execution.routes.select_stack.enter_delay_us")?.toUInt(),
            timeoutUs = value("execution.routes.select_stack.timeout_us")?.toUInt(),
            lockAnchorImage = value("lock_anchor_image")?.toULong(),
        )
    }
}
