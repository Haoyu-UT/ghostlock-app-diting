package com.ghostlock.app.data.profile

import com.ghostlock.app.data.getLongAt
import com.ghostlock.app.data.route.RouteKind

/**
 * Single authority for mapping a merged profile value map onto typed core and
 * execution layers. It owns the route-aware field lookup shared by the app and
 * the Gradle exporter, and the fail-closed structural validation.
 */
object ProfileResolver {
    private val KnownTopLevel = setOf(
        "release", "schema_version", "kernel_major", "recommend_shizuku",
        "route", "fallback", "kernelsnitch", "task_struct", "cred", "offset",
        "kernel_phys_load", "kernel_phys_offset", "execution",
        /* Stage 3: optional per-image waiter layout, carried by the wire. */
        "waiter_layout",
        /* Page-free Stage 1: selinux_state field offsets and W1's scratch
         * region. Optional; absence keeps the release layout / the page path. */
        "selinux", "w1_scratch",
    )
    private val RequiredTopLevel = setOf(
        "release", "schema_version", "kernel_major", "route", "task_struct", "cred", "offset",
    )
    private val RequiredTaskStruct = listOf(
        "prio", "normal_prio", "sched_task_group", "pi_lock", "pi_waiters", "pi_top_task",
        "pi_blocked_on", "pid", "tgid", "atomic_flags", "real_cred", "cred", "comm", "tasks",
        "seccomp",
    )
    private val RequiredCred = listOf("copy_size", "caps_count")
    private val RequiredOffset = listOf(
        "init_task", "init_cred", "root_task_group", "selinux_enforcing",
    )

    /**
     * Canonical native field lookup over the declared route branches. The v2
     * transport carries `recommended_cpus`, so the effective `selected_cpus`
     * is folded into those slots; `compact_waiter`/`pselect_waiter_shift`/
     * `mcast.*` map onto `route.<name>.*` then `fallback.route.<name>.*`.
     */
    fun nativeValue(
        profile: Map<String, Any?>,
        route: String?,
        fallbackTo: String?,
        path: String,
    ): Long? {
        if (path == "execution.recommended_cpus.main" ||
            path == "execution.recommended_cpus.consumer"
        ) {
            val slot = path.removePrefix("execution.recommended_cpus.")
            profile.getLongAt("execution.selected_cpus.$slot")?.let { return it }
        }
        val branchField = when (path) {
            "compact_waiter" -> "compact_waiter"
            "pselect_waiter_shift" -> "waiter_shift"
            "lock_anchor_image" -> "lock_anchor_image"
            "lock_anchor_bytes" -> "lock_anchor_bytes"
            "lock_anchor_stride" -> "lock_anchor_stride"
            /* The AArch32 compat carrier's switch and measured geometry. */
            "compat_carrier" -> "compat_carrier"
            "waiter_home" -> "waiter_home"
            "select_dst_depth" -> "select_dst_depth"
            /* The sigreturn route's per-build copy-window offsets. Bare paths,
             * like the select route's own geometry keys above, so both the
             * active route's branch and its fallback branch are searched. */
            "sig.waiter_off_sve" -> "waiter_off_sve"
            "sig.waiter_off_plain" -> "waiter_off_plain"
            else -> null
        }
        if (branchField != null) {
            route?.let { name ->
                profile.getLongAt("route.$name.$branchField")?.let { return it }
            }
            if (fallbackTo != null && fallbackTo != "none") {
                profile.getLongAt("fallback.route.$fallbackTo.$branchField")?.let { return it }
            }
        }
        if (path.startsWith("mcast.")) {
            val field = path.removePrefix("mcast.")
            route?.let { name ->
                profile.getLongAt("route.$name.$field")?.let { return it }
            }
            if (fallbackTo != null && fallbackTo != "none") {
                profile.getLongAt("fallback.route.$fallbackTo.$field")?.let { return it }
            }
            profile.getLongAt("mcast.$field")?.let { return it }
        }
        return profile.getLongAt(path)
    }

    /** Fail-closed structural validation of a merged profile. */
    fun validateMerged(
        profile: Map<String, Any?>,
        route: String?,
        fallbackTo: String?,
    ): List<ConfigError> {
        val errors = mutableListOf<ConfigError>()
        for (key in profile.keys) {
            if (key !in KnownTopLevel) {
                errors += ConfigError(key, "unknown top-level key")
            }
        }
        for (key in RequiredTopLevel) {
            if (!profile.containsKey(key)) {
                errors += ConfigError(key, "missing required key")
            }
        }
        if (route == null || route !in RouteNames) {
            errors += ConfigError("route", "missing or unknown route")
        }
        if (fallbackTo != null && fallbackTo != "none" && fallbackTo !in RouteNames) {
            errors += ConfigError("fallback.to", "unknown fallback route")
        }
        val task = profile["task_struct"] as? Map<*, *>
        if (task == null) {
            errors += ConfigError("task_struct", "not an object")
        } else {
            for (field in RequiredTaskStruct) {
                if (task[field] !is Number) errors += ConfigError("task_struct.$field", "missing")
            }
        }
        val cred = profile["cred"] as? Map<*, *>
        if (cred == null) {
            errors += ConfigError("cred", "not an object")
        } else {
            for (field in RequiredCred) {
                when (val value = cred[field]) {
                    null -> errors += ConfigError("cred.$field", "missing")
                    !is Number -> errors += ConfigError("cred.$field", "not a number")
                    else -> if (value.toLong() == 0L) {
                        errors += ConfigError("cred.$field", "zero")
                    }
                }
            }
        }
        val offset = profile["offset"] as? Map<*, *>
        if (offset == null) {
            errors += ConfigError("offset", "not an object")
        } else {
            for (field in RequiredOffset) {
                when (val value = offset[field]) {
                    null -> errors += ConfigError("offset.$field", "missing")
                    !is Number -> errors += ConfigError("offset.$field", "not a number")
                    else -> if (value.toLong() == 0L) {
                        errors += ConfigError("offset.$field", "zero")
                    }
                }
            }
        }
        errors += validateLayoutGroups(profile, route, fallbackTo)
        errors += validateStage1Blocks(profile, route, fallbackTo)
        return errors
    }

    /**
     * Page-free Stage 1 blocks. Both are optional -- a profile without them is
     * the page path and the release-derived selinux layout, i.e. every profile
     * that predates the keys. When present they must describe one coherent
     * layout: `enforcing` is the struct's first byte on every sampled image,
     * `initialized` is a byte offset inside the value, and a scratch that lies
     * inside the route's lock-anchor region is the slot the allocator reserves
     * (its 0x18-byte collateral window must stay inside the region).
     */
    private fun validateStage1Blocks(
        profile: Map<String, Any?>,
        route: String?,
        fallbackTo: String?,
    ): List<ConfigError> {
        val errors = mutableListOf<ConfigError>()
        profile["selinux"]?.let { raw ->
            val block = raw as? Map<*, *>
            if (block == null) {
                errors += ConfigError("selinux", "not an object")
            } else {
                when (val enforcing = block["enforcing"]) {
                    null -> errors += ConfigError("selinux.enforcing", "missing")
                    !is Number -> errors += ConfigError("selinux.enforcing", "not a number")
                    else -> if (enforcing.toLong() != 0L) {
                        errors += ConfigError("selinux.enforcing", "must be 0")
                    }
                }
                when (val initialized = block["initialized"]) {
                    null -> errors += ConfigError("selinux.initialized", "missing")
                    !is Number -> errors += ConfigError("selinux.initialized", "not a number")
                    else -> if (initialized.toLong() !in 0L..7L) {
                        errors += ConfigError("selinux.initialized", "must be a byte offset")
                    }
                }
            }
        }
        profile["w1_scratch"]?.let { raw ->
            val block = raw as? Map<*, *>
            if (block == null) {
                errors += ConfigError("w1_scratch", "not an object")
                return@let
            }
            val image = block["image"]
            when (image) {
                null -> errors += ConfigError("w1_scratch.image", "missing")
                !is Number -> errors += ConfigError("w1_scratch.image", "not a number")
                else -> if (image.toLong() <= 0L) {
                    errors += ConfigError("w1_scratch.image", "must be positive")
                } else {
                    val anchorPrefix = route?.let { "route.$it" }
                        ?: fallbackTo?.takeIf { it != "none" }?.let { "fallback.route.$it" }
                        ?: "route"
                    val anchorImage = profile.getLongAt("$anchorPrefix.lock_anchor_image")
                    val anchorBytes = profile.getLongAt("$anchorPrefix.lock_anchor_bytes")
                    if (anchorImage != null && anchorBytes != null &&
                        image.toLong() >= anchorImage &&
                        image.toLong() < anchorImage + anchorBytes
                    ) {
                        /* Inside the anchor: this is the reserved slot. The
                         * value is alias(image) + 0x100 and the erase's
                         * collateral spans 0x18 bytes from it. */
                        val window = image.toLong() - anchorImage + 0x100
                        if (window + 0x18 > anchorBytes) {
                            errors += ConfigError(
                                "w1_scratch.image",
                                "collateral window leaves the anchor region",
                            )
                        }
                    }
                }
            }
        }
        return errors
    }

    /**
     * Stage-4 coupled groups. The stage-3 keys are optional, but when present
     * they describe one physical layout: the copy must cover the `security`
     * pointer, the uid must follow the usage word, the waiter's offsets must
     * be ordered, and the anchor stride must not be smaller than
     * `sizeof(rt_mutex)`. The copy bound is a minimum, not an equality: 5.x
     * places user/user_ns/ucounts/group_info and the rcu head after
     * `security`, so its copy is sizeof(cred) and is larger.
     */
    private fun validateLayoutGroups(
        profile: Map<String, Any?>,
        route: String?,
        fallbackTo: String?,
    ): List<ConfigError> {
        val errors = mutableListOf<ConfigError>()
        val anchorPrefix = route?.let { "route.$it" }
            ?: fallbackTo?.takeIf { it != "none" }?.let { "fallback.route.$it" }
            ?: "route"

        val copy = profile.getLongAt("cred.copy_size")
        val usageOffset = profile.getLongAt("cred.usage_offset") ?: 0L
        val usageSize = profile.getLongAt("cred.usage_size")
        val uid = profile.getLongAt("cred.uid_offset")
        val security = profile.getLongAt("cred.security_offset")
        val caps = profile.getLongAt("cred.caps_offset")
        val capsCount = profile.getLongAt("cred.caps_count")
        if (usageSize != null && usageSize != 4L && usageSize != 8L) {
            errors += ConfigError("cred.usage_size", "must be 4 or 8")
        }
        if (usageSize != null && copy != null && usageOffset + usageSize > copy) {
            errors += ConfigError("cred.usage_size", "does not fit cred.copy_size")
        }
        if (uid != null && copy != null && uid + 4L > copy) {
            errors += ConfigError("cred.uid_offset", "does not fit cred.copy_size")
        }
        if (uid != null && usageSize != null && uid < usageOffset + usageSize) {
            errors += ConfigError("cred.uid_offset", "overlaps cred.usage")
        }
        if (security != null && copy != null && copy < security + 8L) {
            errors += ConfigError(
                "cred.copy_size",
                "must cover cred.security_offset + 8 (cred layout group)",
            )
        }
        if (security != null && caps != null && security < caps) {
            errors += ConfigError("cred.security_offset", "precedes cred.caps_offset")
        }
        if (caps != null && capsCount != null && copy != null &&
            caps + capsCount * 8L > copy
        ) {
            errors += ConfigError("cred.caps_offset", "does not fit cred.copy_size")
        }

        val waiterCompact = profile.getLongAt("waiter_layout.compact")
        if (waiterCompact != null && waiterCompact != 0L && waiterCompact != 1L) {
            errors += ConfigError("waiter_layout.compact", "must be 0 or 1")
        }
        if (waiterCompact != null) {
            val routeCompact = profile.getLongAt("$anchorPrefix.compact_waiter")
            if (routeCompact != null && routeCompact != 0L && waiterCompact != routeCompact) {
                errors += ConfigError(
                    "waiter_layout.compact",
                    "differs from $anchorPrefix.compact_waiter (waiter layout group)",
                )
            }
        }
        val pi = profile.getLongAt("waiter_layout.pi_tree")
        val task = profile.getLongAt("waiter_layout.task")
        val lock = profile.getLongAt("waiter_layout.lock")
        val wake = profile.getLongAt("waiter_layout.wake_state")
        for ((path, value) in listOf(
            "waiter_layout.pi_tree" to pi,
            "waiter_layout.task" to task,
            "waiter_layout.lock" to lock,
            "waiter_layout.wake_state" to wake,
        )) {
            if (value != null && (value < 0L || value > 0x200L)) {
                errors += ConfigError(path, "outside the waiter's plausible field range")
            }
        }
        if (pi != null && task != null && pi >= task) {
            errors += ConfigError("waiter_layout.pi_tree", "must precede waiter_layout.task")
        }
        if (task != null && lock != null && task >= lock) {
            errors += ConfigError("waiter_layout.task", "must precede waiter_layout.lock")
        }
        if (lock != null && wake != null && lock >= wake) {
            errors += ConfigError("waiter_layout.lock", "must precede waiter_layout.wake_state")
        }

        val rtMutex = profile.getLongAt("kernelsnitch.rt_mutex_size")
        if (rtMutex != null && (rtMutex < 8L || rtMutex > 256L)) {
            errors += ConfigError("kernelsnitch.rt_mutex_size", "outside 8..256")
        }
        if (rtMutex != null) {
            val stride = profile.getLongAt("$anchorPrefix.lock_anchor_stride")
            if (stride != null && stride < rtMutex) {
                errors += ConfigError(
                    "$anchorPrefix.lock_anchor_stride",
                    "smaller than kernelsnitch.rt_mutex_size (rt_mutex layout group)",
                )
            }
            if (stride != null && stride % rtMutex != 0L) {
                errors += ConfigError(
                    "$anchorPrefix.lock_anchor_stride",
                    "not a multiple of kernelsnitch.rt_mutex_size",
                )
            }
        }
        return errors
    }

    /** Flattens the `execution` object into path -> value. */
    fun executionFromMerged(profile: Map<String, Any?>): Map<String, ULong> {
        val execution = profile["execution"] as? Map<*, *> ?: return emptyMap()
        val out = LinkedHashMap<String, ULong>()
        fun walk(prefix: String, node: Map<*, *>) {
            for ((rawKey, value) in node) {
                val key = rawKey.toString()
                val path = if (prefix.isEmpty()) key else "$prefix.$key"
                when (value) {
                    is Map<*, *> -> walk(path, value)
                    is Number -> out[path] = value.toLong().toULong()
                }
            }
        }
        walk("", execution)
        return out
    }

    private val RouteNames = RouteKind.entries.map { it.token }
}
