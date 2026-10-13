package com.ghostlock.app.data

import com.ghostlock.app.data.NativeProfileDocument.Companion.fromBinary
import com.ghostlock.app.data.route.NoRouteConfig
import com.ghostlock.app.data.route.RouteConfig
import com.ghostlock.app.data.route.RouteKind
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Typed mirror of the native wire v2 document (`profile/binary.cpp`).
 *
 * v2 is object-sectioned: the header is followed by a list of named sections,
 * each holding `field name -> u64` entries. Presence is carried by key
 * occurrence (an omitted field is not the same as a provided 0), the u64 is a
 * raw bit container (signed values use two's complement), and values are never
 * clamped. Only the active route's `route.*` section is written or accepted.
 */
data class NativeProfileDocument(
    val release: String,
    val routeKind: UInt,
    val kernelMajor: UInt,
    val recommendShizuku: UInt,
    val fallbackRoute: UInt,
    val taskStruct: TaskStructOffsets,
    val cred: CredTemplate,
    val kernelOffset: KernelOffsetTable,
    val kernelPhysLoad: ULong?,
    val kernelPhysOffset: ULong?,
    val compactWaiter: UByte?,
    val kernelsnitchCollisions: UInt?,
    val mmStructSz: UInt?,
    val execution: ExecutionTuning,
    val safeMode: UInt,
    /** Route-specific configuration; never part of the shared schema. */
    val routeConfig: RouteConfig,
) {
    fun toBinary(): ByteArray {
        val releaseBytes = release.toByteArray(Charsets.UTF_8)
        require(releaseBytes.size <= 0xffff) { "release is too long" }
        /* The digest is computed over the schema before the digest entry
         * exists, so it can never cover itself. */
        val sections = sections() + Section("profile", listOf("digest" to schemaDigest()))
        var size = HeaderSize + releaseBytes.size + 2
        for (section in sections) {
            size += 1 + section.name.toByteArray(Charsets.UTF_8).size + 4
            for ((key, _) in section.entries) {
                size += 1 + key.toByteArray(Charsets.UTF_8).size + 8
            }
        }
        val buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(Magic.toInt())
        buffer.putShort(Version.toShort())
        buffer.putShort(FrontendRootChild.toShort())
        buffer.putShort(BackendCve202643499.toShort())
        buffer.putShort(routeKind.toShort())
        buffer.putShort(releaseBytes.size.toShort())
        buffer.putShort(Reserved.toShort())
        buffer.put(releaseBytes)
        buffer.putShort(sections.size.toShort())
        for (section in sections) {
            val nameBytes = section.name.toByteArray(Charsets.UTF_8)
            buffer.put(nameBytes.size.toByte())
            buffer.put(nameBytes)
            buffer.putInt(section.entries.size)
            for ((key, value) in section.entries) {
                val keyBytes = key.toByteArray(Charsets.UTF_8)
                buffer.put(keyBytes.size.toByte())
                buffer.put(keyBytes)
                buffer.putLong(value.toLong())
            }
        }
        return buffer.array()
    }

    /**
     * The complete wire schema: every section and key this document can carry,
     * with the value it holds or `null` when it is omitted. [sections] is the
     * present-only projection that becomes the bytes; the digest hashes the
     * schema itself, so a key that exists on one side of the transport and not
     * the other — the way a new profile key once vanished between the resolved
     * document and the wire — is a mismatch instead of a silent drop.
     */
    private fun schema(): List<Pair<String, List<WireEntry>>> = buildList {
        add(
            "meta" to listOf(
                WireEntry("kernel_major", kernelMajor.toULong()),
                WireEntry("recommend_shizuku", recommendShizuku.toULong()),
                WireEntry("fallback_route", fallbackRoute.toULong()),
                WireEntry("safe_mode", safeMode.toULong()),
            ),
        )
        add("task_struct" to taskEntries())
        add("cred" to credEntries())
        add("offset" to offsetEntries())
        add(
            "kernel" to listOf(
                WireEntry("kernel_phys_load", kernelPhysLoad),
                WireEntry("kernel_phys_offset", kernelPhysOffset),
                WireEntry("compact_waiter", compactWaiter?.toULong()),
                WireEntry("kernelsnitch_collisions", kernelsnitchCollisions?.toULong()),
                WireEntry("mm_struct_sz", mmStructSz?.toULong()),
            ),
        )
        add(
            "execution.recommended_cpus" to listOf(
                WireEntry("main", execution.recommendedMainCpu.toULong()),
                WireEntry("consumer", execution.recommendedConsumerCpu.toULong()),
            ),
        )
        add(
            "execution.heap" to listOf(
                WireEntry("prepare_max_attempts", execution.heapPrepareMaxAttempts.toULong()),
                WireEntry("prepare_timeout_ms", execution.heapPrepareTimeoutMs.toULong()),
                WireEntry("kernelsnitch_timeout_ms", execution.heapKernelsnitchTimeoutMs.toULong()),
            ),
        )
        add(
            "execution.race" to listOf(
                WireEntry("route_wait_ms", execution.raceRouteWaitMs.toULong()),
                WireEntry("route_done_timeout_ms", execution.raceRouteDoneTimeoutMs.toULong()),
                WireEntry("setup_settle_us", execution.raceSetupSettleUs.toULong()),
                WireEntry("state_poll_interval_us", execution.raceStatePollIntervalUs.toULong()),
            ),
        )
        add(
            "execution.stages" to listOf(
                WireEntry("w1_attempts", execution.w1Attempts.toULong()),
                WireEntry("w1_settle_us", execution.w1SettleUs.toULong()),
                WireEntry("w1_scratch_repair_attempts", execution.w1ScratchRepairAttempts.toULong()),
                WireEntry("w2_attempts", execution.w2Attempts.toULong()),
                WireEntry("w2_settle_us", execution.w2SettleUs.toULong()),
                WireEntry("w3_chain_rounds", execution.w3ChainRounds.toULong()),
                WireEntry("w3_attempts", execution.w3Attempts.toULong()),
                WireEntry("w3_settle_us", execution.w3SettleUs.toULong()),
            ),
        )
        add(
            "execution.handoff" to listOf(
                WireEntry("pre_dispatch_settle_ms", execution.handoffPreDispatchSettleMs.toULong()),
                WireEntry("module_poll_attempts", execution.handoffModulePollAttempts.toULong()),
                WireEntry("module_poll_interval_ms", execution.handoffModulePollIntervalMs.toULong()),
                WireEntry("enforce_poll_attempts", execution.handoffEnforcePollAttempts.toULong()),
                WireEntry("enforce_poll_interval_ms", execution.handoffEnforcePollIntervalMs.toULong()),
            ),
        )
        add(
            "execution.consumer" to listOf(
                WireEntry("max_calls", execution.consumerMaxCalls.toULong()),
                WireEntry("burst_calls", execution.consumerBurstCalls.toULong()),
            ),
        )
        routeSchema()?.let(::add)
    }

    /** The present-only projection of [schema] that is written to the wire. */
    private fun sections(): List<Section> = schema().mapNotNull { (name, entries) ->
        val present = entries.mapNotNull { entry -> entry.value?.let { entry.key to it } }
        if (present.isEmpty()) null else Section(name, present)
    }

    /**
     * Every key this document's schema declares, across its sections. A
     * resolved profile carrying a key outside this set is a key no wire
     * section can carry — the shape of the bug that lost the lock anchor
     * between the document and the transport.
     */
    fun wireKeys(): Set<String> = schema().flatMapTo(linkedSetOf()) { (_, entries) ->
        entries.map { it.key }
    }

    /** The active route's section, carrying its keys even when all are absent. */
    private fun routeSchema(): Pair<String, List<WireEntry>>? {
        val kind = RouteKind.fromWire(routeKind) ?: return null
        val values = routeConfig.entries().toMap()
        return routeSectionName(kind.wire) to
            routeConfig.keys().map { WireEntry(it, values[it]) }
    }

    /**
     * Canonical digest of [schema]: sections and keys in sorted order, each key
     * followed by a presence byte and, when present, its value little-endian.
     * Native recomputes the same stream from what it decoded (`binary.cpp`,
     * `schema_digest`) and treats a mismatch as fatal.
     *
     * Scope, stated because it is easy to over-read: this catches a **dropped
     * key** — a key one side of the transport declares and the other does not —
     * plus a mangled or truncated payload. It does **not** catch staleness: an
     * old imported layer or an override from an older build resolves to the
     * same document on both sides and hashes equal. The layer policy is what
     * stops those (§B/§C of PORT-PLAN Phase 8).
     */
    private fun schemaDigest(): ULong {
        val entries = mutableListOf<Pair<String, String>>()   // section -> key
        val values = mutableMapOf<Pair<String, String>, ULong?>()
        for ((section, keys) in schema()) {
            for (entry in keys) {
                if (section == "profile" || (section == "meta" && entry.key == "safe_mode")) {
                    /* safe_mode is rewritten in transit by the app (patchSafeMode)
                     * and `profile` carries this digest itself. */
                    continue
                }
                entries += section to entry.key
                values[section to entry.key] = entry.value
            }
        }
        entries.sortWith(compareBy({ it.first }, { it.second }))
        var hash = FnvOffsetBasis
        fun feed(byte: Int) {
            hash = (hash xor byte.toULong()) * FnvPrime
        }
        for ((section, key) in entries) {
            section.forEach { feed(it.code) }
            feed(SchemaSeparator)
            key.forEach { feed(it.code) }
            feed(SchemaSeparator)
            val value = values[section to key]
            if (value == null) {
                feed(0)
            } else {
                feed(1)
                for (index in 0 until 8) feed(((value shr (8 * index)) and 0xFFu).toInt())
            }
        }
        return hash
    }

    private fun taskEntries(): List<WireEntry> = listOf(
        WireEntry("prio", taskStruct.prio.toULong()),
        WireEntry("normal_prio", taskStruct.normalPrio.toULong()),
        WireEntry("sched_task_group", taskStruct.schedTaskGroup.toULong()),
        WireEntry("pi_lock", taskStruct.piLock.toULong()),
        WireEntry("pi_waiters", taskStruct.piWaiters.toULong()),
        WireEntry("pi_top_task", taskStruct.piTopTask.toULong()),
        WireEntry("pi_blocked_on", taskStruct.piBlockedOn.toULong()),
        WireEntry("pid", taskStruct.pid.toULong()),
        WireEntry("tgid", taskStruct.tgid.toULong()),
        WireEntry("atomic_flags", taskStruct.atomicFlags.toULong()),
        WireEntry("real_cred", taskStruct.realCred.toULong()),
        WireEntry("cred", taskStruct.cred.toULong()),
        WireEntry("comm", taskStruct.comm.toULong()),
        WireEntry("tasks", taskStruct.tasks.toULong()),
        WireEntry("seccomp", taskStruct.seccomp.toULong()),
    )

    private fun credEntries(): List<WireEntry> = listOf(
        WireEntry("copy_size", cred.copySize.toULong()),
        WireEntry("usage_offset", cred.usageOffset.toULong()),
        WireEntry("usage_value", cred.usageValue.toULong()),
        WireEntry("caps_offset", cred.capsOffset.toULong()),
        WireEntry("caps_count", cred.capsCount.toULong()),
        WireEntry("caps_value", cred.capsValue),
        WireEntry("ref_count", cred.refCount.toULong()),
        WireEntry("ref0_offset", cred.ref0Offset.toULong()),
        WireEntry("ref1_offset", cred.ref1Offset.toULong()),
        WireEntry("ref2_offset", cred.ref2Offset.toULong()),
        WireEntry("ref3_offset", cred.ref3Offset.toULong()),
        WireEntry("ref0_image", cred.ref0Image),
        WireEntry("ref1_image", cred.ref1Image),
        WireEntry("ref2_image", cred.ref2Image),
        WireEntry("ref3_image", cred.ref3Image),
    )

    private fun offsetEntries(): List<WireEntry> = listOf(
        WireEntry("init_task", kernelOffset.initTask),
        WireEntry("init_cred", kernelOffset.initCred),
        WireEntry("empty_zero_page", kernelOffset.emptyZeroPage),
        WireEntry("root_task_group", kernelOffset.rootTaskGroup),
        WireEntry("selinux_enforcing", kernelOffset.selinuxEnforcing),
        WireEntry("selinux_blob_sizes", kernelOffset.selinuxBlobSizes),
        WireEntry("security_hook_heads", kernelOffset.securityHookHeads),
        WireEntry("slide_nfulnl_logger", kernelOffset.slideNfulnlLogger),
        WireEntry("slide_loggers_0_1", kernelOffset.slideLoggers01),
        WireEntry("slide_boot_id", kernelOffset.slideBootId),
    )

    companion object {
        const val Magic = 0x0D000721u

        /** Wire v2 container version (object sections). */
        const val Version: UShort = 2u

        /* FNV-1a over the schema stream; native mirrors this byte for byte
         * (`schema_digest` in core/profile/binary.cpp). */
        private const val FnvOffsetBasis = 0xcbf29ce484222325uL
        private const val FnvPrime = 0x100000001b3uL
        private const val SchemaSeparator = 0x1F

        private const val FrontendRootChild: UShort = 1u
        private const val FrontendUmhForward: UShort = 2u
        private const val BackendCve202643499: UShort = 1u
        private const val BackendCve20264560: UShort = 2u
        private const val HeaderSize = 16
        private const val Reserved: UShort = 0u

        fun routeKind(route: String?): UInt = RouteKind.fromToken(route)?.wire ?: 0u

        /**
         * Rewrites the `meta.safe_mode` entry of a v2 document to 1, returning a
         * copy, or null when the blob is not a well-formed v2 document. v2 has
         * no fixed slot offset, so the section/entry is located by scanning.
         */
        fun patchSafeMode(document: ByteArray): ByteArray? {
            if (document.size < HeaderSize) return null
            val buffer = ByteBuffer.wrap(document).order(ByteOrder.LITTLE_ENDIAN)
            if (buffer.int.toUInt() != Magic) return null
            if (buffer.short.toUShort() != Version) return null
            buffer.short // frontend
            buffer.short // backend
            buffer.short // middleware
            val releaseLength = buffer.short.toInt() and 0xffff
            buffer.short // reserved
            if (buffer.remaining() < releaseLength + 2) return null
            buffer.position(buffer.position() + releaseLength)
            val sectionCount = buffer.short.toInt() and 0xffff
            repeat(sectionCount) {
                if (buffer.remaining() < 1) return null
                val nameLength = buffer.get().toInt() and 0xff
                if (buffer.remaining() < nameLength + 4) return null
                val nameBytes = ByteArray(nameLength)
                buffer.get(nameBytes)
                val entryCount = buffer.int.toUInt().toLong()
                var entry = 0L
                while (entry < entryCount) {
                    if (buffer.remaining() < 1) return null
                    val keyLength = buffer.get().toInt() and 0xff
                    if (buffer.remaining() < keyLength + 8) return null
                    val keyBytes = ByteArray(keyLength)
                    buffer.get(keyBytes)
                    val valueOffset = buffer.position()
                    buffer.long // value
                    if (String(nameBytes, Charsets.UTF_8) == "meta" &&
                        String(keyBytes, Charsets.UTF_8) == "safe_mode"
                    ) {
                        val copy = document.copyOf()
                        ByteBuffer.wrap(copy)
                            .order(ByteOrder.LITTLE_ENDIAN)
                            .putLong(valueOffset, 1L)
                        return copy
                    }
                    entry++
                }
            }
            return null
        }

        /**
         * The digest this document carries in its `profile` section, or null
         * when it predates the digest. Read out of the transmitted bytes, so a
         * caller logs the value native will actually verify.
         */
        fun digestOf(document: ByteArray): ULong? = scanSection(document, "profile", "digest")

        /**
         * Locates one `section`/`key` entry in a v2 document by scanning, and
         * returns its raw 64-bit value. v2 has no fixed slot offsets.
         */
        private fun scanSection(
            document: ByteArray,
            wantedSection: String,
            wantedKey: String,
        ): ULong? {
            if (document.size < HeaderSize) return null
            val buffer = ByteBuffer.wrap(document).order(ByteOrder.LITTLE_ENDIAN)
            if (buffer.int.toUInt() != Magic) return null
            if (buffer.short.toUShort() != Version) return null
            buffer.short // frontend
            buffer.short // backend
            buffer.short // middleware
            val releaseLength = buffer.short.toInt() and 0xffff
            buffer.short // reserved
            if (buffer.remaining() < releaseLength + 2) return null
            buffer.position(buffer.position() + releaseLength)
            val sectionCount = buffer.short.toInt() and 0xffff
            repeat(sectionCount) {
                if (buffer.remaining() < 1) return null
                val nameLength = buffer.get().toInt() and 0xff
                if (buffer.remaining() < nameLength + 4) return null
                val nameBytes = ByteArray(nameLength)
                buffer.get(nameBytes)
                val entryCount = buffer.int.toUInt().toLong()
                var entry = 0L
                while (entry < entryCount) {
                    if (buffer.remaining() < 1) return null
                    val keyLength = buffer.get().toInt() and 0xff
                    if (buffer.remaining() < keyLength + 8) return null
                    val keyBytes = ByteArray(keyLength)
                    buffer.get(keyBytes)
                    val value = buffer.long.toULong()
                    if (String(nameBytes, Charsets.UTF_8) == wantedSection &&
                        String(keyBytes, Charsets.UTF_8) == wantedKey
                    ) {
                        return value
                    }
                    entry++
                }
            }
            return null
        }

        fun fromBinary(bytes: ByteArray): NativeProfileDocument? {
            if (bytes.size < HeaderSize) return null
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            if (buffer.int.toUInt() != Magic) return null
            if (buffer.short.toUShort() != Version) return null
            val frontend = buffer.short.toUShort()
            val backend = buffer.short.toUShort()
            val middleware = buffer.short.toUShort()
            /* Unknown ids are rejected here; known-but-unavailable ids (UMH,
             * cve_2026_64560) decode and are rejected by the orchestrator. */
            if (frontend != FrontendRootChild && frontend != FrontendUmhForward) return null
            if (backend != BackendCve202643499 && backend != BackendCve20264560) return null
            val kind = RouteKind.fromWire(middleware.toUInt()) ?: return null
            val releaseLength = buffer.short.toInt() and 0xffff
            buffer.short // reserved
            if (buffer.remaining() < releaseLength + 2) return null
            val releaseBytes = ByteArray(releaseLength)
            buffer.get(releaseBytes)
            val release = String(releaseBytes, Charsets.UTF_8)

            val builder = Builder(release, kind)
            val activeRoute = routeSectionName(kind.wire)
            val sectionCount = buffer.short.toInt() and 0xffff
            repeat(sectionCount) {
                if (buffer.remaining() < 1) return null
                val nameLength = buffer.get().toInt() and 0xff
                if (buffer.remaining() < nameLength + 4) return null
                val nameBytes = ByteArray(nameLength)
                buffer.get(nameBytes)
                val name = String(nameBytes, Charsets.UTF_8)
                val entryCount = buffer.int.toUInt().toLong()
                var entry = 0L
                while (entry < entryCount) {
                    if (buffer.remaining() < 1) return null
                    val keyLength = buffer.get().toInt() and 0xff
                    if (buffer.remaining() < keyLength + 8) return null
                    val keyBytes = ByteArray(keyLength)
                    buffer.get(keyBytes)
                    val raw = buffer.long.toULong()
                    /* A route section only applies to the document's own route;
                     * other-route sections are consumed but never merged. */
                    if (!name.startsWith("route.") || name == activeRoute) {
                        builder.apply(name, String(keyBytes, Charsets.UTF_8), raw)
                    }
                    entry++
                }
            }
            return builder.build()
        }

        /** Builds the document from resolved profile values by dotted path. */
        fun from(
            release: String,
            route: String?,
            fallbackTo: String?,
            value: (String) -> Long?,
        ): NativeProfileDocument {
            fun vu(path: String): UInt = value(path)?.toUInt() ?: 0u
            fun vul(path: String): ULong = value(path)?.toULong() ?: 0uL
            fun vuOrNull(path: String): UInt? = value(path)?.toUInt()
            fun vulOrNull(path: String): ULong? = value(path)?.toULong()
            fun vbOrNull(path: String): UByte? = value(path)?.toUByte()
            val routeConfig = RouteKind.fromToken(route)?.buildConfig(value) ?: NoRouteConfig
            return NativeProfileDocument(
                release = release,
                routeKind = routeKind(route),
                kernelMajor = vu("kernel_major"),
                recommendShizuku = vu("recommend_shizuku"),
                fallbackRoute = routeKind(fallbackTo),
                taskStruct = TaskStructOffsets(
                    prio = vu("task_struct.prio"),
                    normalPrio = vu("task_struct.normal_prio"),
                    schedTaskGroup = vu("task_struct.sched_task_group"),
                    piLock = vu("task_struct.pi_lock"),
                    piWaiters = vu("task_struct.pi_waiters"),
                    piTopTask = vu("task_struct.pi_top_task"),
                    piBlockedOn = vu("task_struct.pi_blocked_on"),
                    pid = vu("task_struct.pid"),
                    tgid = vu("task_struct.tgid"),
                    atomicFlags = vu("task_struct.atomic_flags"),
                    realCred = vu("task_struct.real_cred"),
                    cred = vu("task_struct.cred"),
                    comm = vu("task_struct.comm"),
                    tasks = vu("task_struct.tasks"),
                    seccomp = vu("task_struct.seccomp"),
                ),
                cred = CredTemplate(
                    copySize = vu("cred.copy_size"),
                    usageOffset = vu("cred.usage_offset"),
                    usageValue = vu("cred.usage_value"),
                    capsOffset = vu("cred.caps_offset"),
                    capsCount = vu("cred.caps_count"),
                    capsValue = vul("cred.caps_value"),
                    refCount = vu("cred.ref_count"),
                    ref0Offset = vu("cred.ref0_offset"),
                    ref1Offset = vu("cred.ref1_offset"),
                    ref2Offset = vu("cred.ref2_offset"),
                    ref3Offset = vu("cred.ref3_offset"),
                    ref0Image = vul("cred.ref0_image"),
                    ref1Image = vul("cred.ref1_image"),
                    ref2Image = vul("cred.ref2_image"),
                    ref3Image = vul("cred.ref3_image"),
                ),
                kernelOffset = KernelOffsetTable(
                    initTask = vul("offset.init_task"),
                    initCred = vul("offset.init_cred"),
                    emptyZeroPage = vul("offset.empty_zero_page"),
                    rootTaskGroup = vul("offset.root_task_group"),
                    selinuxEnforcing = vul("offset.selinux_enforcing"),
                    selinuxBlobSizes = vul("offset.selinux_blob_sizes"),
                    securityHookHeads = vul("offset.security_hook_heads"),
                    slideNfulnlLogger = vul("offset.slide_nfulnl_logger"),
                    slideLoggers01 = vul("offset.slide_loggers_0_1"),
                    slideBootId = vul("offset.slide_boot_id"),
                ),
                kernelPhysLoad = vulOrNull("kernel_phys_load"),
                kernelPhysOffset = vulOrNull("kernel_phys_offset"),
                compactWaiter = vbOrNull("compact_waiter"),
                kernelsnitchCollisions = vuOrNull("kernelsnitch.collisions"),
                mmStructSz = vuOrNull("kernelsnitch.mm_struct_sz"),
                execution = ExecutionTuning(
                    recommendedMainCpu = vu("execution.recommended_cpus.main"),
                    recommendedConsumerCpu = vu("execution.recommended_cpus.consumer"),
                    heapPrepareMaxAttempts = vu("execution.heap.prepare_max_attempts"),
                    heapPrepareTimeoutMs = vu("execution.heap.prepare_timeout_ms"),
                    heapKernelsnitchTimeoutMs = vu("execution.heap.kernelsnitch_timeout_ms"),
                    raceRouteWaitMs = vu("execution.race.route_wait_ms"),
                    raceRouteDoneTimeoutMs = vu("execution.race.route_done_timeout_ms"),
                    raceSetupSettleUs = vu("execution.race.setup_settle_us"),
                    raceStatePollIntervalUs = vu("execution.race.state_poll_interval_us"),
                    w1Attempts = vu("execution.stages.w1_attempts"),
                    w1SettleUs = vu("execution.stages.w1_settle_us"),
                    w1ScratchRepairAttempts = vu("execution.stages.w1_scratch_repair_attempts"),
                    w2Attempts = vu("execution.stages.w2_attempts"),
                    w2SettleUs = vu("execution.stages.w2_settle_us"),
                    w3ChainRounds = vu("execution.stages.w3_chain_rounds"),
                    w3Attempts = vu("execution.stages.w3_attempts"),
                    w3SettleUs = vu("execution.stages.w3_settle_us"),
                    handoffPreDispatchSettleMs = vu("execution.handoff.pre_dispatch_settle_ms"),
                    handoffModulePollAttempts = vu("execution.handoff.module_poll_attempts"),
                    handoffModulePollIntervalMs = vu("execution.handoff.module_poll_interval_ms"),
                    handoffEnforcePollAttempts = vu("execution.handoff.enforce_poll_attempts"),
                    handoffEnforcePollIntervalMs = vu("execution.handoff.enforce_poll_interval_ms"),
                    consumerMaxCalls = vu("execution.routes.select_stack.consumer_max_calls"),
                    consumerBurstCalls = vu("execution.routes.select_stack.consumer_burst_calls"),
                ),
                safeMode = 0u,
                routeConfig = routeConfig,
            )
        }

        /** Section-scoped entry accumulator used by [fromBinary]. */
        private class Builder(
            private val release: String,
            private val routeKind: RouteKind,
        ) {
            private var metaKernelMajor = 0u
            private var metaRecommendShizuku = 0u
            private var metaFallbackRoute = 0u
            private var metaSafeMode = 0u
            private var task = TaskStructOffsets()
            private var credential = CredTemplate()
            private var offsets = KernelOffsetTable()
            private var kernelPhysLoad: ULong? = null
            private var kernelPhysOffset: ULong? = null
            private var compactWaiter: UByte? = null
            private var kernelsnitchCollisions: UInt? = null
            private var mmStructSz: UInt? = null
            private var execution = ExecutionTuning()
            private var routeConfig: RouteConfig = routeKind.emptyConfig()

            fun apply(section: String, key: String, raw: ULong) {
                if (section.startsWith("route.")) {
                    routeConfig = routeConfig.apply(key, raw)
                    return
                }
                when (section) {
                    "meta" -> when (key) {
                        "kernel_major" -> metaKernelMajor = raw.toUInt()
                        "recommend_shizuku" -> metaRecommendShizuku = raw.toUInt()
                        "fallback_route" -> metaFallbackRoute = raw.toUInt()
                        "safe_mode" -> metaSafeMode = raw.toUInt()
                    }

                    "task_struct" -> task = when (key) {
                        "prio" -> task.copy(prio = raw.toUInt())
                        "normal_prio" -> task.copy(normalPrio = raw.toUInt())
                        "sched_task_group" -> task.copy(schedTaskGroup = raw.toUInt())
                        "pi_lock" -> task.copy(piLock = raw.toUInt())
                        "pi_waiters" -> task.copy(piWaiters = raw.toUInt())
                        "pi_top_task" -> task.copy(piTopTask = raw.toUInt())
                        "pi_blocked_on" -> task.copy(piBlockedOn = raw.toUInt())
                        "pid" -> task.copy(pid = raw.toUInt())
                        "tgid" -> task.copy(tgid = raw.toUInt())
                        "atomic_flags" -> task.copy(atomicFlags = raw.toUInt())
                        "real_cred" -> task.copy(realCred = raw.toUInt())
                        "cred" -> task.copy(cred = raw.toUInt())
                        "comm" -> task.copy(comm = raw.toUInt())
                        "tasks" -> task.copy(tasks = raw.toUInt())
                        "seccomp" -> task.copy(seccomp = raw.toUInt())
                        else -> task
                    }

                    "cred" -> credential = when (key) {
                        "copy_size" -> credential.copy(copySize = raw.toUInt())
                        "usage_offset" -> credential.copy(usageOffset = raw.toUInt())
                        "usage_value" -> credential.copy(usageValue = raw.toUInt())
                        "caps_offset" -> credential.copy(capsOffset = raw.toUInt())
                        "caps_count" -> credential.copy(capsCount = raw.toUInt())
                        "caps_value" -> credential.copy(capsValue = raw)
                        "ref_count" -> credential.copy(refCount = raw.toUInt())
                        "ref0_offset" -> credential.copy(ref0Offset = raw.toUInt())
                        "ref1_offset" -> credential.copy(ref1Offset = raw.toUInt())
                        "ref2_offset" -> credential.copy(ref2Offset = raw.toUInt())
                        "ref3_offset" -> credential.copy(ref3Offset = raw.toUInt())
                        "ref0_image" -> credential.copy(ref0Image = raw)
                        "ref1_image" -> credential.copy(ref1Image = raw)
                        "ref2_image" -> credential.copy(ref2Image = raw)
                        "ref3_image" -> credential.copy(ref3Image = raw)
                        else -> credential
                    }

                    "offset" -> offsets = when (key) {
                        "init_task" -> offsets.copy(initTask = raw)
                        "init_cred" -> offsets.copy(initCred = raw)
                        "empty_zero_page" -> offsets.copy(emptyZeroPage = raw)
                        "root_task_group" -> offsets.copy(rootTaskGroup = raw)
                        "selinux_enforcing" -> offsets.copy(selinuxEnforcing = raw)
                        "selinux_blob_sizes" -> offsets.copy(selinuxBlobSizes = raw)
                        "security_hook_heads" -> offsets.copy(securityHookHeads = raw)
                        "slide_nfulnl_logger" -> offsets.copy(slideNfulnlLogger = raw)
                        "slide_loggers_0_1" -> offsets.copy(slideLoggers01 = raw)
                        "slide_boot_id" -> offsets.copy(slideBootId = raw)
                        else -> offsets
                    }

                    "kernel" -> when (key) {
                        "kernel_phys_load" -> kernelPhysLoad = raw
                        "kernel_phys_offset" -> kernelPhysOffset = raw
                        "compact_waiter" -> compactWaiter = raw.toUByte()
                        "kernelsnitch_collisions" -> kernelsnitchCollisions = raw.toUInt()
                        "mm_struct_sz" -> mmStructSz = raw.toUInt()
                    }

                    "execution.recommended_cpus" -> execution = when (key) {
                        "main" -> execution.copy(recommendedMainCpu = raw.toUInt())
                        "consumer" -> execution.copy(recommendedConsumerCpu = raw.toUInt())
                        else -> execution
                    }

                    "execution.heap" -> execution = when (key) {
                        "prepare_max_attempts" ->
                            execution.copy(heapPrepareMaxAttempts = raw.toUInt())

                        "prepare_timeout_ms" -> execution.copy(heapPrepareTimeoutMs = raw.toUInt())
                        "kernelsnitch_timeout_ms" ->
                            execution.copy(heapKernelsnitchTimeoutMs = raw.toUInt())

                        else -> execution
                    }

                    "execution.race" -> execution = when (key) {
                        "route_wait_ms" -> execution.copy(raceRouteWaitMs = raw.toUInt())
                        "route_done_timeout_ms" ->
                            execution.copy(raceRouteDoneTimeoutMs = raw.toUInt())

                        "setup_settle_us" -> execution.copy(raceSetupSettleUs = raw.toUInt())
                        "state_poll_interval_us" ->
                            execution.copy(raceStatePollIntervalUs = raw.toUInt())

                        else -> execution
                    }

                    "execution.stages" -> execution = when (key) {
                        "w1_attempts" -> execution.copy(w1Attempts = raw.toUInt())
                        "w1_settle_us" -> execution.copy(w1SettleUs = raw.toUInt())
                        "w1_scratch_repair_attempts" ->
                            execution.copy(w1ScratchRepairAttempts = raw.toUInt())

                        "w2_attempts" -> execution.copy(w2Attempts = raw.toUInt())
                        "w2_settle_us" -> execution.copy(w2SettleUs = raw.toUInt())
                        "w3_chain_rounds" -> execution.copy(w3ChainRounds = raw.toUInt())
                        "w3_attempts" -> execution.copy(w3Attempts = raw.toUInt())
                        "w3_settle_us" -> execution.copy(w3SettleUs = raw.toUInt())
                        else -> execution
                    }

                    "execution.handoff" -> execution = when (key) {
                        "pre_dispatch_settle_ms" ->
                            execution.copy(handoffPreDispatchSettleMs = raw.toUInt())

                        "module_poll_attempts" ->
                            execution.copy(handoffModulePollAttempts = raw.toUInt())

                        "module_poll_interval_ms" ->
                            execution.copy(handoffModulePollIntervalMs = raw.toUInt())

                        "enforce_poll_attempts" ->
                            execution.copy(handoffEnforcePollAttempts = raw.toUInt())

                        "enforce_poll_interval_ms" ->
                            execution.copy(handoffEnforcePollIntervalMs = raw.toUInt())

                        else -> execution
                    }

                    "execution.consumer" -> execution = when (key) {
                        "max_calls" -> execution.copy(consumerMaxCalls = raw.toUInt())
                        "burst_calls" -> execution.copy(consumerBurstCalls = raw.toUInt())
                        else -> execution
                    }
                }
            }

            fun build(): NativeProfileDocument = NativeProfileDocument(
                release = release,
                routeKind = routeKind.wire,
                kernelMajor = metaKernelMajor,
                recommendShizuku = metaRecommendShizuku,
                fallbackRoute = metaFallbackRoute,
                taskStruct = task,
                cred = credential,
                kernelOffset = offsets,
                kernelPhysLoad = kernelPhysLoad,
                kernelPhysOffset = kernelPhysOffset,
                compactWaiter = compactWaiter,
                kernelsnitchCollisions = kernelsnitchCollisions,
                mmStructSz = mmStructSz,
                execution = execution,
                safeMode = metaSafeMode,
                routeConfig = routeConfig,
            )
        }
    }
}

private data class Section(val name: String, val entries: List<Pair<String, ULong>>)

/** One wire schema slot: the value held, or null when the document omits it. */
private data class WireEntry(val key: String, val value: ULong?)

private fun routeSectionName(route: UInt): String = when (RouteKind.fromWire(route)) {
    RouteKind.TCP_ZEROCOPY -> "route.tcp_zerocopy"
    RouteKind.SELECT_STACK -> "route.select_stack"
    RouteKind.MULTICAST_WAITER -> "route.multicast_waiter"
    null -> ""
}

data class TaskStructOffsets(
    val prio: UInt = 0u,
    val normalPrio: UInt = 0u,
    val schedTaskGroup: UInt = 0u,
    val piLock: UInt = 0u,
    val piWaiters: UInt = 0u,
    val piTopTask: UInt = 0u,
    val piBlockedOn: UInt = 0u,
    val pid: UInt = 0u,
    val tgid: UInt = 0u,
    val atomicFlags: UInt = 0u,
    val realCred: UInt = 0u,
    val cred: UInt = 0u,
    val comm: UInt = 0u,
    val tasks: UInt = 0u,
    val seccomp: UInt = 0u,
)

data class CredTemplate(
    val copySize: UInt = 0u,
    val usageOffset: UInt = 0u,
    val usageValue: UInt = 0u,
    val capsOffset: UInt = 0u,
    val capsCount: UInt = 0u,
    val capsValue: ULong = 0uL,
    val refCount: UInt = 0u,
    val ref0Offset: UInt = 0u,
    val ref1Offset: UInt = 0u,
    val ref2Offset: UInt = 0u,
    val ref3Offset: UInt = 0u,
    val ref0Image: ULong = 0uL,
    val ref1Image: ULong = 0uL,
    val ref2Image: ULong = 0uL,
    val ref3Image: ULong = 0uL,
)

data class KernelOffsetTable(
    val initTask: ULong = 0uL,
    val initCred: ULong = 0uL,
    val emptyZeroPage: ULong = 0uL,
    val rootTaskGroup: ULong = 0uL,
    val selinuxEnforcing: ULong = 0uL,
    val selinuxBlobSizes: ULong = 0uL,
    val securityHookHeads: ULong = 0uL,
    val slideNfulnlLogger: ULong = 0uL,
    val slideLoggers01: ULong = 0uL,
    val slideBootId: ULong = 0uL,
)

data class ExecutionTuning(
    val recommendedMainCpu: UInt = 0u,
    val recommendedConsumerCpu: UInt = 0u,
    val heapPrepareMaxAttempts: UInt = 0u,
    val heapPrepareTimeoutMs: UInt = 0u,
    val heapKernelsnitchTimeoutMs: UInt = 0u,
    val raceRouteWaitMs: UInt = 0u,
    val raceRouteDoneTimeoutMs: UInt = 0u,
    val raceSetupSettleUs: UInt = 0u,
    val raceStatePollIntervalUs: UInt = 0u,
    val w1Attempts: UInt = 0u,
    val w1SettleUs: UInt = 0u,
    val w1ScratchRepairAttempts: UInt = 0u,
    val w2Attempts: UInt = 0u,
    val w2SettleUs: UInt = 0u,
    val w3ChainRounds: UInt = 0u,
    val w3Attempts: UInt = 0u,
    val w3SettleUs: UInt = 0u,
    val handoffPreDispatchSettleMs: UInt = 0u,
    val handoffModulePollAttempts: UInt = 0u,
    val handoffModulePollIntervalMs: UInt = 0u,
    val handoffEnforcePollAttempts: UInt = 0u,
    val handoffEnforcePollIntervalMs: UInt = 0u,
    val consumerMaxCalls: UInt = 0u,
    val consumerBurstCalls: UInt = 0u,
)
