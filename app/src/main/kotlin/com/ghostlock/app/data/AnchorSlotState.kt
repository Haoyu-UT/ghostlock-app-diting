package com.ghostlock.app.data

/**
 * Pure mirror of the native lock-anchor allocator's boot-scoped decision
 * (`src/core/route/lock_anchor.cpp`, `allocate_slot`) so the app can refuse a
 * run the native would refuse anyway — before a run-store entry or a native
 * process exists.
 *
 * Keep the branch order identical to the native. The state file is
 * `<boot-id> <next> <slots>\n` (`write_anchor_state`); `next` is a chunk
 * reservation high-water mark (8 slots per write), so `next >= slots` means the
 * boot's budget is spent.
 *
 * The native stays the authority: this gate only blocks when it is confident.
 */
internal object AnchorSlotState {
    /** `kLockAnchorBytesDefault` / `kLockAnchorStrideDefault` on the native side. */
    const val DefaultBytes = 4096L
    const val DefaultStride = 32L

    /** `kLockAnchorStrideMin`: the fake rt_mutex reaches owner@+0x18. */
    const val MinStride = 32L

    enum class Verdict {
        /** A slot can be handed out (or a new boot / trusted install resets it). */
        OK,

        /** No parsable state file and the install does not predate the boot. */
        MISSING_UNTRUSTED,

        /** This boot's slot budget is spent. */
        BUDGET_SPENT,

        /** The file's grid is not this profile's grid (or its count is invalid). */
        GRID_MISMATCH,
    }

    private data class Parsed(val bootId: String?, val next: Long?, val slots: Long?)

    fun evaluate(
        bootId: String,
        stateText: String?,
        slots: Long,
        installPredatesBoot: Boolean,
    ): Verdict {
        if (slots <= 0L) return Verdict.OK
        val parsed = parse(stateText)
        val sameBoot = parsed.bootId != null && parsed.bootId == bootId
        val haveAll = parsed.next != null && parsed.slots != null
        val gridOk = haveAll && parsed.slots == slots
        val next = parsed.next ?: 0L
        return when {
            sameBoot && gridOk && next <= slots ->
                if (next >= slots) Verdict.BUDGET_SPENT else Verdict.OK

            /* A boot id that differs proves the region was re-zeroed at boot. */
            parsed.bootId != null && !sameBoot -> Verdict.OK

            /* Same boot, but the count/grid cannot be trusted. */
            sameBoot && haveAll -> Verdict.GRID_MISMATCH

            /* No usable file, but the install provably predates the boot: any
             * run this boot would have written the file, so slot 0 is safe. */
            installPredatesBoot -> Verdict.OK

            else -> Verdict.MISSING_UNTRUSTED
        }
    }

    private fun parse(text: String?): Parsed {
        if (text.isNullOrBlank()) return Parsed(null, null, null)
        val parts = text.trim().split(Regex("\\s+"))
        if (parts.isEmpty() || parts[0].isBlank()) return Parsed(null, null, null)
        return Parsed(
            bootId = parts[0],
            next = parts.getOrNull(1)?.toLongOrNull(),
            slots = parts.getOrNull(2)?.toLongOrNull(),
        )
    }
}
