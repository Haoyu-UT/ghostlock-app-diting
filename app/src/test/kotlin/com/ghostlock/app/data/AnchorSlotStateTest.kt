package com.ghostlock.app.data

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The app-side mirror of the native anchor allocator's boot-scoped decision
 * (`src/core/route/lock_anchor.cpp`). Every branch is tested against the native
 * order, because a mismatch in either direction is a wrong block (refusing a
 * run that would work) or a wasted run (the 2026-11-07 report).
 */
class AnchorSlotStateTest {
    private val boot = "11111111-2222-3333-4444-555555555555"
    private val otherBoot = "99999999-8888-7777-6666-555555555555"
    private val slots = 128L

    private fun state(bootId: String, next: Long, grid: Long = slots) = "$bootId $next $grid\n"

    @Test
    fun `missing file with an install before the boot starts at slot 0`() {
        assertEquals(
            AnchorSlotState.Verdict.OK,
            AnchorSlotState.evaluate(boot, null, slots, installPredatesBoot = true),
        )
    }

    @Test
    fun `missing file with an install after the boot began is refused`() {
        assertEquals(
            AnchorSlotState.Verdict.MISSING_UNTRUSTED,
            AnchorSlotState.evaluate(boot, null, slots, installPredatesBoot = false),
        )
    }

    @Test
    fun `a state file from an older boot proves the region was re-zeroed`() {
        assertEquals(
            AnchorSlotState.Verdict.OK,
            AnchorSlotState.evaluate(boot, state(otherBoot, 128), slots, installPredatesBoot = false),
        )
    }

    @Test
    fun `same boot with a free slot is allowed`() {
        assertEquals(
            AnchorSlotState.Verdict.OK,
            AnchorSlotState.evaluate(boot, state(boot, 0), slots, installPredatesBoot = false),
        )
        assertEquals(
            AnchorSlotState.Verdict.OK,
            AnchorSlotState.evaluate(boot, state(boot, 8), slots, installPredatesBoot = false),
        )
    }

    @Test
    fun `same boot with the budget spent is refused`() {
        assertEquals(
            AnchorSlotState.Verdict.BUDGET_SPENT,
            AnchorSlotState.evaluate(boot, state(boot, 128), slots, installPredatesBoot = false),
        )
    }

    @Test
    fun `same boot with a count past the grid is a grid mismatch`() {
        assertEquals(
            AnchorSlotState.Verdict.GRID_MISMATCH,
            AnchorSlotState.evaluate(boot, state(boot, 129), slots, installPredatesBoot = false),
        )
    }

    @Test
    fun `same boot with another profile's grid is a grid mismatch`() {
        assertEquals(
            AnchorSlotState.Verdict.GRID_MISMATCH,
            AnchorSlotState.evaluate(boot, state(boot, 0, grid = 64), slots, installPredatesBoot = false),
        )
    }

    @Test
    fun `a truncated same-boot file is trusted only when the install predates the boot`() {
        val truncated = "$boot 8\n"
        assertEquals(
            AnchorSlotState.Verdict.MISSING_UNTRUSTED,
            AnchorSlotState.evaluate(boot, truncated, slots, installPredatesBoot = false),
        )
        assertEquals(
            AnchorSlotState.Verdict.OK,
            AnchorSlotState.evaluate(boot, truncated, slots, installPredatesBoot = true),
        )
    }

    @Test
    fun `an unreadable boot id falls back to the native sentinel`() {
        assertEquals(
            AnchorSlotState.Verdict.OK,
            AnchorSlotState.evaluate("unknown-boot", state("unknown-boot", 8), slots, false),
        )
    }

    @Test
    fun `whitespace and a missing trailing newline parse like the native`() {
        assertEquals(
            AnchorSlotState.Verdict.OK,
            AnchorSlotState.evaluate(boot, "  $boot   16  $slots  ", slots, installPredatesBoot = false),
        )
    }

    @Test
    fun `a zero grid is left to the native`() {
        assertEquals(
            AnchorSlotState.Verdict.OK,
            AnchorSlotState.evaluate(boot, state(boot, 8), slots = 0, installPredatesBoot = false),
        )
    }
}
