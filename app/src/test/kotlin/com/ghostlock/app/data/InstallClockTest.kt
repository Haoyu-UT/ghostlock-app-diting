package com.ghostlock.app.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The one fact that decides whether a missing anchor state file may be
 * recreated: did this installation's data exist before the current boot?
 * Getting it wrong in the permissive direction hands out a slot a previous
 * installation's run may have poisoned, so the boundary is tested.
 */
class InstallClockTest {
    private val now = 1_700_000_000_000L
    /** Device up for an hour: the boot instant is `now - elapsed`. */
    private val elapsed = 3_600_000L
    private val bootInstant = now - elapsed

    @Test
    fun `an install from before this boot is trusted`() {
        assertTrue(InstallClock.installPredatesBoot(bootInstant - 86_400_000, now, elapsed))
    }

    /** Equal timestamps count as before: the install landed at the boot instant. */
    @Test
    fun `an install exactly at the boot instant is trusted`() {
        assertTrue(InstallClock.installPredatesBoot(bootInstant, now, elapsed))
    }

    /** Installed after the boot began: a previous install may have run since. */
    @Test
    fun `an install after the boot began is not trusted`() {
        assertFalse(InstallClock.installPredatesBoot(bootInstant + 1, now, elapsed))
    }

    @Test
    fun `an install just now on a long-running device is not trusted`() {
        assertFalse(InstallClock.installPredatesBoot(now - 1000, now, elapsed))
    }

    @Test
    fun `an unreadable install time is not trusted`() {
        assertFalse(InstallClock.installPredatesBoot(0L, now, elapsed))
        assertFalse(InstallClock.installPredatesBoot(-1L, now, elapsed))
    }
}
