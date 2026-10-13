package com.ghostlock.app.domain.model

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * When the start-up "layers were disabled" notice is due (§C.12a): once per
 * build identity, and only when something really is inactive.
 */
class ProfileLayersTest {
    private fun layers(
        imported: String? = null,
        importedApplied: Boolean = false,
        overridesPresent: Boolean = false,
        overridesApplied: Boolean = false,
        build: String = "build-b",
    ) = ProfileLayers(
        builtinRelease = "5.10.236-test",
        bundledAuthoritative = true,
        imported = imported,
        importedApplied = importedApplied,
        overridesPresent = overridesPresent,
        overridesApplied = overridesApplied,
        build = build,
    )

    @Test
    fun `due when an import is loaded but not applied`() {
        assertTrue(layers(imported = "r2-era.conf").noticeDue(acknowledgedBuild = null))
    }

    @Test
    fun `due when overrides were written by another build`() {
        assertTrue(
            layers(overridesPresent = true, overridesApplied = false)
                .noticeDue(acknowledgedBuild = null),
        )
    }

    @Test
    fun `not due once acknowledged for this build`() {
        val state = layers(imported = "r2-era.conf")
        assertFalse(state.noticeDue(acknowledgedBuild = "build-b"))
    }

    /** A new build is a new identity: it disables the layers again, so it tells the user again. */
    @Test
    fun `due again after the build changes`() {
        assertTrue(layers(imported = "r2-era.conf").noticeDue(acknowledgedBuild = "build-a"))
    }

    @Test
    fun `not due when everything on disk is applied`() {
        val healthy = layers(
            imported = "r2-era.conf",
            importedApplied = true,
            overridesPresent = true,
            overridesApplied = true,
        )
        assertFalse(healthy.hasInactiveLayer)
        assertFalse(healthy.noticeDue(acknowledgedBuild = null))
    }

    @Test
    fun `not due when nothing is stored`() {
        assertFalse(layers().noticeDue(acknowledgedBuild = null))
    }

    /** Without a build identity nothing could ever be acknowledged, so it must not fire. */
    @Test
    fun `not due without a build identity`() {
        val unknown = layers(imported = "r2-era.conf", build = "")
        assertTrue(unknown.hasInactiveLayer)
        assertFalse(unknown.noticeDue(acknowledgedBuild = null))
    }
}
