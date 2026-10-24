package com.ghostlock.app.data.profile

import com.ghostlock.app.data.NativeProfileDocument
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The wire digest: what it covers, what it must ignore, and the number it
 * produces for the vector the native side asserts too.
 */
class NativeProfileDigestTest {
    /**
     * FNV-1a over the canonical schema stream for [goldenDocument]. The same
     * constant is asserted in `src/core/tests/profile_binary_test.cpp`, so the
     * two implementations are a checked contract rather than two hopeful
     * copies — change one and its own test fails.
     */
    private val goldenDigest = 0xcc8fc4e3d6a4eadfuL

    private fun document(
        values: Map<String, Long> = emptyMap(),
        route: String? = "select_stack",
        fallbackTo: String? = null,
    ): NativeProfileDocument = NativeProfileDocument.from(
        release = "digest-vector",
        route = route,
        fallbackTo = fallbackTo,
    ) { path -> values[path] }

    /** The native vector: kernel_major 5 plus a fully populated select route. */
    private fun goldenDocument(): NativeProfileDocument = document(
        mapOf(
            "kernel_major" to 5L,
            "compact_waiter" to 1L,
            "pselect_waiter_shift" to -2L,
            "lock_anchor_image" to 0x2a3a590L,
            "lock_anchor_bytes" to 0x1000L,
            "lock_anchor_stride" to 0x20L,
            "execution.routes.select_stack.enter_delay_us" to 5000L,
            "execution.routes.select_stack.timeout_us" to 30000L,
        ),
    )

    private fun digestOf(document: NativeProfileDocument): ULong =
        checkNotNull(NativeProfileDocument.digestOf(document.toBinary())) {
            "every document written here carries a digest"
        }

    @Test
    fun `digest matches the native implementation's vector`() {
        assertEquals(goldenDigest, digestOf(goldenDocument()))
    }

    @Test
    fun `digest survives a decode and re-encode round trip`() {
        val bytes = goldenDocument().toBinary()
        val decoded = checkNotNull(NativeProfileDocument.fromBinary(bytes))
        assertEquals(goldenDigest, checkNotNull(NativeProfileDocument.digestOf(decoded.toBinary())))
    }

    /** The digest must be a function of the content, not of the run. */
    @Test
    fun `digest is stable across identical builds`() {
        assertEquals(digestOf(goldenDocument()), digestOf(goldenDocument()))
    }

    /**
     * Presence is part of the schema stream, which is what lets a key that
     * exists on one side of the transport and not the other be detected.
     */
    @Test
    fun `a key present on one side and absent on the other changes the digest`() {
        val present = document(mapOf("lock_anchor_image" to 0x2a3a590L))
        val absent = document(emptyMap())
        assertNotEquals(digestOf(present), digestOf(absent))
    }

    @Test
    fun `a changed value changes the digest`() {
        assertNotEquals(
            digestOf(document(mapOf("lock_anchor_image" to 0x2a3a590L))),
            digestOf(document(mapOf("lock_anchor_image" to 0x2a3a591L))),
        )
    }

    /**
     * `safe_mode` is excluded because the app rewrites it in transit
     * (`patchSafeMode`); a digest that covered it would fail every safe-mode
     * run. Nothing else in the meta section is exempt.
     */
    @Test
    fun `safe_mode is outside the digest and kernel_major is inside it`() {
        assertEquals(digestOf(goldenDocument()), digestOf(goldenDocument().copy(safeMode = 1u)))
        assertNotEquals(digestOf(goldenDocument()), digestOf(goldenDocument().copy(kernelMajor = 6u)))
    }

    @Test
    fun `digestOf reports nothing for a document that has no digest`() {
        assertNull(NativeProfileDocument.digestOf(byteArrayOf(1, 2, 3)))
        assertNull(NativeProfileDocument.digestOf(goldenDocument().toBinary().copyOf(8)))
    }
}
