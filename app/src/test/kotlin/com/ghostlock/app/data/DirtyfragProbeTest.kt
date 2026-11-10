package com.ghostlock.app.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class DirtyfragProbeTest {
    private val key = ByteArray(32) { (0x11 + it).toByte() }
    private val old = ByteArray(16) { (0x40 + it).toByte() }
    private val desired = "DIRTYFRAG-PROBE!".toByteArray(Charsets.US_ASCII)

    @Test
    fun `the iv makes cbc decrypt the old block to the desired bytes`() {
        val iv = ProbeCrypto.ivFor(key, old, desired)
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        assertArrayEquals(desired, cipher.doFinal(old))
    }

    @Test
    fun `the control packet decrypts to the inner udp sentinel`() {
        val sentinel = "DF-CONTROL-16B!!".toByteArray(Charsets.US_ASCII)
        assertEquals(16, sentinel.size)
        val packet = ProbeCrypto.controlPacket(key, spi = 0x1234, seq = 7, sentinel, 40000, 40001)
        val header = ByteBuffer.wrap(packet)
        assertEquals(0x1234L, header.getInt(0).toLong())
        assertEquals(7L, header.getInt(4).toLong())
        val plain = ProbeCrypto.controlPlaintext(key, packet)
        assertEquals(0, plain.size % 16)
        assertArrayEquals(sentinel, plain.copyOfRange(8, 8 + sentinel.size))
        assertEquals(17, plain[plain.size - 1].toInt())
        assertEquals(
            (8 + sentinel.size).toLong(),
            (ByteBuffer.wrap(plain).getShort(4).toInt() and 0xffff).toLong(),
        )
    }

    @Test
    fun `classification is control first then send then the block`() {
        assertEquals(DirtyfragProbe.Outcome.SetupFailed, ProbeCrypto.classify(false, 0, false))
        assertEquals(DirtyfragProbe.Outcome.Pass, ProbeCrypto.classify(true, 0, true))
        assertEquals(DirtyfragProbe.Outcome.SetupFailed, ProbeCrypto.classify(true, -1, false))
        assertEquals(DirtyfragProbe.Outcome.PrimitiveFailed, ProbeCrypto.classify(true, 0, false))
    }
}
