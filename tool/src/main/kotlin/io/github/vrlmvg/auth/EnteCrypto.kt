package io.github.vrlmvg.auth

import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.LongBuffer
import java.security.MessageDigest

/**
 * The two libsodium primitives Ente Auth uses for its encrypted export:
 * `crypto_pwhash` (Argon2id v1.3) and `crypto_secretstream_xchacha20poly1305`.
 */
internal object EnteCrypto {

    /**
     * libsodium `crypto_pwhash(ARGON2ID13)` with one lane.
     *
     * Ente derives export keys with 256 MiB–1 GiB of memory, far beyond an app's Java heap limit
     * (and on Android even direct buffers count against it), so the caller supplies the working
     * memory through [memory]: the app maps anonymous shared memory, JVM tests use a plain buffer.
     * [onProgress] receives values in 0..1 as blocks are filled.
     */
    fun argon2id(
        password: ByteArray,
        salt: ByteArray,
        opsLimit: Int,
        memLimitBytes: Long,
        outputLength: Int = 32,
        memory: WorkingMemory = HeapWorkingMemory,
        onProgress: (Float) -> Unit = {},
    ): ByteArray {
        require(opsLimit >= 1) { "opsLimit must be at least 1" }
        val lanes = 1
        val memoryKiB = (memLimitBytes / 1024).toInt()
        // Each lane needs at least 2 blocks per slice.
        val blockCount = maxOf(memoryKiB, 8 * lanes) / (4 * lanes) * (4 * lanes)

        val h0 = blake2b(64) {
            le32(lanes); le32(outputLength); le32(memoryKiB); le32(opsLimit)
            le32(ARGON2_VERSION); le32(ARGON2_TYPE_ID)
            le32(password.size); update(password, 0, password.size)
            le32(salt.size); update(salt, 0, salt.size)
            le32(0) // secret
            le32(0) // associated data
        }

        return memory.use(blockCount * BLOCK_BYTES) { buffer ->
            fill(buffer.order(ByteOrder.LITTLE_ENDIAN).asLongBuffer(), h0, blockCount, opsLimit, outputLength, onProgress)
        }
    }

    private fun fill(
        memory: LongBuffer,
        h0: ByteArray,
        blockCount: Int,
        opsLimit: Int,
        outputLength: Int,
        onProgress: (Float) -> Unit,
    ): ByteArray {
        val laneLength = blockCount // one lane
        val segmentLength = laneLength / 4

        // First two blocks of the lane come straight from H0.
        for (column in 0..1) {
            val seed = h0 + intLe(column) + intLe(0)
            writeBlock(memory, column, bytesToWords(variableHash(BLOCK_BYTES, seed)))
        }

        val prev = LongArray(WORDS)
        val ref = LongArray(WORDS)
        val next = LongArray(WORDS)
        val scratch = LongArray(WORDS)
        val addressBlock = LongArray(WORDS)
        val inputBlock = LongArray(WORDS)
        val zeroBlock = LongArray(WORDS)

        val totalBlocks = opsLimit.toLong() * blockCount
        var filled = 0L

        for (pass in 0 until opsLimit) {
            for (slice in 0 until 4) {
                val dataIndependent = pass == 0 && slice < 2
                if (dataIndependent) {
                    inputBlock.fill(0)
                    inputBlock[0] = pass.toLong(); inputBlock[1] = 0
                    inputBlock[2] = slice.toLong(); inputBlock[3] = blockCount.toLong()
                    inputBlock[4] = opsLimit.toLong(); inputBlock[5] = ARGON2_TYPE_ID.toLong()
                }
                var startIndex = 0
                if (pass == 0 && slice == 0) {
                    startIndex = 2
                    if (dataIndependent) nextAddresses(addressBlock, inputBlock, zeroBlock, scratch)
                }
                for (index in startIndex until segmentLength) {
                    val current = slice * segmentLength + index
                    val previous = if (current == 0) laneLength - 1 else current - 1

                    readBlock(memory, previous, prev)
                    val pseudoRandom = if (dataIndependent) {
                        if (index % WORDS == 0) nextAddresses(addressBlock, inputBlock, zeroBlock, scratch)
                        addressBlock[index % WORDS]
                    } else {
                        prev[0]
                    }

                    val refIndex = referenceIndex(pass, slice, index, segmentLength, laneLength, pseudoRandom)
                    readBlock(memory, refIndex, ref)
                    if (pass == 0) {
                        fillBlock(prev, ref, next, scratch, withXor = false)
                    } else {
                        readBlock(memory, current, next)
                        fillBlock(prev, ref, next, scratch, withXor = true)
                    }
                    writeBlock(memory, current, next)

                    filled++
                    if (filled and 0x3FFF == 0L) onProgress(filled.toFloat() / totalBlocks)
                }
            }
        }
        onProgress(1f)

        val last = LongArray(WORDS)
        readBlock(memory, laneLength - 1, last)
        return variableHash(outputLength, wordsToBytes(last))
    }

    /**
     * Decrypts a single-message `crypto_secretstream_xchacha20poly1305` stream, as written by
     * Ente's `encryptData`. Throws [DecryptionFailedException] if the key is wrong or data altered.
     */
    fun secretStreamDecrypt(cipher: ByteArray, key: ByteArray, header: ByteArray): ByteArray {
        if (key.size != 32 || header.size != 24 || cipher.size < SECRETSTREAM_ABYTES) {
            throw DecryptionFailedException()
        }
        val subKey = hChaCha20(key, header.copyOfRange(0, 16))
        // State nonce: 32-bit counter (starts at 1) followed by the last 8 header bytes.
        val nonce = intLe(1) + header.copyOfRange(16, 24)

        val messageLength = cipher.size - SECRETSTREAM_ABYTES

        val polyKeyBlock = chacha20(subKey, nonce, counter = 0, input = ByteArray(64))
        val mac = Poly1305().apply { init(KeyParameter(polyKeyBlock.copyOfRange(0, 32))) }

        // The tag byte is encrypted on its own 64-byte block (counter 1). The MAC covers that block
        // after the keystream is applied, with byte 0 put back to the ciphertext byte.
        val tagBlock = chacha20(subKey, nonce, counter = 1, input = ByteArray(64).also { it[0] = cipher[0] })
        val tag = tagBlock[0]
        tagBlock[0] = cipher[0]
        mac.update(tagBlock, 0, 64)
        mac.update(cipher, 1, messageLength)
        // libsodium computes this as (0x10 - sizeof(block) + mlen) & 0xf: an operator-precedence
        // quirk that is part of the format, so it must be matched exactly.
        val padding = (0x10 - 64 + messageLength) and 0xf
        mac.update(ByteArray(padding), 0, padding)
        mac.update(longLe(0), 0, 8) // associated data length
        mac.update(longLe(64L + messageLength), 0, 8)
        val expectedMac = ByteArray(16).also { mac.doFinal(it, 0) }
        val actualMac = cipher.copyOfRange(1 + messageLength, cipher.size)
        if (!MessageDigest.isEqual(expectedMac, actualMac)) throw DecryptionFailedException()
        if (tag != TAG_FINAL) throw DecryptionFailedException()

        return chacha20(subKey, nonce, counter = 2, input = cipher.copyOfRange(1, 1 + messageLength))
    }

    // --- Argon2 internals -------------------------------------------------------------------

    private fun referenceIndex(
        pass: Int,
        slice: Int,
        index: Int,
        segmentLength: Int,
        laneLength: Int,
        pseudoRandom: Long,
    ): Int {
        val referenceAreaSize: Long = if (pass == 0) {
            if (slice == 0) index - 1L else slice.toLong() * segmentLength + index - 1
        } else {
            laneLength.toLong() - segmentLength + index - 1
        }
        var relative = pseudoRandom and 0xFFFFFFFFL
        relative = (relative * relative) ushr 32
        relative = referenceAreaSize - 1 - ((referenceAreaSize * relative) ushr 32)
        val start = if (pass != 0 && slice != 3) (slice + 1).toLong() * segmentLength else 0L
        return ((start + relative) % laneLength).toInt()
    }

    private fun nextAddresses(address: LongArray, input: LongArray, zero: LongArray, scratch: LongArray) {
        input[6]++
        fillBlock(zero, input, address, scratch, withXor = false)
        fillBlock(zero, address.copyOf(), address, scratch, withXor = false)
    }

    /** Argon2 compression G: next = P(prev ⊕ ref) ⊕ (prev ⊕ ref) [⊕ next when xoring]. */
    private fun fillBlock(prev: LongArray, ref: LongArray, next: LongArray, r: LongArray, withXor: Boolean) {
        for (i in 0 until WORDS) r[i] = prev[i] xor ref[i]
        if (withXor) {
            for (i in 0 until WORDS) next[i] = next[i] xor r[i]
        } else {
            System.arraycopy(r, 0, next, 0, WORDS)
        }
        for (row in 0 until 8) {
            val b = row * 16
            round(r, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
                b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15)
        }
        for (col in 0 until 8) {
            val b = col * 2
            round(r, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
                b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113)
        }
        for (i in 0 until WORDS) next[i] = next[i] xor r[i]
    }

    private fun round(
        v: LongArray,
        v0: Int, v1: Int, v2: Int, v3: Int, v4: Int, v5: Int, v6: Int, v7: Int,
        v8: Int, v9: Int, v10: Int, v11: Int, v12: Int, v13: Int, v14: Int, v15: Int,
    ) {
        g(v, v0, v4, v8, v12); g(v, v1, v5, v9, v13); g(v, v2, v6, v10, v14); g(v, v3, v7, v11, v15)
        g(v, v0, v5, v10, v15); g(v, v1, v6, v11, v12); g(v, v2, v7, v8, v13); g(v, v3, v4, v9, v14)
    }

    private fun g(v: LongArray, a: Int, b: Int, c: Int, d: Int) {
        v[a] = blaMka(v[a], v[b]); v[d] = (v[d] xor v[a]).rotateRight(32)
        v[c] = blaMka(v[c], v[d]); v[b] = (v[b] xor v[c]).rotateRight(24)
        v[a] = blaMka(v[a], v[b]); v[d] = (v[d] xor v[a]).rotateRight(16)
        v[c] = blaMka(v[c], v[d]); v[b] = (v[b] xor v[c]).rotateRight(63)
    }

    private fun blaMka(x: Long, y: Long): Long = x + y + 2 * (x and 0xFFFFFFFFL) * (y and 0xFFFFFFFFL)

    /** Argon2's variable-length hash H'. */
    private fun variableHash(length: Int, input: ByteArray): ByteArray {
        if (length <= 64) return blake2b(length) { le32(length); update(input, 0, input.size) }
        val out = ByteArray(length)
        var v = blake2b(64) { le32(length); update(input, 0, input.size) }
        val fullChunks = (length + 31) / 32 - 2
        var offset = 0
        for (i in 0 until fullChunks) {
            System.arraycopy(v, 0, out, offset, 32)
            offset += 32
            if (i < fullChunks - 1) v = blake2b(64) { update(v, 0, 64) }
        }
        val remaining = length - offset
        val last = blake2b(remaining) { update(v, 0, 64) }
        System.arraycopy(last, 0, out, offset, remaining)
        return out
    }

    private inline fun blake2b(outLength: Int, feed: Blake2bDigest.() -> Unit): ByteArray {
        val digest = Blake2bDigest(outLength * 8)
        digest.feed()
        return ByteArray(outLength).also { digest.doFinal(it, 0) }
    }

    private fun Blake2bDigest.le32(value: Int) = update(intLe(value), 0, 4)

    private fun readBlock(memory: LongBuffer, index: Int, into: LongArray) {
        memory.position(index * WORDS)
        memory.get(into, 0, WORDS)
    }

    private fun writeBlock(memory: LongBuffer, index: Int, from: LongArray) {
        memory.position(index * WORDS)
        memory.put(from, 0, WORDS)
    }

    private fun bytesToWords(bytes: ByteArray): LongArray {
        val words = LongArray(WORDS)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer().get(words)
        return words
    }

    private fun wordsToBytes(words: LongArray): ByteArray {
        val buffer = ByteBuffer.allocate(BLOCK_BYTES).order(ByteOrder.LITTLE_ENDIAN)
        buffer.asLongBuffer().put(words)
        return buffer.array()
    }

    // --- ChaCha internals -------------------------------------------------------------------

    private fun chacha20(key: ByteArray, nonce: ByteArray, counter: Int, input: ByteArray): ByteArray {
        val engine = ChaCha7539Engine()
        engine.init(true, ParametersWithIV(KeyParameter(key), nonce))
        engine.skip(64L * counter)
        val out = ByteArray(input.size)
        engine.processBytes(input, 0, input.size, out, 0)
        return out
    }

    /** HChaCha20: derives the XChaCha20 subkey from the key and the first 16 nonce bytes. */
    internal fun hChaCha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        val keyWords = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN)
        val nonceWords = ByteBuffer.wrap(nonce16).order(ByteOrder.LITTLE_ENDIAN)
        val x = IntArray(16)
        x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574
        for (i in 0 until 8) x[4 + i] = keyWords.getInt(i * 4)
        for (i in 0 until 4) x[12 + i] = nonceWords.getInt(i * 4)
        repeat(10) {
            quarterRound(x, 0, 4, 8, 12); quarterRound(x, 1, 5, 9, 13)
            quarterRound(x, 2, 6, 10, 14); quarterRound(x, 3, 7, 11, 15)
            quarterRound(x, 0, 5, 10, 15); quarterRound(x, 1, 6, 11, 12)
            quarterRound(x, 2, 7, 8, 13); quarterRound(x, 3, 4, 9, 14)
        }
        val out = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until 4) out.putInt(x[i])
        for (i in 12 until 16) out.putInt(x[i])
        return out.array()
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(16)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(12)
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(8)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(7)
    }

    private fun intLe(value: Int): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()

    private fun longLe(value: Long): ByteArray =
        ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array()

    private const val BLOCK_BYTES = 1024
    private const val WORDS = 128
    private const val ARGON2_VERSION = 0x13
    private const val ARGON2_TYPE_ID = 2
    private const val SECRETSTREAM_ABYTES = 17
    private const val TAG_FINAL: Byte = 0x03
}

/** Provides the large scratch buffer Argon2 works in, and releases it afterwards. */
interface WorkingMemory {
    fun <T> use(sizeBytes: Int, block: (ByteBuffer) -> T): T
}

/** Plain buffer; fine for small parameters and JVM tests. */
object HeapWorkingMemory : WorkingMemory {
    override fun <T> use(sizeBytes: Int, block: (ByteBuffer) -> T): T = block(ByteBuffer.allocateDirect(sizeBytes))
}

class DecryptionFailedException : Exception("Wrong password, or the export file is damaged.")
