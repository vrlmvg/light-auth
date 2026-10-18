package io.github.vrlmvg.auth

import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.engines.XSalsa20Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.math.ec.rfc7748.X25519
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/** The libsodium primitives behind an Ente account's key chain (besides Argon2id / secretstream). */
internal object EnteKeys {

    /** Ente's SRP "password": crypto_kdf_derive_from_key(32, 1, "loginctx", kek), first 16 bytes. */
    fun deriveLoginKey(keyEncryptionKey: ByteArray): ByteArray {
        val salt = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).putLong(1L).array()
        val personal = "loginctx".toByteArray(Charsets.US_ASCII) + ByteArray(8)
        val digest = Blake2bDigest(keyEncryptionKey, 32, salt, personal)
        val out = ByteArray(32)
        digest.doFinal(out, 0)
        return out.copyOf(16)
    }

    /** crypto_secretbox_open_easy (XSalsa20-Poly1305); input is MAC ‖ ciphertext. */
    fun secretBoxOpen(boxed: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        if (boxed.size < 16 || nonce.size != 24 || key.size != 32) throw DecryptionFailedException()
        val engine = XSalsa20Engine()
        engine.init(false, ParametersWithIV(KeyParameter(key), nonce))
        // The first 32 keystream bytes are the one-time Poly1305 key; the message follows.
        val polyKey = ByteArray(32)
        engine.processBytes(ByteArray(32), 0, 32, polyKey, 0)

        val cipherLength = boxed.size - 16
        val mac = Poly1305().apply { init(KeyParameter(polyKey)) }
        mac.update(boxed, 16, cipherLength)
        val expected = ByteArray(16).also { mac.doFinal(it, 0) }
        if (!MessageDigest.isEqual(expected, boxed.copyOfRange(0, 16))) throw DecryptionFailedException()

        val plain = ByteArray(cipherLength)
        engine.processBytes(boxed, 16, cipherLength, plain, 0)
        return plain
    }

    /** crypto_box_seal_open: ephemeral X25519 key ‖ box, nonce = BLAKE2b-24(epk ‖ pk). */
    fun sealedBoxOpen(sealed: ByteArray, publicKey: ByteArray, secretKey: ByteArray): ByteArray {
        if (sealed.size < 32 + 16) throw DecryptionFailedException()
        val ephemeralPublic = sealed.copyOfRange(0, 32)
        val nonce = Blake2bDigest(24 * 8).run {
            update(ephemeralPublic, 0, 32)
            update(publicKey, 0, publicKey.size)
            ByteArray(24).also { doFinal(it, 0) }
        }
        val shared = ByteArray(32)
        if (!X25519.calculateAgreement(secretKey, 0, ephemeralPublic, 0, shared, 0)) {
            throw DecryptionFailedException()
        }
        val boxKey = hSalsa20(shared, ByteArray(16))
        return secretBoxOpen(sealed.copyOfRange(32, sealed.size), nonce, boxKey)
    }

    /** HSalsa20 core (crypto_box_beforenm's key step). */
    internal fun hSalsa20(key: ByteArray, input16: ByteArray): ByteArray {
        val k = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN)
        val n = ByteBuffer.wrap(input16).order(ByteOrder.LITTLE_ENDIAN)
        val x = IntArray(16)
        x[0] = 0x61707865; x[5] = 0x3320646e; x[10] = 0x79622d32; x[15] = 0x6b206574
        for (i in 0 until 4) {
            x[1 + i] = k.getInt(i * 4)
            x[11 + i] = k.getInt(16 + i * 4)
            x[6 + i] = n.getInt(i * 4)
        }
        repeat(10) {
            // column round
            qr(x, 0, 4, 8, 12); qr(x, 5, 9, 13, 1); qr(x, 10, 14, 2, 6); qr(x, 15, 3, 7, 11)
            // row round
            qr(x, 0, 1, 2, 3); qr(x, 5, 6, 7, 4); qr(x, 10, 11, 8, 9); qr(x, 15, 12, 13, 14)
        }
        val out = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
        intArrayOf(0, 5, 10, 15, 6, 7, 8, 9).forEach { out.putInt(x[it]) }
        return out.array()
    }

    private fun qr(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[b] = x[b] xor (x[a] + x[d]).rotateLeft(7)
        x[c] = x[c] xor (x[b] + x[a]).rotateLeft(9)
        x[d] = x[d] xor (x[c] + x[b]).rotateLeft(13)
        x[a] = x[a] xor (x[d] + x[c]).rotateLeft(18)
    }
}
