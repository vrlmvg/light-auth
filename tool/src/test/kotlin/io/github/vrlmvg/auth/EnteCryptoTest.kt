package io.github.vrlmvg.auth

import kotlin.test.Test
import kotlin.test.assertEquals

/** Reference values were produced with libsodium (via PyNaCl) crypto_pwhash. */
class EnteCryptoTest {

    @Test
    fun argon2idMatchesLibsodium() {
        val salt = ByteArray(16) { it.toByte() }
        val cases = listOf(
            Triple(8192L, 1, "3a008963c65f7ffa7331a90babd1fd17ea9f03bd05356b857ceb43f7b7080adc"),
            Triple(65536L, 2, "716882821df77bc6414358b07159fb63ca1c90beaeb9d0ca0e43bd887dcf2ca9"),
            Triple(1048576L, 3, "8f92a1acc0c0509e55d57b2be709a525017461f8f29d51008c6a0b247f0d1748"),
            Triple(8388608L, 2, "937638fd13ac494fa6fd1cc6b6e8006c577546db9fc516ecfd8dd6a982b1c2eb"),
        )
        for ((mem, ops, expected) in cases) {
            val key = EnteCrypto.argon2id("password".toByteArray(), salt, ops, mem)
            assertEquals(expected, key.toHex(), "mem=$mem ops=$ops")
        }
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
}
