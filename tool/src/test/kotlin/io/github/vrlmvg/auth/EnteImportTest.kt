package io.github.vrlmvg.auth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

/**
 * Reference values were produced with libsodium (via PyNaCl): Argon2id outputs from
 * crypto_pwhash, and the export from crypto_secretstream_xchacha20poly1305 exactly as Ente does.
 */
class EnteImportTest {

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

    @Test
    fun decryptsEnteEncryptedExport() {
        val source = EnteImport.detect(EXPORT)
        assertIs<ImportSource.Encrypted>(source)
        val text = EnteImport.decrypt(source, "correct horse battery")
        val result = EnteImport.parseCodes(text)

        assertEquals(listOf("GitHub", "Fastmail", "Proton"), result.accounts.map { it.issuer })
        assertEquals("alice@example.com", result.accounts[1].label)
        assertEquals(8, result.accounts[1].digits)
        assertEquals(0, result.skipped)
    }

    @Test
    fun wrongPasswordFails() {
        val source = EnteImport.detect(EXPORT) as ImportSource.Encrypted
        assertFailsWith<DecryptionFailedException> { EnteImport.decrypt(source, "wrong") }
    }

    @Test
    fun parsesPlainTextExportAndSkipsUnsupported() {
        val text = """
            otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
            otpauth://hotp/Bank?secret=JBSWY3DPEHPK3PXP&counter=3
            otpauth://steam/Steam:alice?secret=JBSWY3DPEHPK3PXP

        """.trimIndent()
        assertIs<ImportSource.PlainText>(EnteImport.detect(text))
        val result = EnteImport.parseCodes(text)
        assertEquals(listOf("GitHub"), result.accounts.map { it.issuer })
        assertEquals(2, result.skipped)
    }

    @Test
    fun rejectsOtherFiles() {
        assertFailsWith<UnrecognisedImportFileException> { EnteImport.detect("hello") }
        assertFailsWith<UnrecognisedImportFileException> { EnteImport.detect("{\"foo\": 1}") }
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    private companion object {
        const val EXPORT = """{"version": 1, "kdfParams": {"memLimit": 8388608, "opsLimit": 2, "salt": "nAQwwHAoTN/bqi6FSf53Mg=="}, "encryptedData": "BxfC6xRlEJ3OPWcO9ElOWrw97V7CAOqAERXzYZWo0d+lncSICtXuGSNMIQCHRDrwsRHG4a2fOnFX5xYVXVVRNUz25SyaNgjRlZ3z0Fid4C1BHtYfdqZVsOO0bzDmG3M0vtJzLsyQWYBCaW6ZrzGOxm3kUivXQ40CYvlZ/CuKKcM6V1bv4bGzGTvHjjHrFJhMfV8t5tLQQ5OU5P4x0yKazqAyGWfKxKc7V7v2Qqn+jxGUCiG0+Ta4+SJtmMFRPJwHktN624Y+UUNg7XBP9z+EXHAI6TrI/aJbIdha8lr1nfxYuYE1qjzax19mVRbJbFhGRs3jQPNyVxpFKjEJFsEVlc9QSOepTYChWlYq7AjcqiiDR9rgnmU1s7f/RtXEgbpoQFKhI68n1nnWqk/EC0G647KlfMY62fNchgB9YK2w1MgudI45M01qO/uVFLq51otc7T+auHKtE4jbRAdVbvHBY0d+ez7FnL6qvbJ9WqGs3jaeow==", "encryptionNonce": "g8k/ZfObvY+dwN+qf39QXd48O/GfD28R"}"""
    }
}
