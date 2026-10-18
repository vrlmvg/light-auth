package io.github.vrlmvg.auth

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.bouncycastle.crypto.agreement.srp.SRP6Server
import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator
import org.bouncycastle.crypto.digests.SHA256Digest
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The fixture is a fake Ente account built with libsodium (PyNaCl) the way Ente's clients build one. */
class EnteAccountTest {
    private val json = Json { ignoreUnknownKeys = true }
    private val fixture = json.parseToJsonElement(FIXTURE).jsonObject
    private fun str(key: String) = fixture[key]!!.jsonPrimitive.content

    private fun kek() = EnteAccountCrypto.deriveKek(
        password = str("password"),
        kekSalt = str("kekSalt"),
        memLimit = fixture["memLimit"]!!.jsonPrimitive.long,
        opsLimit = fixture["opsLimit"]!!.jsonPrimitive.int,
    )

    @Test
    fun derivesKekAndLoginKeyLikeLibsodium() {
        val kek = kek()
        assertEquals(str("kekHex"), kek.toHex())
        assertEquals(str("loginSubKeyHex"), EnteKeys.deriveLoginKey(kek).toHex())
    }

    @Test
    fun unlocksTokenAndAuthKeyThenDecryptsCodes() {
        val keyAttributes = json.decodeFromJsonElement<KeyAttributes>(fixture["keyAttributes"]!!)
        val (masterKey, token) = EnteAccountCrypto.unlock(keyAttributes, str("encryptedToken"), kek())
        assertEquals(str("tokenUrlSafe"), token)

        val authKey = EnteAccountCrypto.decryptAuthKey(json.decodeFromJsonElement(fixture["authKey"]!!), masterKey)
        val diff = json.decodeFromJsonElement<EnteEntityDiff>(JsonObject(mapOf("diff" to fixture["diff"]!!)))

        val codes = diff.diff.filterNot { it.isDeleted }.map { EnteAccountCrypto.decryptEntity(it, authKey) }
        assertEquals(3, codes.size)
        assertTrue(codes[0].uri.startsWith("otpauth://totp/Ente:"))
        assertFalse(codes[0].trashed)
        assertTrue(codes[1].uri.startsWith("otpauth://totp/Bitwarden:"))
        assertFalse(codes[1].trashed)
        assertTrue(codes[2].trashed)
        assertTrue(diff.diff.last().isDeleted)
    }

    @Test
    fun wrongPasswordCannotOpenMasterKey() {
        val keyAttributes = json.decodeFromJsonElement<KeyAttributes>(fixture["keyAttributes"]!!)
        val wrongKek = EnteAccountCrypto.deriveKek("wrong", str("kekSalt"), fixture["memLimit"]!!.jsonPrimitive.long, fixture["opsLimit"]!!.jsonPrimitive.int)
        assertFailsWith<DecryptionFailedException> { EnteAccountCrypto.unlock(keyAttributes, str("encryptedToken"), wrongKek) }
    }

    @Test
    fun trashedFlagInsideUriIsHonoured() {
        val uri = "otpauth://totp/X?secret=AAAA&codeDisplay=%7B%22pinned%22%3Afalse%2C%22trashed%22%3Atrue%7D"
        assertTrue(EnteAccountCrypto.parseEntityPlaintext("\"$uri\"").trashed)
    }

    @Test
    fun srpHandshakeAgreesWithRfc5054Server() {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val userId = "4e8b1c2a-srp-user"
        val loginKey = EnteKeys.deriveLoginKey(kek())

        // What Ente's apps register at signup (pointycastle's port of the same generator).
        val verifier = SRP6VerifierGenerator().run {
            init(SRP6StandardGroups.rfc5054_4096, SHA256Digest())
            generateVerifier(salt, userId.toByteArray(), loginKey)
        }
        val server = SRP6Server().apply { init(SRP6StandardGroups.rfc5054_4096, verifier, SHA256Digest(), SecureRandom()) }

        val client = EnteSrpClient(userId, Base64.getEncoder().encodeToString(salt), loginKey)
        assertEquals(512, Base64.getDecoder().decode(client.srpA).size)

        val b = server.generateServerCredentials()
        val m1 = client.evidence(Base64.getEncoder().encodeToString(b.toByteArray()))
        server.calculateSecret(BigInteger(1, Base64.getDecoder().decode(client.srpA)))
        assertTrue(server.verifyClientEvidenceMessage(BigInteger(1, Base64.getDecoder().decode(m1))))
        val m2 = server.calculateServerEvidenceMessage()
        assertTrue(client.verifyServer(Base64.getEncoder().encodeToString(m2.toByteArray())))
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    private companion object {
        const val FIXTURE = """{"password": "light phone rocks", "kekSalt": "XIogVKWmo/iVm7rSGwYF6w==", "memLimit": 8388608, "opsLimit": 2, "kekHex": "c009503d61597ee7804748f038aa1b5fe88aee9d69ecda511cd51bfd49effc7e", "loginSubKeyHex": "bc7981d652142ef6de60763504295c0f", "keyAttributes": {"kekSalt": "XIogVKWmo/iVm7rSGwYF6w==", "encryptedKey": "eEy+YWUe+AaUh2W16GvHQEcUPpso5uxyVlytPu/DwhsQfHPe4AuPj4+SSxRjau2p", "keyDecryptionNonce": "dg4zh84OO85DCDnPC12im6qiLJAstbBf", "publicKey": "ezJNrefE2ou1kku0zo3EsmE7peQCdzUi+TOvt1Hgk1s=", "encryptedSecretKey": "iYpbFQnmsb94zNOI7im8yoQC0sJWmS9+r+FJFxeIu5fv0e0SXOt00EzeQVkXQFpf", "secretKeyDecryptionNonce": "cDcRvla+Uw3Km8omE8SDWb5RSh7W7yZ6", "memLimit": 8388608, "opsLimit": 2}, "encryptedToken": "/z3g82WkdGaaV7RQ5syWcCITmDlwcLUFQfhpEy9B2AM2GmKVZZ1kLZtwRFPfGocl/Lu/rdCfg0xBEDxttP4EEBYZW/G6AHspvM9e8raWo0s=", "tokenUrlSafe": "dVwgDV6uF5eDnbHfhmfhxSAtYBi8M_y0RYJSkYMdeuw=", "authKey": {"encryptedKey": "KaUUdNhEvmkBS7XM36900Kwk/bm81AMkEGUYMBw9YZxKTI+lcCLLm1CTq+cJquJO", "header": "Sq1pxqDwHuONyXAfgmZuijY35YkkZbGu"}, "diff": [{"id": "e1", "encryptedData": "lP6eOrCuhy25lrsJIln0mUk2r1envkulxgF8iBXUe3CtsiDMXwQ9coR1x7wDbQib/vIU7Kil281zqthjTlr+54M31HD1rP+CFTOdUuXs6QZYx5n0mRc/2dpkhpEBE/llqS2GTu+xYgDHbzA5+wyqT/cFSVuVReuBQRhym2pycC0=", "header": "aPaMuuhmZ0kDBx4ImePsy+/ronjQ2zpt", "isDeleted": false, "updatedAt": 1760000000000001}, {"id": "e2", "encryptedData": "go1iuHHlX1m/A068Tp2jhmdEil0mGNb2VhhBEA4nvnfQwjGW7wfIYHC6xy7COdBFzyGSYBk68vqyJFjdkh4Vki8el0707faN+M2p7+AAzP6kH8Aw0RUJsl8a0ZiO0HsGIjofISqjBnkipejGhg/UgFjCW7Bb3o/PeEunW8aVXKoBdPA0JHinavHGqrCy2IGsTIYKbaS3", "header": "PqAUG6weEflSx8Kr1bPXFP0A+ih5OLtK", "isDeleted": false, "updatedAt": 1760000000000002}, {"id": "e3", "encryptedData": "pr1eDkw5WHaYMsM761zOCdY+XI9LCYdx0Ec+pwyPTJlk3FTXXgwUl62gPuaOh7XkxgpHeBt4Vb6NsY6mmERb9HDocbfxvpD44XKn+9MJL4ZcfX67pjDALVEs6vVg+IAKlytLkmKaDWrGlMBIB9GAXtPkswsWzS8f88TTwuH+dzn0", "header": "Ca9P2DS9YLIVNTMJgvNEJbkWNy5Ron5c", "isDeleted": false, "updatedAt": 1760000000000003}, {"id": "e4", "encryptedData": null, "header": null, "isDeleted": true, "updatedAt": 1760000000000004}]}"""
    }
}
