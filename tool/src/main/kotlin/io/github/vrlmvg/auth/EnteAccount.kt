package io.github.vrlmvg.auth

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.crypto.agreement.srp.SRP6Client
import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.util.BigIntegers
import java.math.BigInteger
import java.net.URI
import java.net.URLDecoder
import java.security.SecureRandom
import java.util.Base64

// --- Wire models (Ente museum API) ------------------------------------------------------------

@Serializable
data class SrpAttributes(
    val srpUserID: String,
    val srpSalt: String,
    val memLimit: Long,
    val opsLimit: Int,
    val kekSalt: String,
    val isEmailMFAEnabled: Boolean = false,
)

@Serializable
data class KeyAttributes(
    val kekSalt: String,
    val encryptedKey: String,
    val keyDecryptionNonce: String,
    val publicKey: String,
    val encryptedSecretKey: String,
    val secretKeyDecryptionNonce: String,
    val memLimit: Long? = null,
    val opsLimit: Int? = null,
)

/** Response of verify-session, verify-email and two-factor/verify. */
@Serializable
data class EnteAuthResponse(
    val id: Long? = null,
    val keyAttributes: KeyAttributes? = null,
    val encryptedToken: String? = null,
    val twoFactorSessionID: String? = null,
    val twoFactorSessionIDV2: String? = null,
    val passkeySessionID: String? = null,
    val srpM2: String? = null,
) {
    val pendingTwoFactorSession: String?
        get() = twoFactorSessionID?.takeIf { it.isNotEmpty() } ?: twoFactorSessionIDV2?.takeIf { it.isNotEmpty() }
}

@Serializable
data class EnteAuthKey(val encryptedKey: String, val header: String)

@Serializable
data class EnteEntity(
    val id: String,
    val encryptedData: String? = null,
    val header: String? = null,
    val isDeleted: Boolean = false,
    val updatedAt: Long,
)

@Serializable
data class EnteEntityDiff(val diff: List<EnteEntity> = emptyList(), val timestamp: Long? = null)

/** What a signed-in device keeps: enough to fetch and decrypt codes, nothing that unlocks the account. */
data class EnteSession(val token: String, val authKey: ByteArray)

/** A decrypted authenticator entry. */
data class EnteCode(val uri: String, val trashed: Boolean)

// --- Crypto chain -----------------------------------------------------------------------------

internal object EnteAccountCrypto {
    private val b64 = Base64.getDecoder()
    private val json = Json { ignoreUnknownKeys = true }

    /** Password → key-encryption key (Argon2id with the account's parameters). */
    fun deriveKek(
        password: String,
        kekSalt: String,
        memLimit: Long,
        opsLimit: Int,
        memory: WorkingMemory = HeapWorkingMemory,
        onProgress: (Float) -> Unit = {},
    ): ByteArray = EnteCrypto.argon2id(
        password = password.toByteArray(Charsets.UTF_8),
        salt = b64.decode(kekSalt),
        opsLimit = opsLimit,
        memLimitBytes = memLimit,
        memory = memory,
        onProgress = onProgress,
    )

    /** KEK → master key → X25519 secret key → session token (url-safe base64, as Ente sends it back). */
    fun unlock(keyAttributes: KeyAttributes, encryptedToken: String, kek: ByteArray): Pair<ByteArray, String> {
        val masterKey = EnteKeys.secretBoxOpen(
            b64.decode(keyAttributes.encryptedKey),
            b64.decode(keyAttributes.keyDecryptionNonce),
            kek,
        )
        val secretKey = EnteKeys.secretBoxOpen(
            b64.decode(keyAttributes.encryptedSecretKey),
            b64.decode(keyAttributes.secretKeyDecryptionNonce),
            masterKey,
        )
        val token = EnteKeys.sealedBoxOpen(b64.decode(encryptedToken), b64.decode(keyAttributes.publicKey), secretKey)
        secretKey.fill(0)
        return masterKey to Base64.getUrlEncoder().encodeToString(token)
    }

    fun decryptAuthKey(authKey: EnteAuthKey, masterKey: ByteArray): ByteArray =
        EnteKeys.secretBoxOpen(b64.decode(authKey.encryptedKey), b64.decode(authKey.header), masterKey)

    /** Entity plaintext is JSON: either "otpauth://…" or {"rawData": "otpauth://…", "display": {...}}. */
    fun decryptEntity(entity: EnteEntity, authKey: ByteArray): EnteCode {
        val plain = EnteCrypto.secretStreamDecrypt(
            b64.decode(entity.encryptedData ?: throw DecryptionFailedException()),
            authKey,
            b64.decode(entity.header ?: throw DecryptionFailedException()),
        ).toString(Charsets.UTF_8)
        return parseEntityPlaintext(plain)
    }

    fun parseEntityPlaintext(plain: String): EnteCode {
        val element = runCatching { json.parseToJsonElement(plain) }.getOrNull()
        val (uri, displayTrashed) = when {
            element is JsonPrimitive && element.isString -> element.content to null
            element is JsonObject -> {
                val raw = element["rawData"]?.jsonPrimitive?.contentOrNull ?: ""
                val trashed = (element["display"] as? JsonObject)?.get("trashed")?.jsonPrimitive?.booleanOrNull
                raw to trashed
            }
            else -> plain.trim() to null
        }
        return EnteCode(uri = uri, trashed = displayTrashed ?: trashedInUri(uri))
    }

    /** Newer Ente versions keep display flags in a codeDisplay={json} query parameter. */
    private fun trashedInUri(uri: String): Boolean {
        val query = runCatching { URI(uri).rawQuery }.getOrNull() ?: return false
        val raw = query.split('&').firstOrNull { it.startsWith("codeDisplay=") } ?: return false
        val value = URLDecoder.decode(raw.removePrefix("codeDisplay="), Charsets.UTF_8.name())
        return runCatching {
            json.parseToJsonElement(value).jsonObject["trashed"]?.jsonPrimitive?.booleanOrNull
        }.getOrNull() ?: false
    }
}

// --- SRP ------------------------------------------------------------------------------------

/**
 * SRP-6a client exactly as Ente's apps use it: RFC 5054 4096-bit group, SHA-256, identity is the
 * srpUserID and the "password" is the 16-byte login key. A is sent padded to 512 bytes, M1 to 32.
 */
internal class EnteSrpClient(srpUserId: String, srpSalt: String, loginKey: ByteArray) {
    private val client = SRP6Client().apply {
        init(SRP6StandardGroups.rfc5054_4096, SHA256Digest(), SecureRandom())
    }
    private val publicA: BigInteger = client.generateClientCredentials(
        Base64.getDecoder().decode(srpSalt),
        srpUserId.toByteArray(Charsets.UTF_8),
        loginKey,
    )

    val srpA: String = encode(publicA, 512)

    fun evidence(srpB: String): String {
        client.calculateSecret(BigInteger(1, Base64.getDecoder().decode(srpB)))
        return encode(client.calculateClientEvidenceMessage(), 32)
    }

    /** True when the server proved it knows the verifier too. */
    fun verifyServer(srpM2: String): Boolean =
        client.verifyServerEvidenceMessage(BigInteger(1, Base64.getDecoder().decode(srpM2)))

    private fun encode(value: BigInteger, length: Int): String =
        Base64.getEncoder().encodeToString(BigIntegers.asUnsignedByteArray(length, value))
}
