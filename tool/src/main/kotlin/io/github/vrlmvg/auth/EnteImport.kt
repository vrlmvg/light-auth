package io.github.vrlmvg.auth

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.Base64

/** Ente Auth's encrypted export file (Settings → Data → Export codes → Encrypted). */
@Serializable
data class EnteEncryptedExport(
    val version: Int,
    val kdfParams: EnteKdfParams,
    val encryptedData: String,
    val encryptionNonce: String,
)

@Serializable
data class EnteKdfParams(
    val memLimit: Long,
    val opsLimit: Int,
    val salt: String,
)

sealed interface ImportSource {
    /** Ente's plain-text export: one otpauth:// URI per line. */
    data class PlainText(val text: String) : ImportSource

    /** Ente's encrypted export; needs the export password. */
    data class Encrypted(val export: EnteEncryptedExport) : ImportSource {
        val memoryMiB: Long get() = export.kdfParams.memLimit / (1024 * 1024)
    }
}

data class ImportResult(
    val accounts: List<Account>,
    /** Entries that are not TOTP (HOTP, Steam) or could not be parsed. */
    val skipped: Int,
)

class UnrecognisedImportFileException : Exception("This doesn't look like an Ente Auth export.")

object EnteImport {
    private val json = Json { ignoreUnknownKeys = true }

    fun detect(content: String): ImportSource {
        val trimmed = content.trim()
        if (trimmed.startsWith("{")) {
            val export = runCatching { json.decodeFromString<EnteEncryptedExport>(trimmed) }
                .getOrElse { throw UnrecognisedImportFileException() }
            if (export.version != 1) throw UnrecognisedImportFileException()
            return ImportSource.Encrypted(export)
        }
        if (trimmed.lineSequence().any { it.trim().startsWith("otpauth://", ignoreCase = true) }) {
            return ImportSource.PlainText(trimmed)
        }
        throw UnrecognisedImportFileException()
    }

    /** Derives the key from [password] (slow: Ente uses 256 MiB–1 GiB Argon2id) and decrypts. */
    fun decrypt(
        source: ImportSource.Encrypted,
        password: String,
        memory: WorkingMemory = HeapWorkingMemory,
        onProgress: (Float) -> Unit = {},
    ): String {
        val export = source.export
        val decoder = Base64.getDecoder()
        val key = EnteCrypto.argon2id(
            password = password.toByteArray(Charsets.UTF_8),
            salt = decoder.decode(export.kdfParams.salt),
            opsLimit = export.kdfParams.opsLimit,
            memLimitBytes = export.kdfParams.memLimit,
            memory = memory,
            onProgress = onProgress,
        )
        val plain = EnteCrypto.secretStreamDecrypt(
            cipher = decoder.decode(export.encryptedData),
            key = key,
            header = decoder.decode(export.encryptionNonce),
        )
        key.fill(0)
        return plain.toString(Charsets.UTF_8)
    }

    fun parseCodes(text: String): ImportResult {
        val lines = text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        val accounts = lines.mapNotNull { line ->
            runCatching { OtpAuthUriParser.parse(line).getOrNull() }.getOrNull()
        }
        return ImportResult(accounts = accounts, skipped = lines.size - accounts.size)
    }
}
