package io.github.vrlmvg.auth

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.util.Base64

/** Which local account each Ente entry was synced into, so edits and deletions in Ente follow. */
@Entity(tableName = "ente_links")
internal data class EnteLink(
    @PrimaryKey val enteId: String,
    val accountId: Long,
)

@Dao
internal interface EnteLinkDao {
    @Query("SELECT accountId FROM ente_links WHERE enteId = :enteId")
    fun accountFor(enteId: String): Long?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun upsert(link: EnteLink)

    @Query("DELETE FROM ente_links WHERE enteId = :enteId")
    fun remove(enteId: String)

    @Query("SELECT * FROM ente_links")
    fun all(): List<EnteLink>

    @Query("DELETE FROM ente_links")
    fun clear()
}

// Separate database file: the SDK's buildDatabase can't register migrations for the existing one.
@Database(entities = [EnteLink::class], version = 1, exportSchema = false)
abstract class EnteLinkDatabase : RoomDatabase() {
    internal abstract fun links(): EnteLinkDao

    companion object {
        const val NAME = "ente_links.db"
    }
}

/**
 * Persists the signed-in Ente session. Only the session token and the authenticator key are kept
 * (encrypted with the tool's Android Keystore key); the password, master key and secret key are not.
 */
class EnteSessionStore internal constructor(
    private val dataStore: DataStore<Preferences>,
    private val cipher: TotpSecretCipher,
) {
    val email: Flow<String?> = dataStore.data.map { it[EMAIL] }
    val lastSync: Flow<Long?> = dataStore.data.map { it[LAST_SYNC_MILLIS] }
    val endpoint: Flow<String> = dataStore.data.map { it[ENDPOINT] ?: ENTE_DEFAULT_ENDPOINT }

    suspend fun session(): EnteSession? {
        val prefs = dataStore.data.first()
        val token = prefs[TOKEN] ?: return null
        val authKey = prefs[AUTH_KEY] ?: return null
        return runCatching {
            EnteSession(
                token = cipher.decrypt(decode(token)),
                authKey = decode(cipher.decrypt(decode(authKey))),
            )
        }.getOrNull()
    }

    suspend fun save(email: String, session: EnteSession) {
        dataStore.edit {
            it[EMAIL] = email
            it[TOKEN] = encode(cipher.encrypt(session.token))
            it[AUTH_KEY] = encode(cipher.encrypt(encode(session.authKey)))
            it[SINCE_TIME] = 0
        }
    }

    suspend fun sinceTime(): Long = dataStore.data.first()[SINCE_TIME] ?: 0

    suspend fun recordSync(sinceTime: Long, atMillis: Long) {
        dataStore.edit {
            it[SINCE_TIME] = sinceTime
            it[LAST_SYNC_MILLIS] = atMillis
        }
    }

    suspend fun setEndpoint(url: String) {
        dataStore.edit { prefs ->
            if (url.isBlank() || url == ENTE_DEFAULT_ENDPOINT) prefs.remove(ENDPOINT) else prefs[ENDPOINT] = url.trim()
        }
    }

    suspend fun clear() {
        dataStore.edit {
            it.remove(EMAIL); it.remove(TOKEN); it.remove(AUTH_KEY)
            it.remove(SINCE_TIME); it.remove(LAST_SYNC_MILLIS)
        }
    }

    private fun encode(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
    private fun decode(text: String) = Base64.getDecoder().decode(text)

    private companion object {
        val EMAIL = stringPreferencesKey("ente_email")
        val TOKEN = stringPreferencesKey("ente_token")
        val AUTH_KEY = stringPreferencesKey("ente_auth_key")
        val ENDPOINT = stringPreferencesKey("ente_endpoint")
        val SINCE_TIME = longPreferencesKey("ente_since_time")
        val LAST_SYNC_MILLIS = longPreferencesKey("ente_last_sync")
    }
}
