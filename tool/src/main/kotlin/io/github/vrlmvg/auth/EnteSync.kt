package io.github.vrlmvg.auth

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

data class SyncResult(val added: Int, val updated: Int, val removed: Int, val skipped: Int)

/**
 * One-way sync: Ente → this phone. Codes are kept in step with the account (edits update,
 * deletions and trashing remove them here).
 */
class EnteSync internal constructor(
    private val store: EnteSessionStore,
    private val repository: TotpAccountRepository,
    private val links: EnteLinkDao,
) {
    private val mutex = Mutex()

    suspend fun sync(): SyncResult = mutex.withLock {
        withContext(Dispatchers.IO) {
            val session = store.session() ?: throw EnteSessionExpiredException()
            val api = EnteApi(store.endpoint.first())
            try {
                var since = store.sinceTime()
                var added = 0; var updated = 0; var removed = 0; var skipped = 0
                while (true) {
                    val page = api.entityDiff(session.token, since)
                    if (page.diff.isEmpty()) break
                    for (entity in page.diff) {
                        when (apply(entity, session.authKey)) {
                            Change.Added -> added++
                            Change.Updated -> updated++
                            Change.Removed -> removed++
                            Change.Skipped -> skipped++
                            Change.None -> Unit
                        }
                    }
                    val next = page.diff.maxOf { it.updatedAt }
                    // A server that doesn't move forward would otherwise keep us here forever.
                    if (next <= since) break
                    since = next
                    if (page.diff.size < 500) break
                }
                store.recordSync(since, System.currentTimeMillis())
                SyncResult(added, updated, removed, skipped)
            } finally {
                api.close()
            }
        }
    }

    /** Removes every synced code (used when signing out). */
    suspend fun forgetSyncedCodes(): Int = mutex.withLock {
        withContext(Dispatchers.IO) {
            val all = links.all()
            all.forEach { repository.deleteAccount(it.accountId) }
            links.clear()
            all.size
        }
    }

    private enum class Change { Added, Updated, Removed, Skipped, None }

    private fun apply(entity: EnteEntity, authKey: ByteArray): Change {
        val linked = links.accountFor(entity.id)
        val code = if (entity.isDeleted) null else runCatching { EnteAccountCrypto.decryptEntity(entity, authKey) }.getOrNull()
        val account = code?.takeUnless { it.trashed }?.let { OtpAuthUriParser.parse(it.uri).getOrNull() }

        if (account == null) {
            // Deleted, trashed, undecryptable or not TOTP: make sure it isn't shown here.
            if (linked != null) {
                repository.deleteAccount(linked)
                links.remove(entity.id)
                return Change.Removed
            }
            return if (entity.isDeleted || code?.trashed == true) Change.None else Change.Skipped
        }

        return if (linked != null && repository.updateAccount(linked, account)) {
            Change.Updated
        } else {
            val stored = repository.addAccount(account)
            links.upsert(EnteLink(entity.id, stored.id))
            Change.Added
        }
    }
}
