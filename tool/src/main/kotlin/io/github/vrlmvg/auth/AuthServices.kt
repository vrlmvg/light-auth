package io.github.vrlmvg.auth

import com.thelightphone.sdk.SealedLightContext
import com.thelightphone.sdk.buildDatabase

/** Process-wide instances shared by the screens (Room databases must be singletons). */
object AuthServices {
    @Volatile private var services: Services? = null

    class Services internal constructor(
        val repository: TotpAccountRepository,
        val enteStore: EnteSessionStore,
        val enteSync: EnteSync,
    )

    fun get(context: SealedLightContext): Services = services ?: synchronized(this) {
        services ?: run {
            val repository = TotpAccountRepository.getInstance {
                context.buildDatabase(TotpDatabase::class.java, TotpAccountRepository.DATABASE_NAME)
            }
            val links = context.buildDatabase(EnteLinkDatabase::class.java, EnteLinkDatabase.NAME).links()
            val store = EnteSessionStore(context.dataStore, TotpSecretCipher())
            Services(repository, store, EnteSync(store, repository, links))
        }.also { services = it }
    }
}
