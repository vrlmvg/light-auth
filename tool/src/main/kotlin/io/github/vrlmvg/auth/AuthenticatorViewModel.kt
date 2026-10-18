package io.github.vrlmvg.auth

import androidx.lifecycle.viewModelScope
import com.thelightphone.sdk.LightViewModel
import com.thelightphone.sdk.SimpleLightScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class AuthenticatorViewModel(
    private val repository: TotpAccountRepository,
    private val enteSync: EnteSync,
    private val enteStore: EnteSessionStore,
) : LightViewModel<Unit>() {
    private val _accounts = MutableStateFlow<List<StoredAccount>>(emptyList())
    val accounts: StateFlow<List<StoredAccount>> = _accounts.asStateFlow()

    private val _errorModal = MutableStateFlow<String?>(null)
    val errorModal: StateFlow<String?> = _errorModal.asStateFlow()

    init {
        reloadAccounts()
    }

    override fun onScreenShow(screen: SimpleLightScreen<Unit>) {
        reloadAccounts()
        syncFromEnteIfDue()
    }

    /** Pulls changes from Ente in the background when signed in and the last sync is a few minutes old. */
    private fun syncFromEnteIfDue() {
        viewModelScope.launch {
            if (enteStore.session() == null) return@launch
            val last = enteStore.lastSync.first() ?: 0L
            if (System.currentTimeMillis() - last < AUTO_SYNC_INTERVAL_MILLIS) return@launch
            runCatching { enteSync.sync() }
                .onSuccess { reloadAccounts() }
                .onFailure { if (it is EnteSessionExpiredException) showError("${it.message}\n\nOpen ENTE to sign in.") }
        }
    }

    fun showError(message: String) {
        _errorModal.value = message
    }

    fun dismissError() {
        _errorModal.value = null
    }

    private fun reloadAccounts() {
        viewModelScope.launch(Dispatchers.IO) {
            _accounts.value = repository.listAccounts()
        }
    }
}

private const val AUTO_SYNC_INTERVAL_MILLIS = 5 * 60 * 1000L
