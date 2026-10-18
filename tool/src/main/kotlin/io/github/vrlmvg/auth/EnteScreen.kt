package io.github.vrlmvg.auth

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.lifecycle.viewModelScope
import com.thelightphone.sdk.LightScreen
import com.thelightphone.sdk.LightViewModel
import com.thelightphone.sdk.SealedLightActivity
import com.thelightphone.sdk.rememberKeyboardOptions
import com.thelightphone.sdk.ui.LightBarButton
import com.thelightphone.sdk.ui.LightBottomBar
import com.thelightphone.sdk.ui.LightFullscreenModal
import com.thelightphone.sdk.ui.LightIcons
import com.thelightphone.sdk.ui.LightProgressBar
import com.thelightphone.sdk.ui.LightText
import com.thelightphone.sdk.ui.LightTextInputEditor
import com.thelightphone.sdk.ui.LightTextVariant
import com.thelightphone.sdk.ui.LightTheme
import com.thelightphone.sdk.ui.LightThemeController
import com.thelightphone.sdk.ui.LightThemeTokens
import com.thelightphone.sdk.ui.LightTopBar
import com.thelightphone.sdk.ui.LightTopBarCenter
import com.thelightphone.sdk.ui.gridUnitsAsDp
import com.thelightphone.sdk.ui.lightClickable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface EnteStep {
    /** Signed out / signed in overview, depending on [EnteUi.email]. */
    data object Overview : EnteStep
    data object EnterEmail : EnteStep
    data object EnterServer : EnteStep
    data class EnterEmailCode(val email: String) : EnteStep
    data object EnterPassword : EnteStep
    data class EnterTwoFactor(val sessionId: String) : EnteStep
    data class Working(val message: String, val progress: Float? = null) : EnteStep
    data object ConfirmSignOut : EnteStep
}

data class EnteUi(
    val step: EnteStep = EnteStep.Overview,
    val email: String? = null,
    val endpoint: String = ENTE_DEFAULT_ENDPOINT,
    val lastSyncMillis: Long? = null,
    val inputSession: Int = 0,
    val message: String? = null,
)

class EnteViewModel(private val services: AuthServices.Services) : LightViewModel<Unit>() {
    private val store = services.enteStore
    private val step = MutableStateFlow<EnteStep>(EnteStep.Overview)
    private val inputSession = MutableStateFlow(0)
    private val message = MutableStateFlow<String?>(null)

    val ui: StateFlow<EnteUi> = combine(step, store.email, store.endpoint, store.lastSync, combine(inputSession, message, ::Pair)) {
            step, email, endpoint, lastSync, (session, msg) ->
        EnteUi(step, email, endpoint, lastSync, session, msg)
    }.stateIn(viewModelScope, SharingStarted.Eagerly, EnteUi())

    // Sign-in progress, held in memory only.
    private var loginEmail: String = ""
    private var srpAttributes: SrpAttributes? = null
    private var pendingResponse: EnteAuthResponse? = null
    private var keyEncryptionKey: ByteArray? = null

    fun startSignIn() = go(EnteStep.EnterEmail)

    fun editServer() = go(EnteStep.EnterServer)

    fun saveServer(text: CharSequence) {
        viewModelScope.launch {
            val url = text.toString().trim().trimEnd('/')
            if (url.isNotEmpty() && !url.startsWith("http://") && !url.startsWith("https://")) {
                showError("Enter a full address, like https://ente.example.com")
                return@launch
            }
            store.setEndpoint(url)
            go(EnteStep.Overview)
        }
    }

    fun submitEmail(text: CharSequence) {
        val email = text.toString().trim()
        if (!email.contains('@')) return showError("Enter the email address of your Ente account.")
        loginEmail = email
        working("Checking account…")
        launchApi(onError = { go(EnteStep.EnterEmail) }) { api ->
            val attributes = api.srpAttributes(email)
            srpAttributes = attributes
            if (attributes.isEmailMFAEnabled) {
                api.sendLoginCode(email)
                go(EnteStep.EnterEmailCode(email))
            } else {
                go(EnteStep.EnterPassword)
            }
        }
    }

    fun submitEmailCode(text: CharSequence) {
        val code = text.toString().trim()
        if (code.isEmpty()) return
        working("Verifying code…")
        launchApi(onError = { go(EnteStep.EnterEmailCode(loginEmail)) }) { api ->
            handleAuthResponse(api.verifyEmail(loginEmail, code))
        }
    }

    fun submitPassword(text: CharSequence) {
        val password = text.toString()
        if (password.isEmpty()) return
        val attributes = srpAttributes ?: return go(EnteStep.EnterEmail)
        working("Unlocking your account…", 0f)
        launchApi(onError = { go(EnteStep.EnterPassword) }) { api ->
            val response = pendingResponse
            // Account keys may use their own Argon2 parameters; fall back to the SRP ones.
            val keyAttributes = response?.keyAttributes
            val kek = withContext(Dispatchers.Default) {
                EnteAccountCrypto.deriveKek(
                    password = password,
                    kekSalt = keyAttributes?.kekSalt ?: attributes.kekSalt,
                    memLimit = keyAttributes?.memLimit ?: attributes.memLimit,
                    opsLimit = keyAttributes?.opsLimit ?: attributes.opsLimit,
                    memory = SharedWorkingMemory,
                ) { progress -> step.value = EnteStep.Working("Unlocking your account…", progress) }
            }
            keyEncryptionKey = kek
            if (response != null) {
                // Email-code path: the server already let us in; the password only opens the keys.
                finish(api, response)
            } else {
                working("Signing in…")
                val srp = EnteSrpClient(attributes.srpUserID, attributes.srpSalt, EnteKeys.deriveLoginKey(kek))
                val session = api.createSrpSession(attributes.srpUserID, srp.srpA)
                val verified = api.verifySrpSession(session.sessionID, attributes.srpUserID, srp.evidence(session.srpB))
                // Ente's mobile app doesn't check the server's M2 either; the keys are still opened
                // locally with the password, so a mismatch here isn't treated as fatal.
                handleAuthResponse(verified)
            }
        }
    }

    fun submitTwoFactor(text: CharSequence) {
        val code = text.toString().filter(Char::isDigit)
        val current = step.value as? EnteStep.EnterTwoFactor ?: return
        if (code.length != 6) return showError("Enter the 6-digit code from your authenticator app.")
        working("Verifying code…")
        launchApi(onError = { go(current) }) { api ->
            handleAuthResponse(api.verifyTwoFactor(current.sessionId, code))
        }
    }

    fun syncNow() {
        working("Syncing codes…")
        viewModelScope.launch {
            val result = runCatching { services.enteSync.sync() }
            go(EnteStep.Overview)
            result.fold(
                onSuccess = { message.value = describe(it) },
                onFailure = { message.value = errorText(it) },
            )
        }
    }

    fun askSignOut() = go(EnteStep.ConfirmSignOut)

    fun signOut() {
        working("Signing out…")
        viewModelScope.launch {
            val removed = services.enteSync.forgetSyncedCodes()
            store.clear()
            go(EnteStep.Overview)
            message.value = "Signed out. Removed $removed synced ${if (removed == 1) "code" else "codes"} from this phone."
        }
    }

    fun dismissMessage() {
        message.value = null
    }

    override fun onBackPressed(): Boolean = when (step.value) {
        EnteStep.Overview -> false
        is EnteStep.Working -> true
        else -> {
            resetLogin()
            go(EnteStep.Overview)
            true
        }
    }

    private suspend fun handleAuthResponse(response: EnteAuthResponse) {
        val twoFactor = response.pendingTwoFactorSession
        when {
            twoFactor != null -> go(EnteStep.EnterTwoFactor(twoFactor))
            !response.passkeySessionID.isNullOrEmpty() -> throw EnteApiException(
                "This account uses a passkey for two-factor sign-in, which Light Phone can't do. " +
                    "Add authenticator-app 2FA in Ente as well, then try again.",
            )
            response.keyAttributes == null || response.encryptedToken == null ->
                throw EnteApiException("Ente's response was missing account keys.")
            keyEncryptionKey == null -> {
                // Email-code sign-in: ask for the password to open the keys.
                pendingResponse = response
                go(EnteStep.EnterPassword)
            }
            else -> EnteApi(store.endpoint.first()).use { finish(it, response) }
        }
    }

    private suspend fun finish(api: EnteApi, response: EnteAuthResponse) {
        working("Fetching your codes…")
        val kek = keyEncryptionKey ?: throw EnteWrongPasswordException()
        val (masterKey, token) = try {
            EnteAccountCrypto.unlock(response.keyAttributes!!, response.encryptedToken!!, kek)
        } catch (e: DecryptionFailedException) {
            throw EnteWrongPasswordException()
        }
        val authKey = EnteAccountCrypto.decryptAuthKey(api.authKey(token), masterKey)
        masterKey.fill(0)
        store.save(loginEmail, EnteSession(token, authKey))
        resetLogin()
        val result = services.enteSync.sync()
        go(EnteStep.Overview)
        message.value = "Signed in.\n\n" + describe(result)
    }

    private fun launchApi(onError: () -> Unit, block: suspend (EnteApi) -> Unit) {
        viewModelScope.launch {
            val api = EnteApi(store.endpoint.first())
            try {
                block(api)
            } catch (e: Throwable) {
                onError()
                message.value = errorText(e)
            } finally {
                api.close()
            }
        }
    }

    private fun describe(result: SyncResult): String = buildString {
        val changes = listOfNotNull(
            result.added.takeIf { it > 0 }?.let { "$it added" },
            result.updated.takeIf { it > 0 }?.let { "$it updated" },
            result.removed.takeIf { it > 0 }?.let { "$it removed" },
        )
        append(if (changes.isEmpty()) "Your codes are up to date." else "Codes: ${changes.joinToString(", ")}.")
        if (result.skipped > 0) append("\n${result.skipped} skipped (only TOTP codes are supported).")
    }

    private fun errorText(e: Throwable): String = when (e) {
        is EnteAccountNotFoundException, is EnteWrongPasswordException, is EnteWrongCodeException,
        is EnteSessionExpiredException, is EnteApiException -> e.message!!
        is OutOfMemoryError -> "Not enough free memory to unlock your account. Close other tools and try again."
        else -> "Couldn't reach Ente. Check your connection and try again."
    }

    private fun resetLogin() {
        srpAttributes = null
        pendingResponse = null
        keyEncryptionKey?.fill(0)
        keyEncryptionKey = null
    }

    private fun go(next: EnteStep) {
        if (next is EnteStep.EnterEmail || next is EnteStep.EnterServer || next is EnteStep.EnterEmailCode ||
            next is EnteStep.EnterPassword || next is EnteStep.EnterTwoFactor
        ) {
            inputSession.update { it + 1 }
        }
        step.value = next
    }

    private fun working(text: String, progress: Float? = null) {
        step.value = EnteStep.Working(text, progress)
    }

    private fun showError(text: String) {
        message.value = text
    }

    override fun onCleared() {
        resetLogin()
        super.onCleared()
    }
}

private inline fun <T> EnteApi.use(block: (EnteApi) -> T): T = try { block(this) } finally { close() }

class EnteScreen(sealedActivity: SealedLightActivity) : LightScreen<Unit, EnteViewModel>(sealedActivity) {

    override val viewModelClass: Class<EnteViewModel>
        get() = EnteViewModel::class.java

    override fun createViewModel() = EnteViewModel(AuthServices.get(lightContext))

    @Composable
    override fun Content() {
        val themeColors by LightThemeController.colors.collectAsState()
        val ui by viewModel.ui.collectAsState()
        val field = rememberTextFieldState("")
        val keyboardOptionsFlow = rememberKeyboardOptions()

        LaunchedEffect(ui.inputSession) {
            when (ui.step) {
                EnteStep.EnterServer -> field.setTextAndPlaceCursorAtEnd(ui.endpoint)
                else -> field.clearText()
            }
        }

        LightTheme(colors = themeColors) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(LightThemeTokens.colors.background),
            ) {
                @Composable
                fun editor(title: String, submitLabel: String, onSubmit: (CharSequence) -> Unit) = LightTextInputEditor(
                    title = title,
                    state = field,
                    keyboardOptionsFlow = keyboardOptionsFlow,
                    onSubmit = onSubmit,
                    onBack = { goBack() },
                    submitLabel = submitLabel,
                    singleLine = true,
                    editorKey = ui.inputSession,
                    modifier = Modifier.fillMaxSize(),
                )

                when (val step = ui.step) {
                    EnteStep.EnterEmail -> editor("Ente email", "NEXT", viewModel::submitEmail)
                    EnteStep.EnterServer -> editor("Ente server", "SAVE", viewModel::saveServer)
                    is EnteStep.EnterEmailCode -> editor("Code sent to ${step.email}", "VERIFY", viewModel::submitEmailCode)
                    EnteStep.EnterPassword -> editor("Ente password", "SIGN IN", viewModel::submitPassword)
                    is EnteStep.EnterTwoFactor -> editor("Two-factor code", "VERIFY", viewModel::submitTwoFactor)
                    else -> Column(modifier = Modifier.fillMaxSize()) {
                        LightTopBar(
                            leftButton = if (step is EnteStep.Working) null else LightBarButton.LightIcon(
                                icon = LightIcons.BACK,
                                onClick = { goBack() },
                                contentDescription = "Back",
                            ),
                            center = LightTopBarCenter.Text("Settings"),
                            modifier = Modifier.padding(bottom = 1f.gridUnitsAsDp()),
                        )
                        when (step) {
                            is EnteStep.Working -> Working(step)
                            EnteStep.ConfirmSignOut -> ConfirmSignOut()
                            else -> Overview(ui)
                        }
                    }
                }

                ui.message?.let { LightFullscreenModal(message = it, onClose = viewModel::dismissMessage) }
            }
        }
    }

    @Composable
    private fun ColumnScope.Overview(ui: EnteUi) {
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 1f.gridUnitsAsDp()),
        ) {
            if (ui.email == null) {
                Row("Account", "Sign in to Ente", viewModel::startSignIn)
                Row("From a file", "Import an export", ::openImport)
                Row("Server", ui.endpoint.removePrefix("https://"), viewModel::editServer)
            } else {
                Row("Signed in as", ui.email, null)
                Row(lastSyncLabel(ui.lastSyncMillis), "Sync now", viewModel::syncNow)
                Row("From a file", "Import an export", ::openImport)
                Row("Account", "Sign out", viewModel::askSignOut)
            }
        }
        LightText(
            text = "Codes sync one way, from Ente to this phone.",
            variant = LightTextVariant.Detail,
            lighten = true,
            align = TextAlign.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(1f.gridUnitsAsDp()),
        )
    }

    @Composable
    private fun Row(label: String, value: String, onClick: (() -> Unit)?) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .then(if (onClick != null) Modifier.lightClickable(onClick = onClick) else Modifier)
                .padding(vertical = 0.75f.gridUnitsAsDp()),
        ) {
            LightText(text = label, variant = LightTextVariant.Detail, lighten = true)
            LightText(text = value, variant = LightTextVariant.Heading)
        }
    }

    @Composable
    private fun ColumnScope.Working(step: EnteStep.Working) {
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 2f.gridUnitsAsDp()),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            LightText(step.message, variant = LightTextVariant.Copy, align = TextAlign.Center)
            step.progress?.let { progress ->
                Box(Modifier.padding(vertical = 1f.gridUnitsAsDp())) {
                    LightProgressBar(colors = LightThemeTokens.colors, progress = progress)
                }
                LightText(
                    "Ente protects your keys with a deliberately slow password check. This can take a minute.",
                    variant = LightTextVariant.Detail,
                    lighten = true,
                    align = TextAlign.Center,
                )
            }
        }
    }

    @Composable
    private fun ColumnScope.ConfirmSignOut() {
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 1f.gridUnitsAsDp()),
            contentAlignment = Alignment.Center,
        ) {
            LightText(
                "Sign out of Ente?\n\nCodes synced from Ente will be removed from this phone. Codes you added here stay.",
                variant = LightTextVariant.Copy,
                align = TextAlign.Center,
            )
        }
        LightBottomBar(
            listOf(
                LightBarButton.LightIcon(LightIcons.CLOSE, onClick = { goBack() }, contentDescription = "Cancel"),
                LightBarButton.Text("SIGN OUT", onClick = viewModel::signOut),
                null,
            ),
        )
    }

    private fun openImport() {
        navigateTo(screenFactory = { ImportScreen(it, AuthServices.get(lightContext).repository) })
    }

    private fun lastSyncLabel(millis: Long?): String {
        if (millis == null) return "Not synced yet"
        val minutes = (System.currentTimeMillis() - millis) / 60_000
        return when {
            minutes < 1 -> "Synced just now"
            minutes < 60 -> "Synced $minutes min ago"
            minutes < 24 * 60 -> "Synced ${minutes / 60} hr ago"
            else -> "Synced ${minutes / (24 * 60)} days ago"
        }
    }
}
