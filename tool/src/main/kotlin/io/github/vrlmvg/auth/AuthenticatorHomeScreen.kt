package io.github.vrlmvg.auth

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import com.thelightphone.sdk.InitialScreen
import com.thelightphone.sdk.LightScreen
import com.thelightphone.sdk.SealedLightActivity
import com.thelightphone.sdk.ui.LightBarButton
import com.thelightphone.sdk.ui.LightBottomBar
import com.thelightphone.sdk.ui.LightFullscreenModal
import com.thelightphone.sdk.ui.LightIcons
import com.thelightphone.sdk.ui.LightScrollView
import com.thelightphone.sdk.ui.LightText
import com.thelightphone.sdk.ui.LightTextVariant
import com.thelightphone.sdk.ui.LightTheme
import com.thelightphone.sdk.ui.LightThemeController
import com.thelightphone.sdk.ui.LightThemeTokens
import com.thelightphone.sdk.ui.LightTopBar
import com.thelightphone.sdk.ui.LightTopBarCenter
import com.thelightphone.sdk.ui.gridUnitsAsDp
import com.thelightphone.sdk.ui.lightClickable

@InitialScreen
class AuthenticatorHomeScreen(sealedActivity: SealedLightActivity) :
    LightScreen<Unit, AuthenticatorViewModel>(sealedActivity) {

    private val services by lazy { AuthServices.get(lightContext) }
    private val repository get() = services.repository

    override val viewModelClass: Class<AuthenticatorViewModel>
        get() = AuthenticatorViewModel::class.java

    override fun createViewModel() = AuthenticatorViewModel(repository, services.enteSync, services.enteStore)

    @Composable
    override fun Content() {
        val themeColors by LightThemeController.colors.collectAsState()
        val accounts by viewModel.accounts.collectAsState()
        val signedIn by viewModel.signedIn.collectAsState()
        val errorModal by viewModel.errorModal.collectAsState()

        LightTheme(colors = themeColors) {
            Box(modifier = Modifier.fillMaxSize()) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(LightThemeTokens.colors.background),
                ) {
                    LightTopBar(
                        center = LightTopBarCenter.Text("Ente Auth"),
                        modifier = Modifier.padding(bottom = 1f.gridUnitsAsDp()),
                    )

                    if (accounts.isEmpty()) {
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxWidth(),
                            contentAlignment = Alignment.Center,
                        ) {
                            LightText(
                                text = when (signedIn) {
                                    true -> "No codes in your Ente account yet. Add them in the Ente app."
                                    false -> "Sign in to your Ente account to see your codes."
                                    null -> ""
                                },
                                variant = LightTextVariant.Copy,
                                align = TextAlign.Center,
                                modifier = Modifier.padding(horizontal = 1f.gridUnitsAsDp()),
                            )
                        }
                    } else {
                        LightScrollView(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxWidth()
                                .padding(start = 1f.gridUnitsAsDp()),
                        ) {
                            accounts.forEach { account ->
                                AccountListRow(
                                    account = account,
                                    modifier = Modifier
                                        .lightClickable {
                                            navigateTo(screenFactory = {
                                                AuthenticatorCodeScreen(
                                                    it,
                                                    account.id,
                                                    repository
                                                )
                                            })
                                        }
                                        .padding(vertical = 0.75f.gridUnitsAsDp()),
                                )
                            }
                        }
                    }

                    fun goToEnte() {
                        navigateTo(screenFactory = { EnteScreen(it) })
                    }

                    LightBottomBar(
                        listOf(
                            LightBarButton.LightIcon(
                                icon = LightIcons.SETTINGS,
                                onClick = ::goToEnte,
                                contentDescription = "Settings",
                            ),
                            if (signedIn == false) LightBarButton.Text("SIGN IN", onClick = ::goToEnte) else null,
                            null,
                        ),
                    )
                }

                errorModal?.let { message ->
                    LightFullscreenModal(
                        message = message,
                        onClose = viewModel::dismissError,
                    )
                }
            }
        }
    }
}
