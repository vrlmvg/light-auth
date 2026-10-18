package io.github.vrlmvg.auth

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import com.thelightphone.sdk.ui.LightText
import com.thelightphone.sdk.ui.LightTextVariant

@Composable
fun AccountListRow(
    account: StoredAccount,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxWidth()) {
        LightText(
            text = account.issuer.ifBlank { "Unknown" },
            variant = LightTextVariant.Copy,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        secondaryLabel(account.issuer, account.label)?.let { name ->
            LightText(
                text = name,
                variant = LightTextVariant.Detail,
                lighten = true,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/** The account name shown under the service, or null when it's empty or just repeats the service. */
internal fun secondaryLabel(issuer: String, label: String): String? =
    label.trim().takeIf { it.isNotEmpty() && !it.equals(issuer.trim(), ignoreCase = true) }
