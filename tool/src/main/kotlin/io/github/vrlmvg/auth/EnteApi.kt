package io.github.vrlmvg.auth

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.concurrent.TimeUnit

const val ENTE_DEFAULT_ENDPOINT = "https://api.ente.io"

class EnteAccountNotFoundException : Exception("No Ente account uses that email.")
class EnteWrongPasswordException : Exception("Incorrect password.")
class EnteWrongCodeException : Exception("That code is incorrect or has expired.")
class EnteSessionExpiredException : Exception("Your Ente session has ended. Sign in again.")
class EnteApiException(message: String) : Exception(message)

/** The few Ente ("museum") endpoints the Auth app uses to sign in and read codes. */
class EnteApi(private val endpoint: String = ENTE_DEFAULT_ENDPOINT) {
    private val json = Json { ignoreUnknownKeys = true }
    private val client = HttpClient(OkHttp) {
        expectSuccess = false
        engine {
            config {
                connectTimeout(15, TimeUnit.SECONDS)
                readTimeout(30, TimeUnit.SECONDS)
                writeTimeout(30, TimeUnit.SECONDS)
            }
        }
    }

    suspend fun srpAttributes(email: String): SrpAttributes {
        val response = get("/users/srp/attributes") { parameter("email", email) }
        if (response.status == HttpStatusCode.NotFound) throw EnteAccountNotFoundException()
        return decode<SrpAttributesEnvelope>(response).attributes
    }

    suspend fun createSrpSession(srpUserID: String, srpA: String): CreateSessionResponse =
        decode(post("/users/srp/create-session", CreateSessionRequest(srpUserID, srpA)))

    suspend fun verifySrpSession(sessionID: String, srpUserID: String, srpM1: String): EnteAuthResponse {
        val response = post("/users/srp/verify-session", VerifySessionRequest(sessionID, srpUserID, srpM1))
        if (response.status == HttpStatusCode.Unauthorized) throw EnteWrongPasswordException()
        return decode(response)
    }

    /** Emails a one-time code; used when the account has email verification turned on. */
    suspend fun sendLoginCode(email: String) {
        ensureOk(post("/users/ott", OttRequest(email, purpose = "login")))
    }

    suspend fun verifyEmail(email: String, code: String): EnteAuthResponse {
        val response = post("/users/verify-email", VerifyEmailRequest(email, code))
        if (response.status == HttpStatusCode.Unauthorized || response.status == HttpStatusCode.Gone) {
            throw EnteWrongCodeException()
        }
        return decode(response)
    }

    suspend fun verifyTwoFactor(sessionID: String, code: String): EnteAuthResponse {
        val response = post("/users/two-factor/verify", TwoFactorRequest(sessionID, code))
        if (response.status == HttpStatusCode.Unauthorized) throw EnteWrongCodeException()
        return decode(response)
    }

    suspend fun authKey(token: String): EnteAuthKey =
        decode(get("/authenticator/key") { header(AUTH_HEADER, token) })

    suspend fun entityDiff(token: String, sinceTime: Long, limit: Int = DIFF_PAGE_SIZE): EnteEntityDiff =
        decode(
            get("/authenticator/entity/diff") {
                header(AUTH_HEADER, token)
                parameter("sinceTime", sinceTime)
                parameter("limit", limit)
            },
        )

    fun close() = client.close()

    private suspend fun get(path: String, block: HttpRequestBuilder.() -> Unit = {}): HttpResponse =
        client.get(endpoint.trimEnd('/') + path) {
            header(CLIENT_PACKAGE_HEADER, ENTE_AUTH_PACKAGE)
            block()
        }

    private suspend inline fun <reified T> post(path: String, body: T): HttpResponse =
        client.post(endpoint.trimEnd('/') + path) {
            header(CLIENT_PACKAGE_HEADER, ENTE_AUTH_PACKAGE)
            contentType(ContentType.Application.Json)
            setBody(json.encodeToString(body))
        }

    private suspend inline fun <reified T> decode(response: HttpResponse): T {
        ensureOk(response)
        return json.decodeFromString(response.bodyAsText())
    }

    private suspend fun ensureOk(response: HttpResponse) {
        when {
            response.status.isSuccess() -> Unit
            response.status == HttpStatusCode.Unauthorized -> throw EnteSessionExpiredException()
            else -> {
                val detail = runCatching { response.bodyAsText().take(200) }.getOrDefault("")
                throw EnteApiException("Ente returned HTTP ${response.status.value}. $detail".trim())
            }
        }
    }

    @Serializable
    private data class SrpAttributesEnvelope(val attributes: SrpAttributes)

    @Serializable
    private data class CreateSessionRequest(val srpUserID: String, val srpA: String)

    @Serializable
    data class CreateSessionResponse(val sessionID: String, val srpB: String)

    @Serializable
    private data class VerifySessionRequest(val sessionID: String, val srpUserID: String, val srpM1: String)

    @Serializable
    private data class OttRequest(val email: String, val purpose: String)

    @Serializable
    private data class VerifyEmailRequest(val email: String, val ott: String)

    @Serializable
    private data class TwoFactorRequest(val sessionID: String, val code: String)

    private companion object {
        const val AUTH_HEADER = "X-Auth-Token"
        const val CLIENT_PACKAGE_HEADER = "X-Client-Package"
        // Ente scopes sessions per app; authenticator data is only served to the Auth app's sessions.
        const val ENTE_AUTH_PACKAGE = "io.ente.auth"
        const val DIFF_PAGE_SIZE = 500
    }
}
