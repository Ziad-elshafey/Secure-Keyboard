package com.frogobox.appkeyboard.data.remote

import com.frogobox.appkeyboard.data.local.AuthTokenManager
import com.frogobox.appkeyboard.data.remote.dto.RefreshTokenRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.Authenticator
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route

/**
 * OkHttp [Authenticator] that automatically refreshes the access token
 * when a 401 response is received.
 *
 * Thread-safe: uses [synchronized] to serialize concurrent refresh attempts.
 * Only the first thread entering the lock actually calls the server; others
 * reuse the token that was already refreshed.
 */
class TokenRefreshAuthenticator(
    private val tokenManager: AuthTokenManager,
    private val apiProvider: () -> SecureApiService
) : Authenticator {

    private val refreshLock = Any()

    override fun authenticate(route: Route?, response: Response): Request? {
        if (response.request.header("X-Token-Refreshed") != null || responseCount(response) >= 2) {
            return null
        }

        val requestAccessToken = response.request.header("Authorization")
            ?.removePrefix("Bearer ")
            ?.trim()
        val cachedAccessToken = tokenManager.getAccessToken()

        if (!cachedAccessToken.isNullOrBlank() && cachedAccessToken != requestAccessToken) {
            return response.request.newBuilder()
                .header("Authorization", "Bearer $cachedAccessToken")
                .header("X-Token-Refreshed", "true")
                .build()
        }

        return synchronized(refreshLock) {
            val latestAccessToken = tokenManager.getAccessToken()
            if (!latestAccessToken.isNullOrBlank() && latestAccessToken != requestAccessToken) {
                return@synchronized response.request.newBuilder()
                    .header("Authorization", "Bearer $latestAccessToken")
                    .header("X-Token-Refreshed", "true")
                    .build()
            }

            val refreshToken = tokenManager.getRefreshToken() ?: return@synchronized null

            try {
                val newTokens = runBlocking {
                    withTimeout(10_000) {
                        apiProvider().refreshToken(RefreshTokenRequest(refreshToken))
                    }
                }

                tokenManager.saveTokens(newTokens.accessToken, newTokens.refreshToken)

                response.request.newBuilder()
                    .header("Authorization", "Bearer ${newTokens.accessToken}")
                    .header("X-Token-Refreshed", "true")
                    .build()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                tokenManager.clearTokens()
                null
            }
        }
    }

    private fun responseCount(response: Response): Int {
        var count = 1
        var priorResponse = response.priorResponse
        while (priorResponse != null) {
            count++
            priorResponse = priorResponse.priorResponse
        }
        return count
    }
}
