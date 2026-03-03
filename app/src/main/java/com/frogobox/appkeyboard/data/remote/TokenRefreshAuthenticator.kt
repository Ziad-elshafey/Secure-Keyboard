package com.frogobox.appkeyboard.data.remote

import com.frogobox.appkeyboard.data.local.AuthTokenManager
import com.frogobox.appkeyboard.data.remote.dto.RefreshTokenRequest
import kotlinx.coroutines.runBlocking
import okhttp3.Authenticator
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route

/**
 * OkHttp [Authenticator] that automatically refreshes the access token
 * when a 401 response is received.
 *
 * Flow:
 * 1. OkHttp gets a 401 → calls [authenticate]
 * 2. We call POST /api/auth/refresh with the stored refresh token
 * 3. On success: save new tokens, retry the original request with the new access token
 * 4. On failure: return null (give up — user must re-login)
 *
 * Uses [runBlocking] because OkHttp's Authenticator runs on the OkHttp thread pool
 * and must return synchronously.
 */
class TokenRefreshAuthenticator(
    private val tokenManager: AuthTokenManager,
    private val apiProvider: () -> SecureApiService
) : Authenticator {

    override fun authenticate(route: Route?, response: Response): Request? {
        // Avoid infinite retry loops — if we already tried refreshing, give up
        if (response.request.header("X-Token-Refreshed") != null) {
            return null
        }

        val refreshToken = tokenManager.getRefreshToken() ?: return null

        return try {
            val newTokens = runBlocking {
                apiProvider().refreshToken(RefreshTokenRequest(refreshToken))
            }

            tokenManager.saveTokens(newTokens.accessToken, newTokens.refreshToken)

            // Retry the failed request with the new access token
            response.request.newBuilder()
                .header("Authorization", "Bearer ${newTokens.accessToken}")
                .header("X-Token-Refreshed", "true")
                .build()
        } catch (_: Exception) {
            // Refresh failed — clear tokens so the app knows to re-login
            tokenManager.clearAll()
            null
        }
    }
}
