package com.frogobox.appkeyboard.data.remote

import com.frogobox.appkeyboard.data.local.AuthTokenManager
import okhttp3.Interceptor
import okhttp3.Response

/**
 * OkHttp interceptor that attaches `Authorization: Bearer <token>` to every
 * request except auth endpoints (register, login, refresh).
 */
class AuthInterceptor(
    private val tokenManager: AuthTokenManager
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val path = original.url.encodedPath

        // Skip auth header for unauthenticated endpoints
        if (AUTH_PATHS.any { path.contains(it) }) {
            return chain.proceed(original)
        }

        val token = tokenManager.getAccessToken()
        return if (token != null) {
            val authed = original.newBuilder()
                .header("Authorization", "Bearer $token")
                .build()
            chain.proceed(authed)
        } else {
            chain.proceed(original)
        }
    }

    companion object {
        private val AUTH_PATHS = listOf(
            "/api/auth/register",
            "/api/auth/login",
            "/api/auth/refresh"
        )
    }
}
