package com.frogobox.appkeyboard.data.local

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Manages JWT tokens (access + refresh) and basic user identity.
 * All values are encrypted at rest via [EncryptedSharedPreferences].
 */
class AuthTokenManager(context: Context) {

    private val prefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context.applicationContext,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // ── Token access ──────────────────────────────────────────

    fun getAccessToken(): String? = prefs.getString(KEY_ACCESS_TOKEN, null)

    fun getRefreshToken(): String? = prefs.getString(KEY_REFRESH_TOKEN, null)

    fun saveTokens(accessToken: String, refreshToken: String) {
        prefs.edit()
            .putString(KEY_ACCESS_TOKEN, accessToken)
            .putString(KEY_REFRESH_TOKEN, refreshToken)
            .apply()
    }

    // ── User identity ─────────────────────────────────────────

    fun getUserId(): String? = prefs.getString(KEY_USER_ID, null)

    fun getUsername(): String? = prefs.getString(KEY_USERNAME, null)

    fun saveUserInfo(userId: String, username: String) {
        prefs.edit()
            .putString(KEY_USER_ID, userId)
            .putString(KEY_USERNAME, username)
            .apply()
    }

    // ── State queries ─────────────────────────────────────────

    fun isLoggedIn(): Boolean = getAccessToken() != null

    /**
     * Checks whether the access token's `exp` claim has passed.
     * Decodes the JWT payload (base64) without cryptographic verification —
     * actual verification happens server-side.
     */
    fun isAccessTokenExpired(): Boolean {
        val token = getAccessToken() ?: return true
        return try {
            val parts = token.split(".")
            if (parts.size != 3) return true
            val payload = String(Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_WRAP))
            val expMatch = Regex("\"exp\"\\s*:\\s*(\\d+)").find(payload)
            val exp = expMatch?.groupValues?.get(1)?.toLongOrNull() ?: return true
            val nowSecs = System.currentTimeMillis() / 1000
            nowSecs >= exp
        } catch (_: Exception) {
            true
        }
    }

    // ── Cleanup ───────────────────────────────────────────────

    fun clearAll() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val PREFS_FILE = "secure_auth_tokens"
        private const val KEY_ACCESS_TOKEN = "access_token"
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_USERNAME = "username"
    }
}
