package com.frogobox.appkeyboard.data.local

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.frogobox.appkeyboard.core.e2ee.IdentityKeyPair
import com.frogobox.appkeyboard.core.e2ee.SignedPreKey

/**
 * Persistent, encrypted storage for E2EE key material.
 *
 * Stores:
 *  • Ed25519 identity key pair (long-term, one per user)
 *  • X25519 signed pre-key pair (rotated periodically)
 *  • Per-conversation shared secrets (derived from X3DH)
 *
 * Everything is encrypted at rest via [EncryptedSharedPreferences]
 * backed by Android Keystore AES-256-GCM.
 */
class SecureKeyStore(context: Context) {

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

    // ════════════════════════════════════════════════════════════
    //  Identity Key Pair (Ed25519)
    // ════════════════════════════════════════════════════════════

    fun saveIdentityKeyPair(keyPair: IdentityKeyPair) {
        prefs.edit()
            .putString(KEY_IDENTITY_PRIVATE, encode(keyPair.privateKey))
            .putString(KEY_IDENTITY_PUBLIC, encode(keyPair.publicKey))
            .apply()
    }

    fun getIdentityKeyPair(): IdentityKeyPair? {
        val priv = prefs.getString(KEY_IDENTITY_PRIVATE, null)?.let(::decode) ?: return null
        val pub  = prefs.getString(KEY_IDENTITY_PUBLIC, null)?.let(::decode) ?: return null
        return IdentityKeyPair(privateKey = priv, publicKey = pub)
    }

    fun hasIdentityKeys(): Boolean =
        prefs.contains(KEY_IDENTITY_PRIVATE) && prefs.contains(KEY_IDENTITY_PUBLIC)

    // ════════════════════════════════════════════════════════════
    //  Signed Pre-Key (X25519 + Ed25519 signature)
    // ════════════════════════════════════════════════════════════

    fun saveSignedPreKey(preKey: SignedPreKey) {
        prefs.edit()
            .putInt(KEY_SPK_ID, preKey.keyId)
            .putString(KEY_SPK_PRIVATE, encode(preKey.privateKey))
            .putString(KEY_SPK_PUBLIC, encode(preKey.publicKey))
            .putString(KEY_SPK_SIGNATURE, encode(preKey.signature))
            .apply()
    }

    fun getSignedPreKey(): SignedPreKey? {
        val id   = if (prefs.contains(KEY_SPK_ID)) prefs.getInt(KEY_SPK_ID, 0) else return null
        val priv = prefs.getString(KEY_SPK_PRIVATE, null)?.let(::decode) ?: return null
        val pub  = prefs.getString(KEY_SPK_PUBLIC, null)?.let(::decode) ?: return null
        val sig  = prefs.getString(KEY_SPK_SIGNATURE, null)?.let(::decode) ?: return null
        return SignedPreKey(keyId = id, privateKey = priv, publicKey = pub, signature = sig)
    }

    fun hasSignedPreKey(): Boolean = prefs.contains(KEY_SPK_PRIVATE)

    // ════════════════════════════════════════════════════════════
    //  Per-Conversation Shared Secrets
    // ════════════════════════════════════════════════════════════

    fun saveSharedSecret(conversationId: String, secret: ByteArray) {
        prefs.edit()
            .putString("$PREFIX_SHARED_SECRET$conversationId", encode(secret))
            .apply()
    }

    fun getSharedSecret(conversationId: String): ByteArray? =
        prefs.getString("$PREFIX_SHARED_SECRET$conversationId", null)?.let(::decode)

    fun hasSharedSecret(conversationId: String): Boolean =
        prefs.contains("$PREFIX_SHARED_SECRET$conversationId")

    fun removeSharedSecret(conversationId: String) {
        prefs.edit()
            .remove("$PREFIX_SHARED_SECRET$conversationId")
            .apply()
    }

    // ════════════════════════════════════════════════════════════
    //  Cleanup
    // ════════════════════════════════════════════════════════════

    /** Wipe everything — identity keys, prekeys, all shared secrets. */
    fun clearAll() {
        prefs.edit().clear().apply()
    }

    // ════════════════════════════════════════════════════════════
    //  Base64 helpers
    // ════════════════════════════════════════════════════════════

    private fun encode(data: ByteArray): String =
        Base64.encodeToString(data, Base64.NO_WRAP)

    private fun decode(encoded: String): ByteArray =
        Base64.decode(encoded, Base64.NO_WRAP)

    companion object {
        private const val PREFS_FILE = "secure_key_store"

        // Identity key pair
        private const val KEY_IDENTITY_PRIVATE = "identity_private"
        private const val KEY_IDENTITY_PUBLIC = "identity_public"

        // Signed pre-key
        private const val KEY_SPK_ID = "spk_id"
        private const val KEY_SPK_PRIVATE = "spk_private"
        private const val KEY_SPK_PUBLIC = "spk_public"
        private const val KEY_SPK_SIGNATURE = "spk_signature"

        // Shared secrets (keyed by conversation ID)
        private const val PREFIX_SHARED_SECRET = "shared_secret_"
    }
}
