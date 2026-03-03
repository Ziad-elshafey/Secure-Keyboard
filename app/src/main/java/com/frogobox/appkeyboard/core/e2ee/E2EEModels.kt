package com.frogobox.appkeyboard.core.e2ee

/**
 * Data models for the E2EE (Signal-like) protocol.
 *
 * Maps 1:1 to the Python dataclasses in
 * Secure-application/Server/app/services/e2ee.py
 */

/** Ed25519 identity key pair — long-term, one per user. */
data class IdentityKeyPair(
    val privateKey: ByteArray,   // 32 bytes — NEVER leaves the device
    val publicKey: ByteArray     // 32 bytes — uploaded to server
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IdentityKeyPair) return false
        return publicKey.contentEquals(other.publicKey)
    }
    override fun hashCode(): Int = publicKey.contentHashCode()
}

/** X25519 signed pre-key — rotated periodically, signed by identity key. */
data class SignedPreKey(
    val keyId: Int,
    val privateKey: ByteArray,   // 32 bytes — stays on device
    val publicKey: ByteArray,    // 32 bytes — uploaded to server
    val signature: ByteArray     // 64 bytes — Ed25519 signature of publicKey
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignedPreKey) return false
        return keyId == other.keyId && publicKey.contentEquals(other.publicKey)
    }
    override fun hashCode(): Int = 31 * keyId + publicKey.contentHashCode()
}

/** Result of X3DH key agreement (initiator side). */
data class X3DHResult(
    val sharedSecret: ByteArray,       // 32 bytes — derived via HKDF
    val ephemeralPublicKey: ByteArray   // 32 bytes — sent to recipient
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X3DHResult) return false
        return sharedSecret.contentEquals(other.sharedSecret)
    }
    override fun hashCode(): Int = sharedSecret.contentHashCode()
}

/** Output of message encryption. */
data class EncryptedMessage(
    val ciphertext: ByteArray,  // ChaCha20-Poly1305 ciphertext + tag
    val nonce: ByteArray        // 12 bytes (96-bit, standard ChaCha20-Poly1305)
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncryptedMessage) return false
        return ciphertext.contentEquals(other.ciphertext) && nonce.contentEquals(other.nonce)
    }
    override fun hashCode(): Int = 31 * ciphertext.contentHashCode() + nonce.contentHashCode()
}
