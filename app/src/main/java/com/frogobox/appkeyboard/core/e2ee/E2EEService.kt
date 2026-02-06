package com.frogobox.appkeyboard.core.e2ee

import android.util.Base64
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import java.security.SecureRandom

/**
 * End-to-End Encryption service implementing the Signal-like protocol.
 *
 * Exact Kotlin port of `Secure-application/Server/app/services/e2ee.py`.
 * All constants and derivation paths match the Python server so that
 * a message encrypted here can be decrypted there and vice-versa.
 *
 * Primitives (all via BouncyCastle):
 *   • Ed25519  — identity key signing / verification
 *   • X25519   — Diffie-Hellman key exchange (X3DH)
 *   • HKDF-SHA256 — key derivation
 *   • ChaCha20-Poly1305 — AEAD message encryption (12-byte nonce)
 */
object E2EEService {

    // ── Protocol constants (must match Python server) ─────────
    private val KDF_INFO_SHARED_SECRET = "SecureMessaging_SharedSecret".toByteArray()
    private val KDF_INFO_MESSAGE_KEY   = "SecureMessaging_MessageKey".toByteArray()
    private const val KEY_LENGTH = 32
    private const val NONCE_LENGTH = 12          // Standard ChaCha20-Poly1305 (NOT XChaCha20's 24)
    private const val TAG_LENGTH = 16            // Poly1305 tag
    private val random = SecureRandom()

    // ════════════════════════════════════════════════════════════
    //  Key Generation
    // ════════════════════════════════════════════════════════════

    /**
     * Generate a long-term Ed25519 identity key pair.
     * Private key NEVER leaves the device.
     */
    fun generateIdentityKeyPair(): IdentityKeyPair {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(random))
        val pair = gen.generateKeyPair()

        val priv = (pair.private as Ed25519PrivateKeyParameters).encoded   // 32 bytes
        val pub  = (pair.public  as Ed25519PublicKeyParameters).encoded    // 32 bytes
        return IdentityKeyPair(privateKey = priv, publicKey = pub)
    }

    /**
     * Generate an X25519 signed pre-key, signed by the identity key.
     * Matches Python: `generate_signed_prekey(key_id, identity_keypair)`
     */
    fun generateSignedPreKey(keyId: Int, identityPrivateKey: ByteArray): SignedPreKey {
        // Generate X25519 key pair
        val gen = X25519KeyPairGenerator()
        gen.init(X25519KeyGenerationParameters(random))
        val pair = gen.generateKeyPair()

        val priv = (pair.private as X25519PrivateKeyParameters).encoded
        val pub  = (pair.public  as X25519PublicKeyParameters).encoded

        // Sign the public key bytes with Ed25519 identity key
        val signature = ed25519Sign(identityPrivateKey, pub)

        return SignedPreKey(
            keyId = keyId,
            privateKey = priv,
            publicKey = pub,
            signature = signature
        )
    }

    // ════════════════════════════════════════════════════════════
    //  Signature Operations
    // ════════════════════════════════════════════════════════════

    /** Sign [data] with an Ed25519 [privateKey] (32 bytes). Returns 64-byte signature. */
    fun ed25519Sign(privateKey: ByteArray, data: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKey, 0))
        signer.update(data, 0, data.size)
        return signer.generateSignature()
    }

    /**
     * Verify an Ed25519 [signature] over [data] using [publicKey].
     * Matches Python: `verify_signed_prekey(signed_prekey_public, signature, identity_public_key)`
     */
    fun ed25519Verify(publicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        return try {
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
            verifier.update(data, 0, data.size)
            verifier.verifySignature(signature)
        } catch (_: Exception) {
            false
        }
    }

    // ════════════════════════════════════════════════════════════
    //  X3DH Key Agreement
    // ════════════════════════════════════════════════════════════

    /**
     * Initiate X3DH key agreement (sender / Alice side).
     *
     * Matches Python `x3dh_initiate()`:
     * ```
     * ephemeral = X25519.generate()
     * dh1 = DH(ephemeral, bob_signed_prekey)
     * shared_secret = HKDF(dh1, info="SecureMessaging_SharedSecret")
     * ```
     *
     * @param recipientSignedPreKeyPublic Bob's signed pre-key public (32 bytes)
     * @return [X3DHResult] containing shared secret + ephemeral public key
     */
    fun x3dhInitiate(recipientSignedPreKeyPublic: ByteArray): X3DHResult {
        // Generate ephemeral X25519 key pair
        val gen = X25519KeyPairGenerator()
        gen.init(X25519KeyGenerationParameters(random))
        val ephPair = gen.generateKeyPair()

        val ephPriv = ephPair.private as X25519PrivateKeyParameters
        val ephPub  = (ephPair.public as X25519PublicKeyParameters).encoded

        // DH1 = DH(ephemeral_private, recipient_signed_prekey_public)
        val dh1 = x25519DH(ephPriv, X25519PublicKeyParameters(recipientSignedPreKeyPublic, 0))

        // shared_secret = HKDF-SHA256(dh1, info=KDF_INFO_SHARED_SECRET)
        val sharedSecret = hkdfDerive(dh1, KDF_INFO_SHARED_SECRET, KEY_LENGTH)

        return X3DHResult(sharedSecret = sharedSecret, ephemeralPublicKey = ephPub)
    }

    /**
     * Respond to X3DH key agreement (receiver / Bob side).
     *
     * Matches Python `x3dh_respond()`:
     * ```
     * dh1 = DH(bob_signed_prekey_private, alice_ephemeral_public)
     * shared_secret = HKDF(dh1, info="SecureMessaging_SharedSecret")
     * ```
     *
     * @param signedPreKeyPrivate Bob's signed pre-key private (32 bytes)
     * @param ephemeralPublicKey  Alice's ephemeral public key (32 bytes)
     * @return 32-byte shared secret (identical to what [x3dhInitiate] produced)
     */
    fun x3dhRespond(signedPreKeyPrivate: ByteArray, ephemeralPublicKey: ByteArray): ByteArray {
        val dh1 = x25519DH(
            X25519PrivateKeyParameters(signedPreKeyPrivate, 0),
            X25519PublicKeyParameters(ephemeralPublicKey, 0)
        )
        return hkdfDerive(dh1, KDF_INFO_SHARED_SECRET, KEY_LENGTH)
    }

    // ════════════════════════════════════════════════════════════
    //  Message Encryption / Decryption
    // ════════════════════════════════════════════════════════════

    /**
     * Encrypt a plaintext message with ChaCha20-Poly1305.
     *
     * Matches Python `encrypt_message(plaintext, shared_secret)`:
     * ```
     * message_key = HKDF(shared_secret, info="SecureMessaging_MessageKey")
     * nonce = random(12)
     * ciphertext = ChaCha20Poly1305(message_key).encrypt(nonce, plaintext, None)
     * ```
     */
    fun encryptMessage(sharedSecret: ByteArray, plaintext: String): EncryptedMessage {
        val messageKey = hkdfDerive(sharedSecret, KDF_INFO_MESSAGE_KEY, KEY_LENGTH)
        val nonce = ByteArray(NONCE_LENGTH).also { random.nextBytes(it) }
        val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
        val ciphertext = chacha20Poly1305Encrypt(messageKey, nonce, plaintextBytes)
        return EncryptedMessage(ciphertext = ciphertext, nonce = nonce)
    }

    /**
     * Encrypt raw bytes with ChaCha20-Poly1305.
     * Used when the caller has already compressed / framed the payload.
     */
    fun encryptBytes(sharedSecret: ByteArray, payload: ByteArray): EncryptedMessage {
        val messageKey = hkdfDerive(sharedSecret, KDF_INFO_MESSAGE_KEY, KEY_LENGTH)
        val nonce = ByteArray(NONCE_LENGTH).also { random.nextBytes(it) }
        val ciphertext = chacha20Poly1305Encrypt(messageKey, nonce, payload)
        return EncryptedMessage(ciphertext = ciphertext, nonce = nonce)
    }

    /**
     * Decrypt a ChaCha20-Poly1305 ciphertext back to plaintext.
     *
     * Matches Python `decrypt_message(ciphertext_b64, nonce_b64, shared_secret)`.
     *
     * @throws IllegalArgumentException if decryption fails (wrong key or tampered data)
     */
    fun decryptMessage(sharedSecret: ByteArray, ciphertext: ByteArray, nonce: ByteArray): String {
        val messageKey = hkdfDerive(sharedSecret, KDF_INFO_MESSAGE_KEY, KEY_LENGTH)
        val plaintext = chacha20Poly1305Decrypt(messageKey, nonce, ciphertext)
        return String(plaintext, Charsets.UTF_8)
    }

    /**
     * Decrypt a ChaCha20-Poly1305 ciphertext back to raw bytes.
     * Used when the caller needs to inspect a protocol flag byte before interpreting.
     */
    fun decryptToBytes(sharedSecret: ByteArray, ciphertext: ByteArray, nonce: ByteArray): ByteArray {
        val messageKey = hkdfDerive(sharedSecret, KDF_INFO_MESSAGE_KEY, KEY_LENGTH)
        return chacha20Poly1305Decrypt(messageKey, nonce, ciphertext)
    }

    // ════════════════════════════════════════════════════════════
    //  Base64 Helpers (match Python's base64.b64encode/decode)
    // ════════════════════════════════════════════════════════════

    fun toBase64(data: ByteArray): String =
        Base64.encodeToString(data, Base64.NO_WRAP)

    fun fromBase64(encoded: String): ByteArray =
        Base64.decode(encoded, Base64.NO_WRAP)

    // ════════════════════════════════════════════════════════════
    //  Internal Primitives
    // ════════════════════════════════════════════════════════════

    /**
     * X25519 Diffie-Hellman exchange.
     * Returns the 32-byte raw shared value (before HKDF).
     */
    private fun x25519DH(
        privateKey: X25519PrivateKeyParameters,
        publicKey: X25519PublicKeyParameters
    ): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(privateKey)
        val shared = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(publicKey, shared, 0)
        return shared
    }

    /**
     * HKDF-SHA256 extract-and-expand.
     *
     * Matches Python:
     * ```
     * HKDF(algorithm=SHA256, length=length, salt=None, info=info).derive(ikm)
     * ```
     * When salt is null, HKDF uses a zero-filled salt of hash-length.
     */
    private fun hkdfDerive(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val params = HKDFParameters(ikm, null, info)   // salt = null → zero salt
        val hkdf = HKDFBytesGenerator(org.bouncycastle.crypto.digests.SHA256Digest())
        hkdf.init(params)
        val output = ByteArray(length)
        hkdf.generateBytes(output, 0, length)
        return output
    }

    /**
     * ChaCha20-Poly1305 AEAD encrypt.
     *
     * Uses BouncyCastle's [ChaCha20Poly1305] engine which produces
     * `ciphertext || 16-byte tag` — same as Python's `ChaCha20Poly1305.encrypt()`.
     *
     * @param key   32-byte key
     * @param nonce 12-byte nonce
     * @param plaintext raw bytes
     * @return ciphertext + Poly1305 tag appended (len = plaintext.size + 16)
     */
    private fun chacha20Poly1305Encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(key), TAG_LENGTH * 8, nonce))
        val output = ByteArray(cipher.getOutputSize(plaintext.size))
        var len = cipher.processBytes(plaintext, 0, plaintext.size, output, 0)
        len += cipher.doFinal(output, len)
        return output.copyOf(len)
    }

    /**
     * ChaCha20-Poly1305 AEAD decrypt.
     *
     * @param key   32-byte key
     * @param nonce 12-byte nonce
     * @param ciphertextWithTag ciphertext + 16-byte Poly1305 tag
     * @return decrypted plaintext bytes
     * @throws IllegalArgumentException on auth failure
     */
    private fun chacha20Poly1305Decrypt(key: ByteArray, nonce: ByteArray, ciphertextWithTag: ByteArray): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(key), TAG_LENGTH * 8, nonce))
        val output = ByteArray(cipher.getOutputSize(ciphertextWithTag.size))
        var len = cipher.processBytes(ciphertextWithTag, 0, ciphertextWithTag.size, output, 0)
        try {
            len += cipher.doFinal(output, len)
        } catch (e: Exception) {
            throw IllegalArgumentException("Decryption failed — wrong key or tampered data", e)
        }
        return output.copyOf(len)
    }
}
