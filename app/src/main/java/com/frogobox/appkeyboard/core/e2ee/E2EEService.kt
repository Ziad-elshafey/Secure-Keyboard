package com.frogobox.appkeyboard.core.e2ee

import android.util.Base64
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/**
 * End-to-End Encryption service implementing the Signal-like protocol.
 *
 * Primitives (all via BouncyCastle):
 *   - Ed25519  -- identity key signing / verification
 *   - X25519   -- Diffie-Hellman key exchange (X3DH)
 *   - HKDF-SHA256 -- key derivation
 *   - ChaCha20-Poly1305 -- AEAD message encryption (12-byte nonce)
 *
 * The authenticated envelope format (magic "SM1") carries nonce + counter
 * alongside the ciphertext. Legacy bare-ChaCha20 envelopes (counter-only
 * suffix) are still supported on the decrypt path for backward compatibility.
 */
object E2EEService {

    private val KDF_INFO_SHARED_SECRET = "SecureMessaging_SharedSecret".toByteArray()
    private val KDF_INFO_MESSAGE_KEY   = "SecureMessaging_MessageKey".toByteArray()
    private val PACKED_MESSAGE_MAGIC   = byteArrayOf(0x53, 0x4D, 0x31) // "SM1"
    private const val KEY_LENGTH = 32
    private const val NONCE_LENGTH = 12
    private const val TAG_LENGTH = 16
    private val random = SecureRandom()

    // ════════════════════════════════════════════════════════════
    //  Key Generation
    // ════════════════════════════════════════════════════════════

    fun generateIdentityKeyPair(): IdentityKeyPair {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(random))
        val pair = gen.generateKeyPair()

        val priv = (pair.private as Ed25519PrivateKeyParameters).encoded
        val pub  = (pair.public  as Ed25519PublicKeyParameters).encoded
        return IdentityKeyPair(privateKey = priv, publicKey = pub)
    }

    fun generateSignedPreKey(keyId: Int, identityPrivateKey: ByteArray): SignedPreKey {
        val gen = X25519KeyPairGenerator()
        gen.init(X25519KeyGenerationParameters(random))
        val pair = gen.generateKeyPair()

        val priv = (pair.private as X25519PrivateKeyParameters).encoded
        val pub  = (pair.public  as X25519PublicKeyParameters).encoded
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

    fun ed25519Sign(privateKey: ByteArray, data: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKey, 0))
        signer.update(data, 0, data.size)
        return signer.generateSignature()
    }

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

    fun x3dhInitiate(recipientSignedPreKeyPublic: ByteArray): X3DHResult {
        val gen = X25519KeyPairGenerator()
        gen.init(X25519KeyGenerationParameters(random))
        val ephPair = gen.generateKeyPair()

        val ephPriv = ephPair.private as X25519PrivateKeyParameters
        val ephPub  = (ephPair.public as X25519PublicKeyParameters).encoded
        val dh1 = x25519DH(ephPriv, X25519PublicKeyParameters(recipientSignedPreKeyPublic, 0))
        val sharedSecret = hkdfDerive(dh1, KDF_INFO_SHARED_SECRET, KEY_LENGTH)

        return X3DHResult(sharedSecret = sharedSecret, ephemeralPublicKey = ephPub)
    }

    fun x3dhRespond(signedPreKeyPrivate: ByteArray, ephemeralPublicKey: ByteArray): ByteArray {
        val dh1 = x25519DH(
            X25519PrivateKeyParameters(signedPreKeyPrivate, 0),
            X25519PublicKeyParameters(ephemeralPublicKey, 0)
        )
        return hkdfDerive(dh1, KDF_INFO_SHARED_SECRET, KEY_LENGTH)
    }

    // ════════════════════════════════════════════════════════════
    //  Authenticated Message Encryption (ChaCha20-Poly1305)
    // ════════════════════════════════════════════════════════════

    fun encryptMessage(sharedSecret: ByteArray, plaintext: String): EncryptedMessage =
        encryptBytes(sharedSecret, plaintext.toByteArray(Charsets.UTF_8), counter = 0)

    fun encryptMessage(sharedSecret: ByteArray, plaintext: String, counter: Int): EncryptedMessage =
        encryptBytes(sharedSecret, plaintext.toByteArray(Charsets.UTF_8), counter)

    fun encryptBytes(sharedSecret: ByteArray, payload: ByteArray): EncryptedMessage =
        encryptBytes(sharedSecret, payload, counter = 0)

    fun encryptBytes(sharedSecret: ByteArray, payload: ByteArray, counter: Int): EncryptedMessage {
        val (messageKey, _) = deriveMessageKey(sharedSecret, counter)
        val nonce = ByteArray(NONCE_LENGTH).also { random.nextBytes(it) }
        val ciphertext = chacha20Poly1305Encrypt(messageKey, nonce, payload, counterToAad(counter))
        return EncryptedMessage(ciphertext = ciphertext, nonce = nonce)
    }

    fun decryptMessage(sharedSecret: ByteArray, ciphertext: ByteArray, nonce: ByteArray): String =
        decryptMessage(sharedSecret, ciphertext, nonce, counter = 0)

    fun decryptMessage(sharedSecret: ByteArray, ciphertext: ByteArray, nonce: ByteArray, counter: Int): String {
        val plaintext = decryptToBytes(sharedSecret, ciphertext, nonce, counter)
        return String(plaintext, Charsets.UTF_8)
    }

    fun decryptToBytes(sharedSecret: ByteArray, ciphertext: ByteArray, nonce: ByteArray): ByteArray =
        decryptToBytes(sharedSecret, ciphertext, nonce, counter = 0)

    fun decryptToBytes(sharedSecret: ByteArray, ciphertext: ByteArray, nonce: ByteArray, counter: Int): ByteArray {
        val (messageKey, _) = deriveMessageKey(sharedSecret, counter)
        return chacha20Poly1305Decrypt(messageKey, nonce, ciphertext, counterToAad(counter))
    }

    // ════════════════════════════════════════════════════════════
    //  Base64 Helpers
    // ════════════════════════════════════════════════════════════

    fun toBase64(data: ByteArray): String =
        Base64.encodeToString(data, Base64.NO_WRAP)

    fun fromBase64(encoded: String): ByteArray =
        Base64.decode(encoded, Base64.NO_WRAP)

    // ════════════════════════════════════════════════════════════
    //  Wire Format: Authenticated Envelope (SM1)
    // ════════════════════════════════════════════════════════════

    /**
     * Pack ciphertext with nonce and counter into the authenticated envelope format.
     * Layout: `[SM1 magic (3)][nonce_len (1)][nonce (12)][counter (2)][ciphertext+tag ...]`
     */
    fun packCiphertextWithNonceAndCounter(ciphertext: ByteArray, nonce: ByteArray, counter: Int): ByteArray {
        require(nonce.size == NONCE_LENGTH) { "Nonce must be $NONCE_LENGTH bytes" }
        require(counter in 0..65535) { "Counter must be 16-bit (0-65535)" }

        val envelope = ByteArray(PACKED_MESSAGE_MAGIC.size + 1 + nonce.size + 2 + ciphertext.size)
        System.arraycopy(PACKED_MESSAGE_MAGIC, 0, envelope, 0, PACKED_MESSAGE_MAGIC.size)
        envelope[PACKED_MESSAGE_MAGIC.size] = nonce.size.toByte()
        System.arraycopy(nonce, 0, envelope, PACKED_MESSAGE_MAGIC.size + 1, nonce.size)
        val counterOffset = PACKED_MESSAGE_MAGIC.size + 1 + nonce.size
        envelope[counterOffset] = (counter shr 8).toByte()
        envelope[counterOffset + 1] = (counter and 0xFF).toByte()
        System.arraycopy(ciphertext, 0, envelope, counterOffset + 2, ciphertext.size)
        return envelope
    }

    /**
     * Unpack a message envelope, supporting both the authenticated SM1 format
     * and the legacy bare-ChaCha20 format (counter-only suffix).
     */
    fun unpackMessageEnvelope(data: ByteArray): PackedMessageEnvelope {
        if (
            data.size >= PACKED_MESSAGE_MAGIC.size + 1 + NONCE_LENGTH + 2 + 1 &&
            data.copyOfRange(0, PACKED_MESSAGE_MAGIC.size).contentEquals(PACKED_MESSAGE_MAGIC)
        ) {
            val encodedNonceLength = data[PACKED_MESSAGE_MAGIC.size].toInt() and 0xFF
            require(encodedNonceLength == NONCE_LENGTH) { "Unsupported nonce length: $encodedNonceLength" }

            val nonceStart = PACKED_MESSAGE_MAGIC.size + 1
            val counterStart = nonceStart + encodedNonceLength
            val ciphertextStart = counterStart + 2
            require(data.size > ciphertextStart) { "Packed AEAD payload is missing ciphertext" }

            val nonce = data.copyOfRange(nonceStart, counterStart)
            val counter = ((data[counterStart].toInt() and 0xFF) shl 8) or
                (data[counterStart + 1].toInt() and 0xFF)
            val ciphertext = data.copyOfRange(ciphertextStart, data.size)
            return PackedMessageEnvelope(ciphertext = ciphertext, counter = counter, nonce = nonce)
        }

        val (ciphertext, counter) = unpackCiphertextAndCounter(data)
        return PackedMessageEnvelope(ciphertext = ciphertext, counter = counter, nonce = null)
    }

    // ════════════════════════════════════════════════════════════
    //  Wire Format: Legacy (bare ChaCha20, counter-only suffix)
    // ════════════════════════════════════════════════════════════

    fun packCiphertextWithCounter(ciphertext: ByteArray, counter: Int): ByteArray {
        require(counter in 0..65535) { "Counter must be 16-bit (0-65535)" }
        return ciphertext + byteArrayOf((counter shr 8).toByte(), (counter and 0xFF).toByte())
    }

    fun unpackCiphertextAndCounter(data: ByteArray): Pair<ByteArray, Int> {
        require(data.size >= 3) { "Data too short — need at least 1 byte ciphertext + 2 bytes counter" }
        val ciphertext = data.copyOfRange(0, data.size - 2)
        val counter = ((data[data.size - 2].toInt() and 0xFF) shl 8) or
                      (data[data.size - 1].toInt() and 0xFF)
        return ciphertext to counter
    }

    // ════════════════════════════════════════════════════════════
    //  Key Derivation
    // ════════════════════════════════════════════════════════════

    fun deriveMessageKey(sharedSecret: ByteArray, counter: Int): Pair<ByteArray, ByteArray> {
        require(sharedSecret.size == KEY_LENGTH) { "Shared secret must be $KEY_LENGTH bytes" }
        require(counter in 0..65535) { "Counter must be 16-bit (0-65535)" }

        val counterBytes = byteArrayOf((counter shr 8).toByte(), (counter and 0xFF).toByte())
        val derived = hkdfDerive(
            ikm = sharedSecret,
            info = KDF_INFO_MESSAGE_KEY,
            length = 48,
            salt = counterBytes
        )
        return derived.copyOfRange(0, 32) to derived.copyOfRange(32, 48)
    }

    // ════════════════════════════════════════════════════════════
    //  Bare ChaCha20 (legacy, kept for backward-compat decryption)
    // ════════════════════════════════════════════════════════════

    fun chacha20Encrypt(plaintext: ByteArray, sharedSecret: ByteArray, counter: Int): ByteArray {
        val (key, nonce16) = deriveMessageKey(sharedSecret, counter)
        return bareChaCha20(key, nonce16, plaintext)
    }

    fun chacha20Decrypt(ciphertext: ByteArray, sharedSecret: ByteArray, counter: Int): ByteArray =
        chacha20Encrypt(ciphertext, sharedSecret, counter)

    // ════════════════════════════════════════════════════════════
    //  Internal Primitives
    // ════════════════════════════════════════════════════════════

    private fun counterToAad(counter: Int): ByteArray =
        byteArrayOf((counter shr 8).toByte(), (counter and 0xFF).toByte())

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

    private fun hkdfDerive(ikm: ByteArray, info: ByteArray, length: Int, salt: ByteArray? = null): ByteArray {
        val params = HKDFParameters(ikm, salt, info)
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(params)
        val output = ByteArray(length)
        hkdf.generateBytes(output, 0, length)
        return output
    }

    private fun chacha20Poly1305Encrypt(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray? = null
    ): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(key), TAG_LENGTH * 8, nonce))
        aad?.let { cipher.processAADBytes(it, 0, it.size) }
        val output = ByteArray(cipher.getOutputSize(plaintext.size))
        var len = cipher.processBytes(plaintext, 0, plaintext.size, output, 0)
        len += cipher.doFinal(output, len)
        return output.copyOf(len)
    }

    private fun chacha20Poly1305Decrypt(
        key: ByteArray,
        nonce: ByteArray,
        ciphertextWithTag: ByteArray,
        aad: ByteArray? = null
    ): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(key), TAG_LENGTH * 8, nonce))
        aad?.let { cipher.processAADBytes(it, 0, it.size) }
        val output = ByteArray(cipher.getOutputSize(ciphertextWithTag.size))
        var len = cipher.processBytes(ciphertextWithTag, 0, ciphertextWithTag.size, output, 0)
        try {
            len += cipher.doFinal(output, len)
        } catch (e: Exception) {
            throw IllegalArgumentException("Decryption failed — wrong key or tampered data", e)
        }
        return output.copyOf(len)
    }

    private fun bareChaCha20(key: ByteArray, nonce16: ByteArray, input: ByteArray): ByteArray {
        val initialCounter = ByteBuffer.wrap(nonce16, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
        val iv12 = nonce16.copyOfRange(4, 16)

        val engine = ChaCha7539Engine()
        engine.init(true, ParametersWithIV(KeyParameter(key), iv12))

        val counterLong = initialCounter.toLong() and 0xFFFFFFFFL
        if (counterLong > 0) {
            engine.seekTo(counterLong * 64L)
        }

        val output = ByteArray(input.size)
        engine.processBytes(input, 0, input.size, output, 0)
        return output
    }
}
