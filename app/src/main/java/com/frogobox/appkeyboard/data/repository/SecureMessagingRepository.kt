package com.frogobox.appkeyboard.data.repository

import android.util.Log
import com.frogobox.appkeyboard.core.e2ee.E2EEService
import com.frogobox.appkeyboard.data.local.AuthTokenManager
import com.frogobox.appkeyboard.data.local.SecureKeyStore
import com.frogobox.appkeyboard.data.remote.SecureApiService
import com.frogobox.appkeyboard.data.remote.dto.*
import com.frogobox.appkeyboard.data.repository.compression.CompressionService
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Orchestrates API calls + E2EE crypto + key storage into single-call use cases.
 *
 * This is the only class the keyboard UI panel needs to interact with.
 * All methods return [Result] so the UI can simply check success/failure.
 */
@Singleton
class SecureMessagingRepository @Inject constructor(
    private val api: SecureApiService,
    private val tokenManager: AuthTokenManager,
    private val keyStore: SecureKeyStore
) {

    companion object {
        private const val TAG = "SecureMessagingRepo"

        /**
         * Protocol flag bytes — first byte of the payload before encryption.
         * 0x00 = raw UTF-8 (uncompressed, backward-compatible)
         * 0x01 = arithmetic-coded compressed payload
         */
        const val FLAG_RAW: Byte        = 0x00
        const val FLAG_COMPRESSED: Byte = 0x01
    }

    /** Set to true to enable compression. Disabled if vocab fails to load. Initialized lazily. */
    private val compressionEnabled: Boolean by lazy {
        try {
            CompressionService.compress("test")
            true
        } catch (_: Exception) {
            Log.w(TAG, "Compression vocab unavailable — falling back to raw mode")
            false
        }
    }

    // ════════════════════════════════════════════════════════════
    //  Auth
    // ════════════════════════════════════════════════════════════

    /**
     * Register a new user, generate + upload E2EE keys, persist everything.
     *
     * Flow:
     * 1. POST /api/auth/register → get tokens + user info
     * 2. Generate Ed25519 identity key pair
     * 3. Generate X25519 signed pre-key (signed by identity key)
     * 4. POST /api/keys/upload → upload public keys to server
     * 5. Save tokens, user info, key pairs locally
     */
    suspend fun register(username: String, password: String): Result<String> = runCatching {
        val email = "$username@keyboard.local"

        // 1. Register on server
        val response = api.register(RegisterRequest(username, email, password))
        tokenManager.saveTokens(response.accessToken, response.refreshToken)
        tokenManager.saveUserInfo(response.userId, response.username)

        // 2-3. Generate key pairs
        val identityKeyPair = E2EEService.generateIdentityKeyPair()
        val signedPreKey = E2EEService.generateSignedPreKey(1, identityKeyPair.privateKey)

        // 4. Upload public keys to server
        api.uploadKeys(
            UploadKeysRequest(
                identityKeyPublic = E2EEService.toBase64(identityKeyPair.publicKey),
                signedPrekeyPublic = E2EEService.toBase64(signedPreKey.publicKey),
                signedPrekeySignature = E2EEService.toBase64(signedPreKey.signature),
                signedPrekeyId = signedPreKey.keyId
            )
        )

        // 5. Save keys locally
        keyStore.saveIdentityKeyPair(identityKeyPair)
        keyStore.saveSignedPreKey(signedPreKey)

        response.userId
    }

    /**
     * Login and ensure E2EE keys exist (generate + upload if needed).
     */
    suspend fun login(username: String, password: String): Result<String> = runCatching {
        // 1. Login
        val response = api.login(LoginRequest(username, password))
        tokenManager.saveTokens(response.accessToken, response.refreshToken)

        // 2. Get user info
        val user = api.getCurrentUser()
        tokenManager.saveUserInfo(user.userId, user.username)

        // 3. Ensure keys exist locally and on server
        if (!keyStore.hasIdentityKeys()) {
            val identityKeyPair = E2EEService.generateIdentityKeyPair()
            val signedPreKey = E2EEService.generateSignedPreKey(1, identityKeyPair.privateKey)

            api.uploadKeys(
                UploadKeysRequest(
                    identityKeyPublic = E2EEService.toBase64(identityKeyPair.publicKey),
                    signedPrekeyPublic = E2EEService.toBase64(signedPreKey.publicKey),
                    signedPrekeySignature = E2EEService.toBase64(signedPreKey.signature),
                    signedPrekeyId = signedPreKey.keyId
                )
            )

            keyStore.saveIdentityKeyPair(identityKeyPair)
            keyStore.saveSignedPreKey(signedPreKey)
        }

        user.userId
    }

    fun isLoggedIn(): Boolean = tokenManager.isLoggedIn()

    fun getUsername(): String? = tokenManager.getUsername()

    fun getUserId(): String? = tokenManager.getUserId()

    fun logout() {
        tokenManager.clearAll()
        keyStore.clearAll()
    }

    // ════════════════════════════════════════════════════════════
    //  Users
    // ════════════════════════════════════════════════════════════

    suspend fun searchUsers(query: String): Result<List<UserSearchResult>> = runCatching {
        api.searchUsers(query)
    }

    // ════════════════════════════════════════════════════════════
    //  Conversations
    // ════════════════════════════════════════════════════════════

    suspend fun createConversation(recipientId: String): Result<ConversationResponse> = runCatching {
        api.createConversation(CreateConversationRequest(participantIds = listOf(recipientId)))
    }

    suspend fun getConversations(): Result<List<ConversationResponse>> = runCatching {
        api.getConversations()
    }

    // ════════════════════════════════════════════════════════════
    //  Send Message
    // ════════════════════════════════════════════════════════════

    /**
     * Encrypt a plaintext message and send it to the server.
     *
     * Flow:
     * 1. Get or establish shared secret for this conversation
     *    a. If we have a cached shared secret → use it
     *    b. If not → fetch recipient's key bundle → X3DH initiate → cache secret
     * 2. Encrypt plaintext with E2EEService
     * 3. POST /api/messages/send → server obfuscates → returns decoy text
     *
     * @return [SendResult] containing the obfuscated decoy text and message ID
     */
    suspend fun sendMessage(
        conversationId: String,
        recipientId: String,
        plaintext: String
    ): Result<SendResult> = runCatching {
        // 1. Get or establish shared secret
        val isFirstMessage = !keyStore.hasSharedSecret(conversationId)
        val (sharedSecret, ephemeralPubKey) = getOrEstablishSharedSecret(conversationId, recipientId)

        // 2. Compress → frame → encrypt
        val payload = buildPayload(plaintext)
        val encrypted = E2EEService.encryptBytes(sharedSecret, payload)

        Log.d(TAG, "sendMessage: raw=${plaintext.toByteArray().size}B, " +
                "payload=${payload.size}B (flag=0x%02X), cipher=${encrypted.ciphertext.size}B"
                    .format(payload[0]))

        // 3. Send to server
        val response = api.sendMessage(
            SendMessageRequest(
                conversationId = conversationId,
                ciphertext = E2EEService.toBase64(encrypted.ciphertext),
                nonce = E2EEService.toBase64(encrypted.nonce),
                ephemeralPublicKey = if (isFirstMessage && ephemeralPubKey != null)
                    E2EEService.toBase64(ephemeralPubKey) else null
            )
        )

        SendResult(
            messageId = response.messageId,
            obfuscatedText = response.obfuscatedText
        )
    }

    // ════════════════════════════════════════════════════════════
    //  Receive & Decrypt Messages
    // ════════════════════════════════════════════════════════════

    /**
     * Get the inbox — list of obfuscated messages (natural-looking English text).
     */
    suspend fun getInbox(): Result<List<InboxMessage>> = runCatching {
        api.getInbox().map { msg ->
            InboxMessage(
                messageId = msg.messageId,
                conversationId = msg.conversationId,
                senderId = msg.senderId,
                senderUsername = msg.senderUsername,
                obfuscatedText = msg.obfuscatedText,
                createdAt = msg.createdAt,
                status = msg.status
            )
        }
    }

    /**
     * Reveal and decrypt a single message.
     *
     * Flow:
     * 1. GET /api/messages/{id}/reveal → server de-obfuscates → returns ciphertext
     * 2. Get or establish shared secret (X3DH respond if first time receiving from this sender)
     * 3. Decrypt with E2EEService → plaintext
     *
     * @return The original plaintext (NEVER stored anywhere)
     */
    suspend fun revealAndDecrypt(
        messageId: String,
        conversationId: String,
        senderId: String
    ): Result<String> = runCatching {
        // 1. Reveal — server removes obfuscation layer
        val revealed = api.revealMessage(messageId)

        // 2. Get or establish shared secret
        val sharedSecret = getOrEstablishSharedSecretForReceive(
            conversationId = conversationId,
            senderId = senderId,
            ephemeralPublicKeyBase64 = revealed.ephemeralPublicKey
        )

        // 3. Decrypt → deflag → decompress
        val ciphertext = E2EEService.fromBase64(revealed.ciphertext)
        val nonce = E2EEService.fromBase64(revealed.nonce)
        val payload = E2EEService.decryptToBytes(sharedSecret, ciphertext, nonce)
        parsePayload(payload)
    }

    // ════════════════════════════════════════════════════════════
    //  Internal: Shared Secret Management
    // ════════════════════════════════════════════════════════════

    /**
     * Get cached shared secret, or initiate X3DH to establish one (sender side).
     *
     * @return Pair of (sharedSecret, ephemeralPublicKey-or-null)
     */
    private suspend fun getOrEstablishSharedSecret(
        conversationId: String,
        recipientId: String
    ): Pair<ByteArray, ByteArray?> {
        // Check cache first
        val cached = keyStore.getSharedSecret(conversationId)
        if (cached != null) return cached to null

        // Fetch recipient's key bundle
        val bundle = api.getKeyBundle(recipientId)

        // Verify signed pre-key signature
        val identityKeyPub = E2EEService.fromBase64(bundle.identityKeyPublic)
        val signedPreKeyPub = E2EEService.fromBase64(bundle.signedPrekeyPublic)
        val signature = E2EEService.fromBase64(bundle.signedPrekeySignature)

        val signatureValid = E2EEService.ed25519Verify(identityKeyPub, signedPreKeyPub, signature)
        check(signatureValid) { "Recipient's signed pre-key signature is invalid — possible MITM" }

        // X3DH initiate
        val x3dhResult = E2EEService.x3dhInitiate(recipientSignedPreKeyPublic = signedPreKeyPub)

        // Cache shared secret
        keyStore.saveSharedSecret(conversationId, x3dhResult.sharedSecret)

        return x3dhResult.sharedSecret to x3dhResult.ephemeralPublicKey
    }

    // ════════════════════════════════════════════════════════════
    //  Internal: Compression Pipeline
    // ════════════════════════════════════════════════════════════

    /**
     * Build the wire payload: `[flag_byte][data]`
     *
     * If compression is enabled and actually shrinks the message, the payload is:
     *   `0x01 || compressed_bytes`
     * Otherwise:
     *   `0x00 || utf8_bytes`
     */
    private fun buildPayload(plaintext: String): ByteArray {
        val rawBytes = plaintext.toByteArray(Charsets.UTF_8)

        if (compressionEnabled) {
            try {
                val compressed = CompressionService.compress(plaintext)
                // Only use compression if it actually saves space
                if (compressed.isNotEmpty() && compressed.size < rawBytes.size) {
                    val bitsPerWord = CompressionService.getBitsPerWord(plaintext, compressed.size)
                    val savings = CompressionService.getSavingsPercent(rawBytes.size, compressed.size)
                    Log.d(TAG, "Compression: ${rawBytes.size}B → ${compressed.size}B " +
                            "(%.1f%% saved, %.1f bits/word)".format(savings, bitsPerWord))

                    return ByteArray(1 + compressed.size).also {
                        it[0] = FLAG_COMPRESSED
                        System.arraycopy(compressed, 0, it, 1, compressed.size)
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Compression failed, falling back to raw", e)
            }
        }

        // Raw fallback
        return ByteArray(1 + rawBytes.size).also {
            it[0] = FLAG_RAW
            System.arraycopy(rawBytes, 0, it, 1, rawBytes.size)
        }
    }

    /**
     * Parse a decrypted wire payload back to plaintext.
     *
     * Reads the first byte to decide whether to decompress.
     */
    private fun parsePayload(payload: ByteArray): String {
        require(payload.isNotEmpty()) { "Empty payload after decryption" }

        val flag = payload[0]
        val data = payload.copyOfRange(1, payload.size)

        return when (flag) {
            FLAG_COMPRESSED -> {
                Log.d(TAG, "Decompressing ${data.size}B payload")
                CompressionService.decompress(data)
            }
            FLAG_RAW -> {
                String(data, Charsets.UTF_8)
            }
            else -> {
                // Unknown flag — best-effort: treat as raw UTF-8
                Log.w(TAG, "Unknown payload flag 0x%02X — treating as raw".format(flag))
                String(data, Charsets.UTF_8)
            }
        }
    }

    // ════════════════════════════════════════════════════════════
    //  Internal: Shared Secret Management
    // ════════════════════════════════════════════════════════════

    /**
     * Get cached shared secret, or respond to X3DH to establish one (receiver side).
     */
    private fun getOrEstablishSharedSecretForReceive(
        conversationId: String,
        senderId: String,
        ephemeralPublicKeyBase64: String?
    ): ByteArray {
        // Check cache first
        val cached = keyStore.getSharedSecret(conversationId)
        if (cached != null) return cached

        // Need ephemeral key from sender to perform X3DH respond
        requireNotNull(ephemeralPublicKeyBase64) {
            "No shared secret cached and no ephemeral key provided — cannot establish session"
        }

        // Get our signed pre-key private
        val signedPreKey = keyStore.getSignedPreKey()
            ?: error("No signed pre-key found — cannot respond to X3DH")

        val ephemeralPub = E2EEService.fromBase64(ephemeralPublicKeyBase64)
        val sharedSecret = E2EEService.x3dhRespond(
            signedPreKeyPrivate = signedPreKey.privateKey,
            ephemeralPublicKey = ephemeralPub
        )

        // Cache for future messages in this conversation
        keyStore.saveSharedSecret(conversationId, sharedSecret)
        return sharedSecret
    }
}

// ════════════════════════════════════════════════════════════
//  Result Types
// ════════════════════════════════════════════════════════════

data class SendResult(
    val messageId: String,
    val obfuscatedText: String
)

data class InboxMessage(
    val messageId: String,
    val conversationId: String,
    val senderId: String,
    val senderUsername: String,
    val obfuscatedText: String,
    val createdAt: String,
    val status: String
)
