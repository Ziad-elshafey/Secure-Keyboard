package com.frogobox.appkeyboard.data.repository

import android.util.Log
import com.frogobox.appkeyboard.core.e2ee.E2EEService
import com.frogobox.appkeyboard.data.local.AuthTokenManager
import com.frogobox.appkeyboard.data.local.SecureKeyStore
import com.frogobox.appkeyboard.data.remote.SecureApiService
import com.frogobox.appkeyboard.data.remote.StegoDecodeApiService
import com.frogobox.appkeyboard.data.remote.StegoDecodeRequest
import com.frogobox.appkeyboard.data.remote.StegoEncodeApiService
import com.frogobox.appkeyboard.data.remote.StegoEncodeRequest
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
    private val stegoEncodeApi: StegoEncodeApiService,
    private val stegoDecodeApi: StegoDecodeApiService,
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

        // stegov2 currently expects a one-word context prompt.
        private const val DEFAULT_STEGO_CONTEXT = "car"
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
        val email = "$username@example.com"  // example.com is valid; keyboard.local fails EmailStr validation

        // 1. Register on server
        val response = api.register(RegisterRequest(username, email, password))
        tokenManager.saveTokens(response.accessToken, response.refreshToken)
        tokenManager.saveUserInfo(response.userId, response.username)
        keyStore.setActiveUser(response.userId)

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
        keyStore.setActiveUser(user.userId)

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
        // Keep long-term keys per user so same emulator can switch users
        // without breaking key agreement for existing sessions.
        if (keyStore.hasActiveUser()) {
            keyStore.clearSessionMaterialForActiveUser()
            keyStore.clearActiveUser()
        }
        tokenManager.clearAll()
    }

    // ════════════════════════════════════════════════════════════
    //  Users
    // ════════════════════════════════════════════════════════════

    suspend fun searchUsers(query: String): Result<List<UserSearchResult>> = runCatching {
        api.searchUsers(query)
    }

    // ════════════════════════════════════════════════════════════
    //  Sessions (v3.0 — replaces Conversations)
    // ════════════════════════════════════════════════════════════

    /**
     * Create (or join) an E2EE session with a peer user.
     *
     * v4.0 Flow — role-aware X3DH:
     *
     * 1. POST /api/sessions/ → server either creates a NEW session or returns
     *    an EXISTING one (idempotent).
     * 2. If we already have a cached shared secret for this session → return early.
     * 3. Detect our role by comparing our user ID with session.initiatorId:
     *    • **Initiator** (we created it): X3DH initiate → DH(our_eph, peer_spk)
     *    • **Responder** (peer created it): fetch stored ephemeral key → X3DH respond
     *      → DH(our_spk, peer_eph)
     * 4. Cache the shared secret.
     */
    suspend fun createSession(
        peerUsername: String,
        peerUserId: String
    ): Result<SessionInfo> = runCatching {
        val myUserId = tokenManager.getUserId()
            ?: error("Not logged in — no user ID available")

        // ── Step 1: Fetch peer's key bundle & verify (needed for initiator path) ──
        val bundle = api.getKeyBundle(peerUserId)
        val identityKeyPub = E2EEService.fromBase64(bundle.identityKeyPublic)
        val signedPreKeyPub = E2EEService.fromBase64(bundle.signedPrekeyPublic)
        val signature = E2EEService.fromBase64(bundle.signedPrekeySignature)

        check(E2EEService.ed25519Verify(identityKeyPub, signedPreKeyPub, signature)) {
            "Recipient's signed pre-key signature is invalid — possible MITM"
        }

        // ── Step 2: Run X3DH initiate speculatively (generates ephemeral key) ──
        //    We'll only USE the result if we end up being the initiator.
        val x3dhInitResult = E2EEService.x3dhInitiate(recipientSignedPreKeyPublic = signedPreKeyPub)

        // ── Step 3: Create session on server (idempotent; may return existing) ──
        val session = api.createSession(CreateSessionRequest(
            peerUsername = peerUsername,
            ephemeralPublicKey = E2EEService.toBase64(x3dhInitResult.ephemeralPublicKey)
        ))

        // ── Step 4: If we already have key material, reuse it (no-op) ──
        if (keyStore.hasSharedSecret(session.sessionId)) {
            Log.d(TAG, "createSession: shared secret already cached for ${session.sessionId}")
            return@runCatching SessionInfo(
                sessionId = session.sessionId,
                peerUsername = peerUsername
            )
        }

        // ── Step 5: Detect our role and derive the correct shared secret ──
        val weAreInitiator = session.initiatorId == myUserId
        Log.d(TAG, "createSession: weAreInitiator=$weAreInitiator " +
                "(myId=$myUserId, initiatorId=${session.initiatorId})")

        val sharedSecret: ByteArray
        if (weAreInitiator) {
            // WE created this session → use X3DH initiate result
            sharedSecret = x3dhInitResult.sharedSecret
            keyStore.saveEphemeralPublicKey(session.sessionId, x3dhInitResult.ephemeralPublicKey)
            Log.d(TAG, "createSession: initiator path — saved ephemeral + shared secret")
        } else {
            // The OTHER user created this session → we are the responder.
            // Fetch THEIR ephemeral key and run x3dhRespond with OUR signed pre-key.
            val ephemeralData = api.getEphemeralKey(session.sessionId)
            val initiatorEphPub = E2EEService.fromBase64(ephemeralData.ephemeralPublicKey)

            val signedPreKey = keyStore.getSignedPreKey()
                ?: error("No signed pre-key found — cannot respond to X3DH")

            sharedSecret = E2EEService.x3dhRespond(
                signedPreKeyPrivate = signedPreKey.privateKey,
                ephemeralPublicKey = initiatorEphPub
            )
            Log.d(TAG, "createSession: responder path — derived shared secret via x3dhRespond")
        }

        // ── Step 6: Cache ──
        keyStore.saveSharedSecret(session.sessionId, sharedSecret)

        SessionInfo(
            sessionId = session.sessionId,
            peerUsername = peerUsername
        )
    }

    suspend fun listSessions(): Result<List<SessionResponse>> = runCatching {
        api.listSessions()
    }

    // ════════════════════════════════════════════════════════════
    //  Send Message (v4.1 - ChaCha20 + Modal stego encode)
    // ════════════════════════════════════════════════════════════

    /**
     * Encrypt a plaintext message and embed it into natural text via stego.
     *
     * Flow:
     * 1. Get next 16-bit counter from server
     * 2. Compress -> bare ChaCha20 encrypt -> pack with counter
     * 3. Convert packed bytes to bitstring
     * 4. Call Modal encode endpoint and return generated text
     */
    suspend fun sendMessage(
        sessionId: String,
        peerUsername: String,
        plaintext: String
    ): Result<SendResult> = runCatching {
        val sharedSecret = keyStore.getSharedSecret(sessionId)
            ?: error("No shared secret for session $sessionId — create session first")

        // 1. Get next counter from server
        val counterResp = api.getNextCounter(sessionId)
        val counter = counterResp.counter
        Log.d(TAG, "sendMessage: got counter=$counter for session=$sessionId peer=$peerUsername")

        // 2. Compress -> encrypt -> pack
        val payload = buildPayload(plaintext)
        val ciphertext = E2EEService.chacha20Encrypt(payload, sharedSecret, counter)
        val packed = E2EEService.packCiphertextWithCounter(ciphertext, counter)
        val packedBits = packed.toBitString()

        Log.d(TAG, "sendMessage: raw=${plaintext.toByteArray().size}B, " +
                "payload=${payload.size}B (flag=0x%02X), cipher=${ciphertext.size}B, " +
                "packed=${packed.size}B, counter=$counter"
                    .format(payload[0]))

        // 3. Encode packed ciphertext bits into natural text.
        //    Try Modal directly; if unreachable, fall back to server-side obfuscation.
        val obfuscatedText = try {
            stegoEncodeApi.encode(
                StegoEncodeRequest(
                    context = buildStegoContext(),
                    bits = packedBits
                )
            ).text
        } catch (e: Exception) {
            Log.w(TAG, "Modal stego encode failed (${e.message}) — falling back to server obfuscation")
            api.obfuscate(
                ObfuscateRequest(
                    ciphertextB64 = E2EEService.toBase64(packed),
                    peerUsername = peerUsername
                )
            ).obfuscatedText
        }

        SendResult(obfuscatedText = obfuscatedText)
    }

    // ════════════════════════════════════════════════════════════
    //  Decrypt Message (v4.1 - Modal stego decode + ChaCha20)
    // ════════════════════════════════════════════════════════════

    /**
     * Decrypt a stego text message received from another user.
     *
     * Flow:
     * 1. Call Modal decode endpoint to recover bits
     * 2. Resolve sender session and shared secret
     * 3. Convert bits to bytes and unpack counter/ciphertext
     * 4. Decrypt payload and parse compression flag
     */
    suspend fun decryptMessage(
        obfuscatedText: String,
        senderUsername: String
    ): Result<String> = runCatching {
        Log.d(TAG, "decryptMessage: sender=$senderUsername")

        // 1. Decode stego text into packed ciphertext bytes.
        //    Try Modal directly; if unreachable, fall back to server-side deobfuscation.
        val packed: ByteArray = try {
            bitStringToByteArray(
                stegoDecodeApi.decode(StegoDecodeRequest(text = obfuscatedText)).bits
            )
        } catch (e: Exception) {
            Log.w(TAG, "Modal stego decode failed (${e.message}) — falling back to server deobfuscation")
            E2EEService.fromBase64(
                api.deobfuscate(DeobfuscateRequest(obfuscatedText, senderUsername)).ciphertextB64
            )
        }

        // 2. Find the session for this sender to get shared secret
        val sessions = api.listSessions(activeOnly = true)
        val session = sessions.firstOrNull { s ->
            s.initiatorUsername == senderUsername || s.responderUsername == senderUsername
        } ?: error("No active session found with $senderUsername")

        // 3. Get or establish shared secret
        val sharedSecret = getOrEstablishSharedSecretForReceive(session.sessionId)

        // 4. Unpack -> decrypt -> decompress
        val (ciphertext, counter) = E2EEService.unpackCiphertextAndCounter(packed)
        Log.d(TAG, "decryptMessage: packed=${packed.size}B ciphertext=${ciphertext.size}B counter=$counter")

        val payload = E2EEService.chacha20Decrypt(ciphertext, sharedSecret, counter)
        val plaintext = parsePayload(payload)
        Log.d(TAG, "decryptMessage: success plaintext=${plaintext.take(50)}...")
        plaintext
    }.onFailure { e ->
        Log.e(TAG, "decryptMessage: failed", e)
    }

    // ════════════════════════════════════════════════════════════
    //  Internal: Shared Secret Management
    // ════════════════════════════════════════════════════════════

    /**
     * Get cached shared secret, or respond to X3DH to establish one (receiver side).
     *
     * v4.0: Ephemeral key is fetched from the server via GET /sessions/{id}/ephemeral-key
     * instead of being embedded in the message metadata.
     */
    private suspend fun getOrEstablishSharedSecretForReceive(
        sessionId: String
    ): ByteArray {
        // Check cache first
        val cached = keyStore.getSharedSecret(sessionId)
        if (cached != null) return cached

        // Fetch ephemeral key from server (v4.0)
        val ephemeralData = api.getEphemeralKey(sessionId)

        // Get our signed pre-key private
        val signedPreKey = keyStore.getSignedPreKey()
            ?: error("No signed pre-key found — cannot respond to X3DH")

        val ephemeralPub = E2EEService.fromBase64(ephemeralData.ephemeralPublicKey)
        val sharedSecret = E2EEService.x3dhRespond(
            signedPreKeyPrivate = signedPreKey.privateKey,
            ephemeralPublicKey = ephemeralPub
        )

        // Cache for future messages in this session
        keyStore.saveSharedSecret(sessionId, sharedSecret)
        return sharedSecret
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

    private fun ByteArray.toBitString(): String =
        joinToString(separator = "") { byte ->
            String.format("%8s", (byte.toInt() and 0xFF).toString(2)).replace(' ', '0')
        }

    private fun bitStringToByteArray(bits: String): ByteArray {
        val normalizedBits = bits.filterNot { it.isWhitespace() }
        require(normalizedBits.isNotBlank()) { "Decoded bitstring is empty" }
        require(normalizedBits.all { it == '0' || it == '1' }) {
            "Decoded bitstring contains invalid chars"
        }
        require(normalizedBits.length % 8 == 0) {
            "Decoded bitstring length must be a multiple of 8, got ${normalizedBits.length}"
        }

        return ByteArray(normalizedBits.length / 8) { index ->
            normalizedBits.substring(index * 8, index * 8 + 8).toInt(2).toByte()
        }
    }

    private fun buildStegoContext(): String = DEFAULT_STEGO_CONTEXT
}

// ════════════════════════════════════════════════════════════
//  Result Types
// ════════════════════════════════════════════════════════════

data class SendResult(
    val obfuscatedText: String
)

data class SessionInfo(
    val sessionId: String,
    val peerUsername: String
)

