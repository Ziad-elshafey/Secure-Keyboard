# Full Integration Plan — Keyboard ↔ Secure-Application Server

> **Goal**: Replace the throwaway Flask mock backend with the full Secure-Application FastAPI server, giving the keyboard real E2EE messaging with steganographic obfuscation.  
> **Last updated**: February 5, 2026

---

## Table of Contents

1. [Current State & Gap Analysis](#1-current-state--gap-analysis)
2. [Phase 1 — Dependency & Build Setup](#2-phase-1--dependency--build-setup)
3. [Phase 2 — Networking Layer (Retrofit + Auth)](#3-phase-2--networking-layer-retrofit--auth)
4. [Phase 3 — E2EE Crypto Service (X3DH + Signal)](#4-phase-3--e2ee-crypto-service-x3dh--signal)
5. [Phase 4 — Key & Session Persistence](#5-phase-4--key--session-persistence)
6. [Phase 5 — Secure Messaging Repository](#6-phase-5--secure-messaging-repository)
7. [Phase 6 — Keyboard Panel UI](#7-phase-6--keyboard-panel-ui)
8. [Phase 7 — KeyboardIME Integration](#8-phase-7--keyboardime-integration)
9. [Phase 8 — Server-Side Adjustments](#9-phase-8--server-side-adjustments)
10. [Phase 9 — Compression Integration](#10-phase-9--compression-integration)
11. [Phase 10 — Testing & Validation](#11-phase-10--testing--validation)
12. [Architecture Diagram](#12-architecture-diagram)
13. [File Manifest](#13-file-manifest)
14. [Open Decisions](#14-open-decisions)

---

## 1. Current State & Gap Analysis

### What Exists

| Component | Status | Location |
|-----------|--------|----------|
| Flask mock backend | ✅ Working (in-memory, no auth, random decoy) | `backend/server.py` |
| FastAPI secure server | ✅ Working (E2EE, stego, JWT, DB) | `Secure-application/Server/` |
| Retrofit + OkHttp | ✅ In build (2.9.0 / 4.12.0) | `app/build.gradle.kts` |
| BackendApiService | ✅ 3 endpoints (Flask only) | `data/remote/BackendApiService.kt` |
| Google Tink | ✅ In build (1.12.0) | `app/build.gradle.kts` |
| AndroidX Security-Crypto | ✅ In build (1.1.0-alpha06) | `app/build.gradle.kts` |
| XChaCha20-Poly1305 | ✅ Custom implementation | `core/XChaCha20Poly1305.kt` |
| HKDF-SHA256 | ✅ In PRNGManager | `core/PRNGManager.kt` |
| CryptoService | ✅ PRNG-based encrypt/decrypt | `core/CryptoService.kt` |
| DemoKeyboard panel | ✅ Upload-only to Flask | `ui/keyboard/demo/` |
| SecureMessagingKeyboard | ✅ Offline-only crypto | `ui/keyboard/securemessaging/` |
| Hilt DI | ✅ Set up, but NetworkModule is **empty** | `di/` |
| INTERNET permission | ✅ Declared | `AndroidManifest.xml` |

### What's Missing

| Component | Gap | Priority |
|-----------|-----|----------|
| **X25519 key exchange** | Not implemented — required for X3DH | 🔴 Critical |
| **Ed25519 signing** | Not implemented — required for identity keys | 🔴 Critical |
| **Standard ChaCha20-Poly1305** (12-byte nonce) | Only XChaCha20 (24-byte) exists; server uses standard | 🔴 Critical |
| **SecureApiService** (Retrofit) | 0 of ~18 server endpoints defined | 🔴 Critical |
| **JWT token management** | No storage, no interceptor, no refresh | 🔴 Critical |
| **OkHttp auth interceptor** | No `Authorization: Bearer` header injection | 🔴 Critical |
| **Hilt NetworkModule providers** | Module exists but provides nothing | 🟡 High |
| **EncryptedSharedPreferences** for keys/tokens | Keys stored in-memory only | 🟡 High |
| **E2EEService.kt** (X3DH protocol) | Python implementation exists, no Kotlin port | 🔴 Critical |
| **SecureMessaging Repository** | No abstraction layer for API + crypto | 🟡 High |
| **New keyboard panel** | Needs full UI for auth + send + receive | 🟡 High |
| **Structured coroutines** | `GlobalScope.launch` everywhere | 🟢 Medium |
| **Compression in pipeline** | Compress before encrypt (optional optimization) | 🟢 Medium |

---

## 2. Phase 1 — Dependency & Build Setup

### 2.1 Add Missing Dependencies

**File**: `app/build.gradle.kts`

```kotlin
// BouncyCastle for Ed25519, X25519 (Tink 1.12 doesn't expose raw X25519 DH)
implementation("org.bouncycastle:bcprov-jdk18on:1.79")
// Or use libsodium-jni for NaCl-compatible crypto:
// implementation("com.goterl:lazysodium-android:5.1.0@aar")
// implementation("net.java.dev.jna:jna:5.14.0@aar")

// Coroutines (if not already present)
implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.0")

// EncryptedSharedPreferences (already in build: androidx.security:security-crypto)
// JWT decoding (lightweight, no verification needed — server handles that)
implementation("com.auth0:java-jwt:4.4.0")  // optional, only if we need to inspect token expiry client-side
```

### 2.2 Decision: BouncyCastle vs Lazysodium vs Tink

| Option | Pros | Cons | Recommendation |
|--------|------|------|----------------|
| **BouncyCastle** | Pure Java, no native libs, well-tested, supports Ed25519 + X25519 + ChaCha20-Poly1305 | Larger binary (~5MB), verbose API | ✅ **Use this** |
| **Lazysodium** | NaCl-compatible, clean API, fast native code | JNA dependency, native `.so` files per ABI, crash risk | Good alternative |
| **Tink** | Already in build, Google-maintained | Doesn't expose raw X25519 DH or Ed25519 sign/verify directly | ❌ Insufficient |

**Decision**: Use **BouncyCastle** (`bcprov-jdk18on`). It provides everything (Ed25519, X25519, ChaCha20-Poly1305, HKDF) in a single pure-Java dependency. Tink stays for `EncryptedSharedPreferences` (which depends on it internally).

### 2.3 ProGuard / R8 Rules

**File**: `app/proguard-rules.pro` — add:
```
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
```

---

## 3. Phase 2 — Networking Layer (Retrofit + Auth)

### 3.1 Create DTO Classes

**New file**: `data/remote/dto/SecureApiDtos.kt`

```
Package: com.frogobox.appkeyboard.data.remote.dto

// ── Auth ──
RegisterRequest(username, email, password)
LoginRequest(username, password)
AuthResponse(userId, accessToken, refreshToken, tokenType)
RefreshRequest(refreshToken)

// ── Keys ──
UploadKeysRequest(identityKey, signedPrekey, signedPrekeySignature)  // all base64
KeyBundleResponse(userId, identityKey, signedPrekey, signedPrekeySignature)
KeyStatusResponse(hasKeys: Boolean)

// ── Conversations ──
CreateConversationRequest(participantIds: List<String>, title: String?)
ConversationResponse(conversationId, title, createdAt, lastMessageAt, participants)

// ── Messages ──
SendMessageRequest(conversationId, ciphertext, nonce, ephemeralPublicKey?)  // all base64
MessageResponse(messageId, conversationId, senderId, senderUsername, obfuscatedText, 
                obfuscationData, obfuscationVersion, seedId, createdAt, deliveredAt, status)
RevealMessageResponse(messageId, conversationId, senderId, ciphertext, nonce, 
                      ephemeralPublicKey?, obfuscationMetadata)

// ── Users ──
UserResponse(userId, username, email, displayName, createdAt)
```

### 3.2 Create SecureApiService Interface

**New file**: `data/remote/SecureApiService.kt`

```kotlin
interface SecureApiService {

    // ── Auth (no token needed) ──
    @POST("api/auth/register")
    suspend fun register(@Body request: RegisterRequest): AuthResponse

    @POST("api/auth/login")
    suspend fun login(@Body request: LoginRequest): AuthResponse

    @POST("api/auth/refresh")
    suspend fun refreshToken(@Body request: RefreshRequest): AuthResponse

    // ── Keys (token required) ──
    @POST("api/keys/upload")
    suspend fun uploadKeys(@Body request: UploadKeysRequest): JsonObject

    @GET("api/keys/bundle/{userId}")
    suspend fun getKeyBundle(@Path("userId") userId: String): KeyBundleResponse

    @GET("api/keys/status")
    suspend fun getKeyStatus(): KeyStatusResponse

    // ── Conversations (token required) ──
    @POST("api/conversations")
    suspend fun createConversation(@Body request: CreateConversationRequest): ConversationResponse

    @GET("api/conversations")
    suspend fun getConversations(): List<ConversationResponse>

    @GET("api/conversations/{id}")
    suspend fun getConversation(@Path("id") id: String): ConversationResponse

    // ── Messages (token required) ──
    @POST("api/messages/send")
    suspend fun sendMessage(@Body request: SendMessageRequest): MessageResponse

    @GET("api/messages/inbox")
    suspend fun getInbox(@Query("skip") skip: Int = 0, @Query("limit") limit: Int = 50): List<MessageResponse>

    @GET("api/messages/conversation/{conversationId}")
    suspend fun getConversationMessages(@Path("conversationId") id: String): List<MessageResponse>

    @GET("api/messages/{messageId}/reveal")
    suspend fun revealMessage(@Path("messageId") id: String): RevealMessageResponse

    // ── Users (token required) ──
    @GET("api/users/me")
    suspend fun getCurrentUser(): UserResponse

    @GET("api/users/search/{query}")
    suspend fun searchUsers(@Path("query") query: String): List<UserResponse>
}
```

### 3.3 Auth Token Manager

**New file**: `data/local/AuthTokenManager.kt`

Responsibilities:
- Store `accessToken`, `refreshToken`, `userId`, `username` in `EncryptedSharedPreferences`
- Expose `getAccessToken(): String?`, `isLoggedIn(): Boolean`
- `saveTokens(auth: AuthResponse)`, `clearTokens()`
- `isTokenExpired(): Boolean` — decode JWT `exp` claim (without verification, just base64 decode the payload)

### 3.4 Auth Interceptor

**New file**: `data/remote/AuthInterceptor.kt`

```kotlin
class AuthInterceptor(private val tokenManager: AuthTokenManager) : Interceptor {
    override fun intercept(chain: Chain): Response {
        val request = chain.request()
        
        // Skip auth for register/login/refresh endpoints
        if (request.url.encodedPath.contains("/auth/")) {
            return chain.proceed(request)
        }
        
        val token = tokenManager.getAccessToken()
        return if (token != null) {
            val authedRequest = request.newBuilder()
                .header("Authorization", "Bearer $token")
                .build()
            chain.proceed(authedRequest)
        } else {
            chain.proceed(request)
        }
    }
}
```

### 3.5 Token Refresh Authenticator

**New file**: `data/remote/TokenRefreshAuthenticator.kt`

```kotlin
class TokenRefreshAuthenticator(
    private val tokenManager: AuthTokenManager,
    private val refreshApiProvider: () -> SecureApiService  // avoid circular DI
) : Authenticator {
    override fun authenticate(route: Route?, response: Response): Request? {
        if (response.code != 401) return null
        
        val refreshToken = tokenManager.getRefreshToken() ?: return null
        
        // Synchronous refresh (Authenticator runs on OkHttp thread)
        val newTokens = runBlocking {
            refreshApiProvider().refreshToken(RefreshRequest(refreshToken))
        }
        tokenManager.saveTokens(newTokens)
        
        return response.request.newBuilder()
            .header("Authorization", "Bearer ${newTokens.accessToken}")
            .build()
    }
}
```

### 3.6 Wire into Hilt NetworkModule

**File**: `di/NetworkModule.kt`

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    @Provides @Singleton
    fun provideAuthTokenManager(@ApplicationContext context: Context): AuthTokenManager

    @Provides @Singleton
    fun provideOkHttpClient(
        authInterceptor: AuthInterceptor,
        tokenRefreshAuthenticator: TokenRefreshAuthenticator
    ): OkHttpClient

    @Provides @Singleton
    fun provideRetrofit(okHttpClient: OkHttpClient): Retrofit

    @Provides @Singleton
    fun provideSecureApiService(retrofit: Retrofit): SecureApiService

    @Provides @Singleton
    fun provideAuthInterceptor(tokenManager: AuthTokenManager): AuthInterceptor

    @Provides @Singleton
    fun provideTokenRefreshAuthenticator(
        tokenManager: AuthTokenManager,
        retrofit: Lazy<Retrofit>  // Lazy to break circular dependency
    ): TokenRefreshAuthenticator
}
```

**Base URL**: `http://10.0.2.2:8000/` (emulator → host FastAPI server on port 8000)

For physical device testing, use the machine's local IP (e.g., `http://192.168.x.x:8000/`). Consider making this configurable via `BuildConfig` field or `local.properties`.

---

## 4. Phase 3 — E2EE Crypto Service (X3DH + Signal)

### 4.1 Port Python `e2ee.py` → Kotlin `E2EEService.kt`

**New file**: `core/e2ee/E2EEService.kt`

This is the **most critical** new file. Port all 12 functions from `Secure-application/Server/app/services/e2ee.py`.

#### Crypto Primitives Needed (via BouncyCastle)

| Primitive | BouncyCastle Class | Purpose |
|-----------|-------------------|---------|
| Ed25519 keygen | `Ed25519KeyPairGenerator` | Identity key generation |
| Ed25519 sign | `Ed25519Signer` | Sign prekeys |
| Ed25519 verify | `Ed25519Signer` | Verify remote prekey signatures |
| X25519 keygen | `X25519KeyPairGenerator` | Signed prekey generation |
| X25519 DH | `X25519Agreement` | Compute shared secret |
| HKDF-SHA256 | `HKDFBytesGenerator` | Derive shared secret + message key |
| ChaCha20-Poly1305 | `ChaCha20Poly1305` | Encrypt/decrypt messages (12-byte nonce) |

#### Functions to Implement

```kotlin
object E2EEService {

    // ── Key Generation ──
    fun generateIdentityKeyPair(): IdentityKeyPair
        // Ed25519 keypair → {privateKey: ByteArray(32), publicKey: ByteArray(32)}

    fun generateSignedPreKey(identityPrivateKey: ByteArray): SignedPreKey
        // X25519 keypair + Ed25519 signature over public key
        // → {privateKey, publicKey, signature}

    // ── Key Serialization ──
    fun publicKeyToBase64(key: ByteArray): String
    fun base64ToPublicKey(b64: String): ByteArray

    // ── Signature Verification ──
    fun verifySignedPreKey(identityPublicKey: ByteArray, signedPreKeyPublic: ByteArray, signature: ByteArray): Boolean

    // ── X3DH Key Agreement ──
    fun x3dhInitiate(
        identityPrivateKey: ByteArray,       // not used directly in current impl
        ephemeralPrivateKey: ByteArray,       // X25519 ephemeral
        recipientSignedPreKeyPublic: ByteArray
    ): X3DHResult
        // DH = X25519(ephemeral_private, recipient_signed_prekey_public)
        // shared_secret = HKDF-SHA256(DH, info="SecureMessaging_SharedSecret")
        // → {sharedSecret: ByteArray(32), ephemeralPublicKey: ByteArray(32)}

    fun x3dhRespond(
        signedPreKeyPrivate: ByteArray,
        ephemeralPublicKey: ByteArray         // from initiator
    ): ByteArray  // shared_secret
        // DH = X25519(signed_prekey_private, ephemeral_public)
        // shared_secret = HKDF-SHA256(DH, info="SecureMessaging_SharedSecret")

    // ── Message Encryption ──
    fun encryptMessage(sharedSecret: ByteArray, plaintext: String): EncryptedMessage
        // message_key = HKDF-SHA256(shared_secret, info="SecureMessaging_MessageKey")
        // nonce = SecureRandom(12)
        // ciphertext = ChaCha20Poly1305.encrypt(message_key, nonce, plaintext.toByteArray())
        // → {ciphertext: ByteArray, nonce: ByteArray(12)}

    fun decryptMessage(sharedSecret: ByteArray, ciphertext: ByteArray, nonce: ByteArray): String
        // message_key = HKDF-SHA256(shared_secret, info="SecureMessaging_MessageKey")
        // plaintext = ChaCha20Poly1305.decrypt(message_key, nonce, ciphertext)
        // → plaintext string
}
```

#### Data Classes

```kotlin
data class IdentityKeyPair(val privateKey: ByteArray, val publicKey: ByteArray)
data class SignedPreKey(val privateKey: ByteArray, val publicKey: ByteArray, val signature: ByteArray)
data class X3DHResult(val sharedSecret: ByteArray, val ephemeralPublicKey: ByteArray)
data class EncryptedMessage(val ciphertext: ByteArray, val nonce: ByteArray)
```

### 4.2 Protocol Constants (Must Match Server)

```kotlin
const val HKDF_INFO_SHARED_SECRET = "SecureMessaging_SharedSecret"
const val HKDF_INFO_MESSAGE_KEY = "SecureMessaging_MessageKey"
const val HKDF_KEY_LENGTH = 32
const val CHACHA_NONCE_LENGTH = 12  // Standard ChaCha20-Poly1305, NOT XChaCha20's 24
```

### 4.3 Compatibility Note

The server uses **standard ChaCha20-Poly1305** (RFC 8439, 12-byte nonce) via Python's `cryptography` library. The existing Android `XChaCha20Poly1305.kt` uses a **24-byte nonce** and custom HChaCha20. These are **incompatible**. The new `E2EEService` must use BouncyCastle's standard `ChaCha20Poly1305` engine for server compatibility.

The existing `XChaCha20Poly1305` + `CryptoService` remain available for the offline `SecureMessagingKeyboard` panel — they serve a different use case.

---

## 5. Phase 4 — Key & Session Persistence

### 5.1 Encrypted Key Store

**New file**: `data/local/SecureKeyStore.kt`

Uses `EncryptedSharedPreferences` (already available via `androidx.security:security-crypto`):

```kotlin
class SecureKeyStore(context: Context) {
    private val prefs = EncryptedSharedPreferences.create(
        "secure_key_store",
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    // Identity keys (Ed25519) — persist across sessions
    fun saveIdentityKeyPair(keyPair: IdentityKeyPair)
    fun getIdentityKeyPair(): IdentityKeyPair?
    fun hasIdentityKeys(): Boolean

    // Signed prekey (X25519) — persist, rotate periodically
    fun saveSignedPreKey(preKey: SignedPreKey)
    fun getSignedPreKey(): SignedPreKey?

    // Shared secrets per conversation — persist for message decryption
    fun saveSharedSecret(conversationId: String, secret: ByteArray)
    fun getSharedSecret(conversationId: String): ByteArray?

    // User info
    fun saveUserId(userId: String)
    fun getUserId(): String?

    fun clearAll()  // logout / account deletion
}
```

### 5.2 What Gets Stored Where

| Data | Storage | Encryption |
|------|---------|-----------|
| JWT access token | `EncryptedSharedPreferences` ("auth_tokens") | AES-256-GCM |
| JWT refresh token | `EncryptedSharedPreferences` ("auth_tokens") | AES-256-GCM |
| Ed25519 identity key pair | `EncryptedSharedPreferences` ("secure_key_store") | AES-256-GCM |
| X25519 signed prekey pair | `EncryptedSharedPreferences` ("secure_key_store") | AES-256-GCM |
| Shared secrets (per conversation) | `EncryptedSharedPreferences` ("secure_key_store") | AES-256-GCM |
| User ID, username | `EncryptedSharedPreferences` ("auth_tokens") | AES-256-GCM |
| Conversation list | Room DB (existing `AppDatabase`) or in-memory cache | Unencrypted (IDs only, no content) |
| Decrypted messages | **Never stored** — display only, held in UI state | N/A |

---

## 6. Phase 5 — Secure Messaging Repository

### 6.1 Repository Layer

**New file**: `data/repository/SecureMessagingRepository.kt`

This is the **orchestrator** that combines API calls + crypto + key storage into clean use cases.

```kotlin
class SecureMessagingRepository @Inject constructor(
    private val api: SecureApiService,
    private val keyStore: SecureKeyStore,
    private val tokenManager: AuthTokenManager,
    private val e2ee: E2EEService
) {

    // ── Auth ──
    suspend fun register(username: String, email: String, password: String): Result<Unit>
        // 1. api.register() → save tokens + userId
        // 2. Generate Ed25519 identity + X25519 signed prekey
        // 3. api.uploadKeys() → upload public keys
        // 4. Save key pairs to SecureKeyStore

    suspend fun login(username: String, password: String): Result<Unit>
        // 1. api.login() → save tokens
        // 2. Check if keys already uploaded (api.getKeyStatus())
        // 3. If not, generate + upload + save

    fun isLoggedIn(): Boolean

    // ── Conversations ──
    suspend fun findUser(query: String): Result<List<UserResponse>>
    suspend fun createConversation(recipientId: String): Result<ConversationResponse>
    suspend fun getConversations(): Result<List<ConversationResponse>>

    // ── Send Message ──
    suspend fun sendMessage(conversationId: String, recipientId: String, plaintext: String): Result<SendResult>
        // 1. Get or establish shared secret:
        //    a. Check keyStore for existing shared secret for this conversation
        //    b. If none: fetch recipient's key bundle → X3DH initiate → save shared secret
        // 2. e2ee.encryptMessage(sharedSecret, plaintext) → {ciphertext, nonce}
        // 3. api.sendMessage(conversationId, base64(ciphertext), base64(nonce), base64(ephemeralPubKey))
        // 4. Return SendResult(obfuscatedText, messageId)

    // ── Receive Messages ──
    suspend fun getInbox(): Result<List<ObfuscatedMessage>>
        // api.getInbox() → list of messages with obfuscated_text (natural English)

    suspend fun revealAndDecrypt(messageId: String, senderId: String): Result<String>
        // 1. api.revealMessage(messageId) → {ciphertext, nonce, ephemeralPublicKey}
        // 2. Get or establish shared secret:
        //    a. Check keyStore for existing shared secret
        //    b. If none: X3DH respond using ephemeralPublicKey + our signedPreKey → save
        // 3. e2ee.decryptMessage(sharedSecret, ciphertext, nonce) → plaintext
        // 4. Return plaintext (NEVER stored)
}

data class SendResult(val obfuscatedText: String, val messageId: String)
data class ObfuscatedMessage(val messageId: String, val senderId: String, 
                              val senderUsername: String, val obfuscatedText: String,
                              val conversationId: String, val createdAt: String)
```

### 6.2 Hilt Wiring

**File**: `di/RepositoryModule.kt` — add:

```kotlin
@Provides @Singleton
fun provideSecureKeyStore(@ApplicationContext context: Context): SecureKeyStore

@Provides @Singleton
fun provideSecureMessagingRepository(
    api: SecureApiService,
    keyStore: SecureKeyStore,
    tokenManager: AuthTokenManager
): SecureMessagingRepository
```

---

## 7. Phase 6 — Keyboard Panel UI

### 7.1 New Panel: `IntegratedSecureKeyboard`

**New directory**: `ui/keyboard/integratedsecure/`

```
integratedsecure/
├── IntegratedSecureKeyboard.kt       # Custom View extending BaseKeyboard
├── IntegratedSecureViewModel.kt      # Or state holder (since Views can't use ViewModel directly)
└── keyboard_integrated_secure.xml    # Layout
```

### 7.2 UI States & Screens

```
┌─────────────────────────────────────────┐
│  State Machine                          │
│                                         │
│  NOT_LOGGED_IN ──→ REGISTERING          │
│       │                │                │
│       ▼                ▼                │
│  LOGGING_IN ──→ LOGGED_IN              │
│                    │                    │
│         ┌──────────┼──────────┐        │
│         ▼          ▼          ▼        │
│     COMPOSE    INBOX     CONVERSATION  │
│     (type &    (list      (read &      │
│      send)     messages)   decrypt)    │
└─────────────────────────────────────────┘
```

**Screen: Not Logged In / Register**
- Username + password fields (compact, fits keyboard height)
- "Register" / "Login" toggle
- Auto-generates email as `username@keyboard.local` if not provided

**Screen: Compose (Main)**
- Reads current text from `InputConnection` (what user typed in the app)
- "Recipient" dropdown (search users)
- **[Send Secure]** button → encrypt → upload → replace input text with obfuscated decoy
- Status: "✅ Sent — decoy text inserted" or "❌ Failed"

**Screen: Inbox**
- List of received messages (shows obfuscated text preview)
- Tap a message → **[Reveal & Decrypt]** → shows plaintext in a toast/overlay
- Plaintext is **never** written to the text field unless user explicitly taps "Paste to field"

**Screen: Conversation View**
- Message thread with sender labels
- Each message shows: obfuscated text → tap → plaintext

### 7.3 Dependency Access Pattern

Since custom Views can't use `@Inject`, use Hilt's `EntryPointAccessors`:

```kotlin
@EntryPoint
@InstallIn(SingletonComponent::class)
interface SecureKeyboardEntryPoint {
    fun secureMessagingRepository(): SecureMessagingRepository
    fun authTokenManager(): AuthTokenManager
}

class IntegratedSecureKeyboard(context: Context, attrs: AttributeSet?) : BaseKeyboard<...>(...) {
    private val entryPoint by lazy {
        EntryPointAccessors.fromApplication(context, SecureKeyboardEntryPoint::class.java)
    }
    private val repository by lazy { entryPoint.secureMessagingRepository() }
}
```

---

## 8. Phase 7 — KeyboardIME Integration

### 8.1 Add Panel to Layout

**File**: `res/layout/keyboard_ime.xml` — add:

```xml
<com.frogobox.appkeyboard.ui.keyboard.integratedsecure.IntegratedSecureKeyboard
    android:id="@+id/keyboardIntegratedSecure"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:visibility="gone" />
```

### 8.2 Add Menu Entry

**File**: `services/KeyboardIME.kt` — in `setupFeatureKeyboard()`:

```kotlin
KeyboardFeatureType.INTEGRATED_SECURE -> {
    hideMainKeyboard()
    binding.keyboardIntegratedSecure.visible()
    binding.keyboardIntegratedSecure.setInputConnection(currentInputConnection)
}
```

### 8.3 Add Feature Type

**File**: `common/KeyboardFeatureType.kt` (or wherever the enum lives):

```kotlin
INTEGRATED_SECURE("Secure Chat", R.drawable.ic_secure_messaging)
```

---

## 9. Phase 8 — Server-Side Adjustments

### 9.1 Verify Stego API Availability

The server's `obfuscation.py` calls external Modal-hosted endpoints:
- `https://nishxnt-97--encode.modal.run` (encode)
- `https://nishxnt-97--decode.modal.run` (decode)

**Action items**:
- [ ] Test if these endpoints are still live
- [ ] If dead: implement a **fallback mock obfuscation** in `obfuscation.py` that uses simple base64 + padding to simulate the stego layer (for development/demo purposes)
- [ ] Consider hosting the stego model locally or on a reliable cloud endpoint

### 9.2 Add Mock Obfuscation Fallback

In `obfuscation.py`, add a fallback when the stego API is unavailable:

```python
def obfuscate_mock(self, ciphertext: bytes, seed: str) -> Dict[str, Any]:
    """Fallback: base64-encode ciphertext, wrap in seed text."""
    b64 = base64.b64encode(ciphertext).decode()
    fake_text = f"{seed} {self._interleave_with_words(b64)}"
    return {
        'obfuscated_text': fake_text,
        'obfuscation_data': {'mock': True, 'b64': b64}
    }
```

### 9.3 CORS Configuration

**File**: `Secure-application/Server/main.py`

Ensure CORS allows requests from the Android app (shouldn't be an issue since Android doesn't enforce CORS, but good practice):

```python
app.add_middleware(CORSMiddleware, allow_origins=["*"], ...)
```

### 9.4 Server Startup for Development

```bash
cd Secure-application/Server
pip install -r requirements.txt
# Create .env from .env.example
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 10. Phase 9 — Compression Integration

### 10.1 Compress Before Encrypt (Optional Optimization)

Insert compression into the message pipeline:

```
plaintext → compress (arithmetic coding) → encrypt (ChaCha20-Poly1305) → send to server
```

**In `SecureMessagingRepository.sendMessage()`**:

```kotlin
// Before encryption:
val compressed = TextCompressor.compress(plaintext)  // existing compressor
val encrypted = e2ee.encryptMessage(sharedSecret, compressed)

// On receive, after decryption:
val decompressed = TextCompressor.decompress(decryptedBytes)
```

### 10.2 Protocol Flag

Add a flag in the message metadata to indicate whether compression was used, so the receiver knows to decompress:

```kotlin
// In SendMessageRequest, add optional field:
val compressed: Boolean = true
```

Or encode it in the first byte of the plaintext payload:
```
Byte 0: 0x01 = compressed, 0x00 = raw
Bytes 1-N: payload
```

### 10.3 Compression Improvements (Future)

Per earlier analysis, current compression achieves ~17 bits/word. Planned improvements:
1. Bigram/trigram context modeling → 10-12 bits/word
2. Variable-length header → reduced overhead on short messages
3. BPE subword tokenization → better unknown-word handling

These are independent of the server integration and can be developed in parallel.

---

## 11. Phase 10 — Testing & Validation

### 11.1 Unit Tests

| Test | What it validates |
|------|------------------|
| `E2EEServiceTest.kt` | Ed25519 keygen, X25519 DH, HKDF derivation, ChaCha20 encrypt/decrypt, X3DH initiator ↔ responder produce same shared secret |
| `SecureApiServiceTest.kt` | Retrofit serialization/deserialization of all DTOs |
| `AuthTokenManagerTest.kt` | Token storage, expiry detection, refresh logic |
| `SecureKeyStoreTest.kt` | Key persistence, retrieval, clearAll |

### 11.2 Integration Tests

| Test | What it validates |
|------|------------------|
| **Cross-language crypto** | Kotlin `E2EEService.encryptMessage()` output can be decrypted by Python `e2ee.py.decrypt_message()` and vice versa |
| **Full round-trip** | Register → upload keys → create conversation → send encrypted → server obfuscates → retrieve → reveal → decrypt → plaintext matches |
| **Token refresh** | Access token expires → interceptor refreshes → request succeeds |
| **Offline resilience** | App handles server unreachable gracefully (queues messages or shows error) |

### 11.3 Cross-Language Crypto Validation (Critical)

Before integrating, validate that Kotlin and Python produce identical outputs:

```
Test vector:
  plaintext = "Hello Bob!"
  shared_secret = SHA256("test-secret")  // deterministic for testing
  nonce = bytes([0]*12)                   // deterministic for testing

  Python:  encrypt_message(shared_secret, plaintext) → ciphertext_py
  Kotlin:  E2EEService.encryptMessage(shared_secret, plaintext, nonce) → ciphertext_kt

  Assert: ciphertext_py == ciphertext_kt
  Assert: Python can decrypt ciphertext_kt
  Assert: Kotlin can decrypt ciphertext_py
```

### 11.4 Two-Device End-to-End Test

1. Start FastAPI server on host machine
2. Launch two emulators (or emulator + physical device)
3. Device A: register as "alice", type message, tap [Send Secure]
4. Device B: register as "bob", open inbox, tap message, tap [Reveal & Decrypt]
5. Verify: Bob sees Alice's original plaintext

---

## 12. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        ANDROID KEYBOARD                         │
│                                                                 │
│  ┌──────────────┐     ┌────────────────────┐                   │
│  │ InputMethod  │     │ IntegratedSecure    │                   │
│  │ Service      │────▶│ Keyboard Panel     │                   │
│  │ (KeyboardIME)│     │ (UI layer)          │                   │
│  └──────────────┘     └────────┬───────────┘                   │
│                                │                                │
│                    ┌───────────▼───────────┐                   │
│                    │ SecureMessaging       │                    │
│                    │ Repository            │                    │
│                    │ (orchestrator)        │                    │
│                    └──┬──────┬──────┬─────┘                    │
│                       │      │      │                           │
│              ┌────────▼┐  ┌──▼───┐  ┌▼──────────┐             │
│              │ Secure  │  │E2EE  │  │ TextComp- │              │
│              │ Api     │  │Svc   │  │ ressor    │              │
│              │ Service │  │(X3DH)│  │ (arith.)  │              │
│              └────┬────┘  └──────┘  └───────────┘              │
│                   │                                             │
│              ┌────▼────────────┐    ┌──────────────┐           │
│              │ OkHttp +        │    │ SecureKey-   │           │
│              │ AuthInterceptor │    │ Store        │           │
│              └────┬────────────┘    │ (EncryptSP)  │           │
│                   │                 └──────────────┘           │
└───────────────────┼─────────────────────────────────────────────┘
                    │ HTTPS
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FASTAPI SERVER (:8000)                        │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ /auth    │  │ /keys    │  │ /convos  │  │ /messages│       │
│  │ register │  │ upload   │  │ create   │  │ send     │       │
│  │ login    │  │ bundle   │  │ list     │  │ inbox    │       │
│  │ refresh  │  │ status   │  │          │  │ reveal   │       │
│  └──────────┘  └──────────┘  └──────────┘  └────┬─────┘       │
│                                                  │              │
│                                     ┌────────────▼────────┐    │
│                                     │ Obfuscation Service │    │
│                                     │ (stego encode/decode)│   │
│                                     └────────────┬────────┘    │
│                                                  │              │
│                                     ┌────────────▼────────┐    │
│                                     │ PostgreSQL / SQLite │    │
│                                     │ (users, messages,   │    │
│                                     │  seeds_vault, keys) │    │
│                                     └─────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼ (External, optional)
        ┌───────────────────────┐
        │ Modal Stego API       │
        │ (LLM arithmetic       │
        │  coding encode/decode) │
        └───────────────────────┘
```

---

## 13. File Manifest

All new files to be created, grouped by phase:

### Phase 1 — Build
| Action | File |
|--------|------|
| MODIFY | `app/build.gradle.kts` — add BouncyCastle dependency |
| MODIFY | `app/proguard-rules.pro` — keep BouncyCastle classes |

### Phase 2 — Networking
| Action | File |
|--------|------|
| CREATE | `app/src/main/java/.../data/remote/dto/SecureApiDtos.kt` |
| CREATE | `app/src/main/java/.../data/remote/SecureApiService.kt` |
| CREATE | `app/src/main/java/.../data/remote/AuthInterceptor.kt` |
| CREATE | `app/src/main/java/.../data/remote/TokenRefreshAuthenticator.kt` |
| MODIFY | `app/src/main/java/.../di/NetworkModule.kt` |

### Phase 3 — Crypto
| Action | File |
|--------|------|
| CREATE | `app/src/main/java/.../core/e2ee/E2EEService.kt` |
| CREATE | `app/src/main/java/.../core/e2ee/E2EEModels.kt` |

### Phase 4 — Persistence
| Action | File |
|--------|------|
| CREATE | `app/src/main/java/.../data/local/AuthTokenManager.kt` |
| CREATE | `app/src/main/java/.../data/local/SecureKeyStore.kt` |

### Phase 5 — Repository
| Action | File |
|--------|------|
| CREATE | `app/src/main/java/.../data/repository/SecureMessagingRepository.kt` |
| MODIFY | `app/src/main/java/.../di/RepositoryModule.kt` |

### Phase 6 — UI
| Action | File |
|--------|------|
| CREATE | `app/src/main/java/.../ui/keyboard/integratedsecure/IntegratedSecureKeyboard.kt` |
| CREATE | `app/src/main/res/layout/keyboard_integrated_secure.xml` |

### Phase 7 — IME Wiring
| Action | File |
|--------|------|
| MODIFY | `app/src/main/res/layout/keyboard_ime.xml` |
| MODIFY | `app/src/main/java/.../services/KeyboardIME.kt` |
| MODIFY | `app/src/main/java/.../common/KeyboardFeatureType.kt` (or equivalent) |

### Phase 8 — Server
| Action | File |
|--------|------|
| MODIFY | `Secure-application/Server/app/services/obfuscation.py` — add mock fallback |
| VERIFY | `Secure-application/Server/main.py` — CORS config |

### Phase 10 — Tests
| Action | File |
|--------|------|
| CREATE | `app/src/test/java/.../core/e2ee/E2EEServiceTest.kt` |
| CREATE | `app/src/test/java/.../data/remote/SecureApiServiceTest.kt` |
| CREATE | `app/src/test/java/.../CrossLanguageCryptoTest.kt` |

**Total: ~14 new files, ~6 modified files**

---

## 14. Open Decisions

| # | Question | Options | Recommendation |
|---|----------|---------|----------------|
| 1 | **Crypto library** | BouncyCastle vs Lazysodium vs Tink | BouncyCastle (pure Java, full coverage) |
| 2 | **Stego API availability** | External Modal API vs local fallback | Implement mock fallback, test external |
| 3 | **Key persistence** | EncryptedSharedPreferences vs Room + Tink AEAD | EncryptedSharedPreferences (simpler) |
| 4 | **Base URL config** | Hardcoded vs BuildConfig vs settings UI | BuildConfig field + `local.properties` override |
| 5 | **Registration UX** | Full form vs auto-generate vs username-only | Username + password only, auto-email |
| 6 | **Compression in pipeline** | Always compress vs flag-based vs skip for now | Flag-based (first byte = 0x01 if compressed) |
| 7 | **Message queue for offline** | Drop messages vs WorkManager queue | WorkManager queue (already in dependencies) |
| 8 | **Panel architecture** | Custom View + EntryPoint vs Fragment vs Compose | Custom View + EntryPoint (matches existing pattern) |
| 9 | **Shared secret per-conversation or per-message** | Reuse vs derive new each time | Per-conversation (persist, simpler, matches demo) |
| 10 | **Double Ratchet (future)** | Implement now vs later | Later — X3DH is sufficient for v1 |

---

## Implementation Order (Suggested)

```
Week 1:  Phase 1 (deps) + Phase 3 (E2EE crypto) + cross-language crypto tests
Week 2:  Phase 2 (networking) + Phase 4 (persistence)
Week 3:  Phase 5 (repository) + Phase 8 (server adjustments)
Week 4:  Phase 6 (UI) + Phase 7 (IME wiring)
Week 5:  Phase 9 (compression) + Phase 10 (full integration testing)
```

Phases 1-3 are the **critical path** — everything else depends on the crypto and networking layers being correct.
