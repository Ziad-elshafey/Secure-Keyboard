# Secure-Keyboard-v2: Production-Readiness Code Review

**Audit Date:** March 10, 2026
**Scope:** Full codebase — Android keyboard app (`app/`), E2EE protocol, accessibility service, compression module, and FastAPI backend (`Secure-application/Server/`)
**Verdict: NOT READY FOR PRODUCTION**

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 33 |
| HIGH     | 40 |
| MEDIUM   | 50 |
| LOW      | 30 |
| **Total** | **153** |

The application has fundamental cryptographic flaws (incomplete X3DH, unauthenticated cipher), crash-inducing lifecycle bugs (`GlobalScope`, force-unwraps), and production configuration failures (hardcoded HTTP, debug logging shipped in release). **All CRITICAL and HIGH issues must be resolved before any deployment.**

---

## Full Remediation Status

**Status Date:** March 25, 2026  
**Scope:** All three codebases -- `app/` (Frogobox keyboard), `Secure-Keyboard-v2/` (FlorisBoard fork), and `Secure-application/Server/` (FastAPI backend).

> The original findings were written against the legacy `app/` + `Secure-application/Server/` stack. SK-v2 already had many fixes. This pass ported all proven SK-v2 patterns into `app/`, hardened the server, and fixed remaining issues in both clients.

### Completed (both app/ and SK-v2)

- [x] Gate sensitive client-side logging behind `BuildConfig.DEBUG`; reduce HTTP logging to `NONE` for release; gate Chucker behind DEBUG.
- [x] Add `EncryptedSharedPreferences` crash recovery via `EncryptedPrefsFactory` (try-catch + delete + retry on Keystore corruption).
- [x] Move secure/stego endpoints into `BuildConfig` fields; restrict cleartext localhost to debug builds only via split `network_security_config.xml`.
- [x] Synchronize token refresh with `synchronized(refreshLock)` + double-check + `withTimeout(10_000)`; keep user identity on failure via `clearTokens()`.
- [x] Replace live messaging path with authenticated ChaCha20-Poly1305 envelopes (SM1 format with counter AAD), with legacy bare-ChaCha20 decrypt fallback.
- [x] Harden decrypt-capture overlays: cancel button on touch overlay, 15-second timeout, `WindowManager.addView()` wrapped in try-catch.
- [x] Add `PROCESS_TEXT` size guard (50KB limit) and change clipboard label from `"Encrypted"` to `"Text"`.
- [x] Roll back local auth/session bootstrap state when registration or login fails to complete key upload.
- [x] Serialize client-side `createSession()` via `Mutex` and resolve ambiguous decrypt by binding to concrete session ID.
- [x] Replace all `GlobalScope` with lifecycle-scoped coroutines (`serviceScope` in IME, `lifecycleScope` in Activities, `viewScope` in Views).
- [x] Fix null-safety crashes: `keyboard ?: return`, null-safe WebView IC, `ThemeType.valueOf` try-catch.
- [x] Use `commitOrThrow()` / `commit()` for all critical SharedPreferences writes (no more `apply()` for key material).
- [x] Fix `isLoggedIn()` to check `isNullOrBlank()`, not just `!= null`.
- [x] Fix `onKey` to only create InputConnection for the focused EditText, not all three.
- [x] Enable R8 minification and lint checks for release builds.
- [x] Exclude encrypted prefs and active session prefs from backup in both `backup_rules.xml` and `data_extraction_rules.xml`.
- [x] Disable compression module (17 CRITICAL/HIGH issues mitigated; decompress path kept for backward compat).
- [x] Thread-safe `SecureMessagingKeyboard` lazy repo init with `@Volatile` + double-checked locking.
- [x] Fix `accessibility_service_config.xml`: `typeAllMask` replaced with specific event types; deprecated flag removed.

### Completed (server only)

- [x] Implement authenticated server logout that invalidates issued tokens and deactivates active sessions.
- [x] Rotate refresh tokens server-side and reject replay of refresh tokens after use.
- [x] Make session counter increments atomic server-side.
- [x] Restrict ephemeral key retrieval to the responder and delete the stored ephemeral key after the first successful fetch.
- [x] Remove insecure default values for `secret_key`, `seed_encryption_key`, `xor_key`; fail-closed startup validation.
- [x] Replace `Fernet.generate_key()` fallback with hard error on invalid key.
- [x] Restrict CORS to configurable origins from settings (empty default = fail-closed).
- [x] Use config-driven token expiry instead of hardcoded values; align JWT algorithm with settings.
- [x] Replace synchronous `requests.post()` with async `httpx.AsyncClient` for stego API calls.
- [x] Use `StaticPool` for SQLite; `QueuePool` for PostgreSQL.
- [x] Remove `debug_mode` and `obfuscation_version` from `/health` endpoint.

### Remaining Open

- [ ] Implement full X3DH identity binding (3 DH operations) and proper ratcheting. Requires coordinated client+server protocol redesign.
- [ ] Fully recycle `AccessibilityNodeInfo` traversal objects across every scan path.
- [ ] Add rate limiting on auth endpoints (requires adding `slowapi` or similar dependency).
- [ ] Add certificate pinning (requires production server certificate hash).
- [ ] Rework compression module code (currently disabled; code unfixed but inert).

---

## 1. CRITICAL Issues (Ship-Blockers)

### 1.1 E2EE Protocol

#### E2EE-C1: Incomplete X3DH — Only 1 of 3 Required DH Operations

- **File:** `app/.../core/e2ee/E2EEService.kt`, lines 125-141
- **Description:** `x3dhInitiate` only computes `DH(ephemeral, signed_prekey)`. The Signal X3DH spec requires 3 DH operations binding both parties' identity keys. Identity keys play zero role in the key agreement.
- **Impact:** MITM can substitute their own keys and impersonate either party undetectably.
- **Fix:** Implement full X3DH: `DH1 = DH(IK_A, SPK_B)`, `DH2 = DH(EK_A, IK_B)`, `DH3 = DH(EK_A, SPK_B)`, concatenate all DH results before HKDF.

#### E2EE-C2: Signed Pre-Key Signature Never Verified

- **File:** `app/.../core/e2ee/E2EEService.kt`, lines 125-141
- **Description:** `x3dhInitiate` accepts `recipientSignedPreKeyPublic` as raw bytes but never calls `ed25519Verify` to check the signature. The verification function exists (line 97) but is unused in the handshake.
- **Impact:** A compromised server can supply a rogue signed pre-key; the initiator derives a shared secret with the attacker.
- **Fix:** Add `recipientIdentityPublic` and `recipientSignedPreKeySignature` parameters to `x3dhInitiate`; verify before DH.

#### E2EE-C3: Bare ChaCha20 Without Authentication Tag

- **File:** `app/.../core/e2ee/E2EEService.kt`, lines 308-398; `app/.../data/repository/SecureMessagingRepository.kt`, lines 282-283
- **Description:** The live messaging path calls `E2EEService.chacha20Encrypt`/`chacha20Decrypt` — a bare stream cipher with no Poly1305 tag. The AEAD path (`encryptMessage`/`decryptMessage`) exists but is never used for actual messages.
- **Impact:** Ciphertext is malleable. Bit-flipping attacks modify plaintext without detection. The compression flag byte (0x00/0x01) is also unprotected.
- **Fix:** Replace `chacha20Encrypt`/`chacha20Decrypt` with `encryptBytes`/`decryptToBytes` (ChaCha20-Poly1305) in `SecureMessagingRepository`.

#### E2EE-C4: No Forward Secrecy — No Ratcheting

- **File:** `app/.../core/e2ee/E2EEService.kt`, lines 178-217
- **Description:** The message key is derived deterministically from `(sharedSecret, counter)` with no evolving state. There is no Double Ratchet or symmetric-key ratchet. Compromise of the shared secret exposes every past and future message.
- **Impact:** No post-compromise security. One leaked shared secret = entire conversation history exposed.
- **Fix:** Implement at minimum a symmetric-key ratchet (KDF chain) where each message key derives the next chain key.

### 1.2 Key Storage

#### KS-C1: EncryptedSharedPreferences Crash Loop on Keystore Corruption

- **File:** `app/.../data/local/SecureKeyStore.kt`, lines 25-36
- **Description:** The `lazy` initialization of `EncryptedSharedPreferences` has no try-catch. If the Android Keystore master key is lost (OS update, backup restore, device migration), `create()` throws and the exception is cached by `lazy` — every subsequent access re-throws permanently.
- **Impact:** Keyboard becomes completely unusable. User must clear app data or reinstall.
- **Fix:** Wrap in try-catch; on failure, delete the corrupted prefs file and retry once.

#### KS-C2: Same Crash Loop in AuthTokenManager

- **File:** `app/.../data/local/AuthTokenManager.kt`, lines 15-26
- **Description:** Identical to KS-C1. No recovery path for Keystore corruption.
- **Impact:** Same permanent crash loop.
- **Fix:** Same recovery pattern.

### 1.3 Keyboard Crashes

#### UI-C1: GlobalScope in IME Service — Crash on Destroyed Context

- **File:** `app/.../services/KeyboardIME.kt`, lines 513, 586
- **Description:** Encrypt/decrypt coroutines use `GlobalScope`. If the IME is destroyed mid-operation, callbacks call `Toast.makeText(this@KeyboardIME, ...)` on a dead context and access `currentInputConnection` which may be null or belong to a different field.
- **Impact:** `BadTokenException` crash or encrypted text committed to the wrong input field.
- **Fix:** Create a `CoroutineScope` tied to service lifecycle; cancel in `onDestroy()`.

#### UI-C2: GlobalScope in SecureTextActionActivity — Rotation Crash

- **File:** `app/.../ui/secure/SecureTextActionActivity.kt`, lines 101, 146, 224, 265
- **Description:** Four `GlobalScope.launch` blocks access `binding` after activity may be destroyed by rotation.
- **Impact:** Crash on screen rotation during encrypt/decrypt. Common since this is a dialog-style activity.
- **Fix:** Use `lifecycleScope`.

#### UI-C3: GlobalScope in SecureAuthActivity

- **File:** `app/.../ui/secure/SecureAuthActivity.kt`, line 60
- **Description:** Auth coroutine accesses `binding` on destroyed activity. No double-submission protection.
- **Impact:** Crash on rotation during login/register.
- **Fix:** Use `lifecycleScope`.

#### UI-C4: `keyboard!!` Force-Unwrap NPE

- **File:** `app/.../services/KeyboardIME.kt`, line 92
- **Description:** `keyboard` is nullable. Android can call `initialSetupKeyboard()` before `onInitializeInterface()` on some devices (Samsung, Xiaomi).
- **Impact:** Keyboard service crashes and becomes unusable.
- **Fix:** `keyboard ?: return`.

#### UI-C5: Null InputConnection in WebView Mode Crashes Every Keystroke

- **File:** `app/.../services/KeyboardIME.kt`, lines 423-429
- **Description:** `webview.onCreateInputConnection(EditorInfo())` can return null (platform type). Result is passed to `onKeyExt` which expects non-null.
- **Impact:** NPE on every single keystroke while WebView keyboard panel is visible.
- **Fix:** `val ic = ... ?: return`.

#### UI-C6: DecryptCaptureState Race Condition — Double Callback

- **File:** `app/.../core/DecryptCaptureState.kt`, lines 29-49
- **Description:** `onTextCaptured` and `recipientName` are not `@Volatile`. No synchronization. Two concurrent `deliverText` calls can both invoke the callback. `recipientName` is cleared before the callback runs.
- **Impact:** Double decrypt, decrypt with wrong recipient, or crash from destroyed service context.
- **Fix:** Make all fields `@Volatile`; add `synchronized(this)` blocks; capture `recipientName` before clearing.

### 1.4 Accessibility Service

#### A11Y-C1: Banner Cancel Button Unreachable

- **File:** `app/.../services/DecryptAccessibilityService.kt`, lines 94-128
- **Description:** The banner is added first, then the full-screen touch overlay is added on top. The overlay consumes all touches (`return true`). The cancel button is completely buried.
- **Impact:** Users have zero way to cancel capture mode. Any tap triggers unintended text extraction.
- **Fix:** Add a cancel button directly on the touch overlay, or detect taps in the cancel zone and call `stopCapture()`.

#### A11Y-C2: Massive AccessibilityNodeInfo Leak in 7 Methods

- **File:** `app/.../services/DecryptAccessibilityService.kt`, lines 196-200, 219-240, 253-270, 288-307, 318-330, 345-372, 447-455
- **Description:** Every `node.getChild(i)` and `node.parent` returns a new `AccessibilityNodeInfo` that must be recycled. None of the traversal methods recycle intermediate nodes. A single capture traverses hundreds of nodes.
- **Impact:** Escalating Binder memory consumption, `TransactionTooLargeException`, OOM on repeated use.
- **Fix:** Wrap every `getChild()`/`getParent()` in try-finally with `safeRecycle()`.

#### A11Y-C3: WindowManager Crashes from Wrong Thread

- **File:** `app/.../core/DecryptCaptureState.kt`, lines 36-41; `app/.../services/DecryptAccessibilityService.kt`, lines 131-137
- **Description:** `stopCapture()` and `deliverText()` call `removeAllOverlays()` which calls `WindowManager.removeView()`. These can be called from any thread (e.g., coroutine callback). `removeView` must be called on the main thread.
- **Impact:** `CalledFromWrongThreadException` crash.
- **Fix:** Post all view operations through `mainHandler`.

#### A11Y-C4: No try-catch Around WindowManager.addView

- **File:** `app/.../services/DecryptAccessibilityService.kt`, lines 127, 405, 497
- **Description:** `addView` can throw `BadTokenException`, `IllegalStateException` (already attached), or `InvalidDisplayException`. If the overlay `addView` throws, the banner remains with no way to dismiss it.
- **Impact:** Unrecoverable crash or orphaned overlay stuck on screen.
- **Fix:** Wrap every `addView` in try-catch; roll back state on failure.

### 1.5 Compression

#### CMP-C1: ESCAPE_SYMBOL Missing from Frequency Table

- **File:** `app/.../compression/custom/TextCompressor.kt`, line 74; `app/.../compression/custom/ArithmeticCoder.kt`, lines 36-37
- **Description:** `ESCAPE_SYMBOL = 0` is added to `idToWord` but never guaranteed to exist in `wordFrequencies`. Any out-of-vocabulary word triggers `encode()` which throws `IllegalArgumentException("Unknown symbol: 0")`.
- **Impact:** Any message containing a proper noun, typo, slang, non-English word, or emoji crashes. Falls through to broken raw fallback.
- **Fix:** Insert `wordFrequencies[ESCAPE_SYMBOL] = 1` if missing.

#### CMP-C2: Raw Fallback Indistinguishable from Compressed Data

- **File:** `app/.../compression/CompressionService.kt`, lines 28-32, 41-46
- **Description:** When `compress()` fails, it returns `text.toByteArray(UTF_8)` with no framing prefix. `decompress()` tries to parse these raw bytes as compressed, reads garbage header, and returns empty string.
- **Impact:** Every message that triggers the compression fallback is permanently lost on decompression. Silent data loss.
- **Fix:** Add a 1-byte magic prefix (0x01 = compressed, 0x00 = raw).

#### CMP-C3: Long Overflow in Arithmetic Coding

- **File:** `app/.../compression/custom/ArithmeticCoder.kt`, lines 43-44, 123, 140-141
- **Description:** `rangeSize * totalFreq` can exceed `Long.MAX_VALUE` if `totalFreq > 2^31`. Signed Long overflow corrupts range computation.
- **Impact:** Silently wrong compressed output that decompresses to garbage.
- **Fix:** Normalize frequencies so `totalFreq < Int.MAX_VALUE`. Add validation check.

#### CMP-C4: Tokenizer Destroys Case

- **File:** `app/.../compression/custom/TextCompressor.kt`, line 23
- **Description:** `text.lowercase()` discards all case. "Hello" becomes "hello" after round-trip.
- **Impact:** Every message permanently lowercased.
- **Fix:** Remove `.lowercase()` and retrain vocab, or store a case bitmask.

#### CMP-C5: Tokenizer Destroys Whitespace

- **File:** `app/.../compression/custom/TextCompressor.kt`, lines 19-24, 185-195
- **Description:** Regex skips all whitespace. Reconstruction uses heuristic single-space insertion. Multiple spaces, tabs, newlines destroyed.
- **Impact:** Multiline and formatted messages irreversibly flattened.
- **Fix:** Encode whitespace as explicit tokens.

#### CMP-C6: Emoji and Supplementary Unicode Corrupted

- **File:** `app/.../compression/custom/TextCompressor.kt`, lines 19-24
- **Description:** Regex operates on UTF-16 code units. Supplementary characters (all emoji) are split into lone surrogates, each producing U+FFFD replacement character.
- **Impact:** Every emoji in every message corrupted to `��`.
- **Fix:** Use code-point-aware tokenizer.

### 1.6 Network / Config

#### NET-C1: Hardcoded Plaintext HTTP URL for Secure API

- **File:** `app/.../di/NetworkModule.kt`, line 33
- **Description:** `SECURE_API_BASE_URL = "http://10.0.2.2:8000/"`. Auth tokens, passwords, and all data transmitted in cleartext.
- **Impact:** Complete credential and data exposure on any network.
- **Fix:** Use `BuildConfig` fields with HTTPS for release builds.

#### NET-C2: Second Hardcoded HTTP URL (BackendApiService)

- **File:** `app/.../data/remote/BackendApiService.kt`, line 30
- **Description:** `BASE_URL = "http://10.0.2.2:5000/"` in a companion-object factory that bypasses Hilt DI entirely. No auth interceptor, no token refresh.
- **Impact:** Full data exposure; unauthenticated requests.
- **Fix:** Wire through Hilt/NetworkModule with HTTPS.

#### NET-C3: BODY-Level Logging Ships in Release (BackendApiService)

- **File:** `app/.../data/remote/BackendApiService.kt`, lines 33-35
- **Description:** `HttpLoggingInterceptor.Level.BODY` logs full request/response bodies to Logcat unconditionally.
- **Impact:** All encrypted content exposed in device logs.
- **Fix:** Gate behind `BuildConfig.DEBUG`.

#### NET-C4: BODY-Level Logging Ships in Release (ApiService)

- **File:** `app/.../data/remote/ApiService.kt`, lines 30-32
- **Description:** Same as NET-C3 in the generic ApiService factory.
- **Impact:** All payloads visible in Logcat.
- **Fix:** Gate behind `BuildConfig.DEBUG`.

#### NET-C5: Chucker Debug Interceptor Active in Production

- **File:** `app/.../data/remote/ApiService.kt`, lines 35-51
- **Description:** Chucker records all HTTP traffic to an internal DB and shows a notification. Not gated behind `DEBUG`.
- **Impact:** User-visible notification exposes debug internals; full traffic browsable on device.
- **Fix:** Use `debugImplementation` dependency or `ChuckerInterceptor.NO_OP` for release.

#### NET-C6: Network Security Config Permits Cleartext

- **File:** `app/src/main/res/xml/network_security_config.xml`, lines 2-8
- **Description:** Cleartext allowed for localhost domains. No `<base-config cleartextTrafficPermitted="false">`. No certificate pinning.
- **Impact:** No defense-in-depth against MITM; cleartext permitted if URLs change.
- **Fix:** Add explicit `<base-config cleartextTrafficPermitted="false">`, move localhost exceptions to `debug/res/xml/` overlay, add certificate pinning for production.

### 1.7 Server

#### SRV-C1: Counter Increment Race Condition [DONE]

- **File:** `Secure-application/Server/app/routes/sessions.py`, lines 295-327
- **Description:** `session.last_counter += 1` is a read-modify-write without database locking. Two concurrent requests get the same counter.
- **Impact:** ChaCha20 nonce reuse = XOR of plaintexts leaked. Complete confidentiality compromise.
- **Fix:** Use `UPDATE ... SET last_counter = last_counter + 1 RETURNING last_counter` or `SELECT ... FOR UPDATE`.
- **Status:** Fixed on March 23, 2026 in `Secure-application/Server/app/routes/sessions.py` with an atomic counter update.

#### SRV-C2: Fernet Key Regenerated on Every Server Restart

- **File:** `Secure-application/Server/app/services/obfuscation.py`, lines 33-41
- **Description:** When `seed_encryption_key` is the default or invalid, falls back to `Fernet.generate_key()` — a new random key each restart. All encrypted seeds become permanently undecryptable.
- **Impact:** All active sessions silently bricked after any server restart.
- **Fix:** Generate a proper Fernet key once; fail loudly at startup if invalid.

#### SRV-C3: Default JWT Secret = "change-this-in-production"

- **File:** `Secure-application/Server/config.py`, line 24
- **Description:** JWT signing uses a publicly known default. If `.env` is missing, all tokens are forgeable.
- **Impact:** Complete authentication bypass.
- **Fix:** Remove default; make it a required setting that fails at startup.

#### SRV-C4: CORS Allows All Origins with Credentials

- **File:** `Secure-application/Server/main.py`, lines 22-28
- **Description:** `allow_origins=["*"]` with `allow_credentials=True`.
- **Impact:** CSRF-like attacks from any website against authenticated users.
- **Fix:** Restrict to specific origins.

#### SRV-C5: Logout Is a No-Op [DONE]

- **File:** `Secure-application/Server/app/routes/auth.py`, lines 229-234
- **Description:** `/logout` returns `{"message": "success"}` but performs no server-side action. No token blacklist.
- **Impact:** Stolen tokens remain valid for up to 30 days (refresh token lifetime).
- **Fix:** Implement token blacklist or server-side session tracking.
- **Status:** Fixed on March 23, 2026 in `Secure-application/Server/app/routes/auth.py` by invalidating tokens and deactivating sessions on logout.

---

## 2. HIGH Issues

### 2.1 E2EE / Crypto

| ID | File | Lines | Issue |
|----|------|-------|-------|
| E2EE-H1 | `E2EEService.kt` | 178-184 | Static message key per session — all security relies on 96-bit random nonce. Birthday bound risk at scale. |
| E2EE-H2 | `E2EEService.kt` | 86-217 | No input validation on key sizes in most public functions. Truncated keys silently reduce security. |
| E2EE-H3 | `E2EEService.kt`, `E2EEModels.kt` | throughout | Private keys and intermediaries never zeroed from memory. Exploitable via memory dump. |
| E2EE-H4 | `E2EEService.kt` | 322-336 | 16-bit counter limit (65,536). No rekeying mechanism. Counter exhaustion = nonce reuse or crash. |

### 2.2 Key Storage / Auth

| ID | File | Lines | Issue |
|----|------|-------|-------|
| KS-H1 | `SecureKeyStore.kt` | 52-56 | `activeUserPrefix()` throws unchecked `IllegalStateException` if active user not set. Any early access = crash. |
| KS-H2 | `SecureKeyStore.kt` | 42-61 | TOCTOU race on active user. No synchronization. Cross-user key leakage possible. |
| KS-H3 | `SecureKeyStore.kt` | all writes | `apply()` used for crypto key writes. Process kill = silent key loss. Use `commit()`. |
| KS-H4 | `AuthTokenManager.kt` | 56 | `isLoggedIn()` returns true for empty-string tokens. |
| KS-H5 | Both | manifest | `allowBackup="true"` with empty rules. EncryptedSharedPreferences files backed up; restore on new device = crash loop (no Keystore). |

### 2.3 Repository / Integration

| ID | File | Lines | Issue |
|----|------|-------|-------|
| REPO-H1 | `SecureMessagingRepository.kt` | 197-203 | Responder sends bogus ephemeral key to server. If server updates it, initiator's X3DH breaks silently. |
| REPO-H2 | `SecureMessagingRepository.kt` | 360 | Plaintext logged to Logcat: `"success plaintext=${plaintext.take(50)}"`. Negates E2EE. |
| REPO-H3 | `SecureMessagingRepository.kt` | 276-277, 355 | No counter replay detection. Client blindly trusts server counter. Duplicate = nonce reuse. |
| REPO-H4 | `SecureMessagingRepository.kt` | multiple | Shared secrets never zeroed from memory after use. |
| REPO-H5 | `SecureMessagingRepository.kt` | 72-100 | Partial state on registration failure: tokens saved but key upload may fail. App appears logged in with no E2EE keys. [DONE] |
| REPO-H6 | `SecureMessagingRepository.kt` | 142-150 | Logout doesn't invalidate server tokens or deactivate sessions. Tokens valid up to 24h post-logout. [DONE] |
| REPO-H7 | `SecureMessagingRepository.kt` | 178-248 | No synchronization on concurrent `createSession()`. Race can derive different shared secrets. [DONE] |
| REPO-H8 | `SecureMessagingRepository.kt` | 346-349 | `decryptMessage` requires network call to find session. No offline decryption. |
| REPO-H9 | `SecureMessagingRepository.kt` | multiple | Sensitive metadata in logs: session IDs, usernames, counter values, payload sizes. |

### 2.4 Network

| ID | File | Lines | Issue |
|----|------|-------|-------|
| NET-H1 | `NetworkModule.kt` | all clients | No certificate pinning for any endpoint. MITM with rogue CA can intercept HTTPS traffic. |
| NET-H2 | `NetworkModule.kt` | 55-57, 104-106 | HEADERS-level logging leaks auth tokens to Logcat. |
| NET-H3 | `AndroidManifest.xml` | 11 | `allowBackup="true"` with empty backup rules. All app data extractable via ADB. |
| NET-H4 | `build.gradle.kts` | 76 | `isMinifyEnabled = false` for release. Full class/method names, hardcoded URLs, decompilable code. |
| NET-H5 | `BackendApiService.kt` | 29-52 | Duplicate networking stack bypasses DI. No auth interceptor, no connection reuse. |

### 2.5 Token Refresh

| ID | File | Lines | Issue |
|----|------|-------|-------|
| TOK-H1 | `TokenRefreshAuthenticator.kt` | 29-54 | Concurrent 401s race: both read stale refresh token, first succeeds, second fails and calls `clearAll()` — spurious logout. [DONE] |
| TOK-H2 | `TokenRefreshAuthenticator.kt` | 38 | `runBlocking` on OkHttp dispatcher thread. If refresh client shares same dispatcher, thread pool can deadlock under load. |

### 2.6 UI / Keyboard

| ID | File | Lines | Issue |
|----|------|-------|-------|
| UI-H1 | `KeyboardIME.kt` | 71-76 | `ThemeType.valueOf()` on corrupted preference throws uncaught `IllegalArgumentException`. Keyboard crashes on startup. |
| UI-H2 | `KeyboardIME.kt` | 400-415 | `onKey` creates 3 InputConnection objects on every keystroke. `onCreateInputConnection(EditorInfo())` loses input type info. |
| UI-H3 | `SecureMessagingKeyboard.kt` | 212, 252 | `GlobalScope` in View. Coroutine outlives view lifecycle. UI updates on detached hierarchy. |
| UI-H4 | `SecureMessagingKeyboard.kt` | 225-235 | Search result text color set to red on error but never reset on success. |
| UI-H5 | `KeyboardUtil.kt` | 49 | `sortedBy { getStateToggle(it.id) }` puts disabled items first (false < true). |
| UI-H6 | `KeyboardIME.kt` | 226-235 | `menuKeyboard()` called 3-4 times per `setupFeatureKeyboard()`. Redundant SharedPrefs I/O on main thread. |
| UI-H7 | `KeyboardIME.kt` | 487-519 | Encrypt can proceed with stale/expired session ID from SharedPreferences. No freshness check. [DONE in current `Secure-Keyboard-v2` implementation] |
| UI-H8 | `SecureAuthActivity.kt` | 49 | Password `.trim()` silently removes leading/trailing whitespace. Users with space-containing passwords locked out. |
| UI-H9 | `SecureTextActionActivity.kt` | 177 | `repo.isLoggedIn()` unguarded — crashes on corrupted EncryptedSharedPreferences. |
| UI-H10 | `KeyboardIME.kt` | 497-519 | `currentInputConnection` changes between capture and async callback. Encrypted text committed to wrong field. |

### 2.7 Accessibility Service

| ID | File | Lines | Issue |
|----|------|-------|-------|
| A11Y-H1 | `DecryptCaptureState.kt` | 29-49 | Non-atomic compound state updates. Only `isCapturing` is `@Volatile`. |
| A11Y-H2 | `DecryptCaptureState.kt` | 43-49 | `recipientName` cleared BEFORE callback invoked. Callback gets null. |
| A11Y-H3 | `DecryptAccessibilityService.kt` | 56, 95-97 | Stale `snapshotRegions` after device rotation. Bounds reference old coordinate system. |
| A11Y-H4 | `accessibility_service_config.xml` | 3 | `typeAllMask` receives ALL events but ignores them all. Massive battery drain and IPC waste. |
| A11Y-H5 | `DecryptAccessibilityService.kt` | 56, 95 | `snapshotRegions` retains captured message text in memory after capture ends. |

### 2.8 Compression

| ID | File | Lines | Issue |
|----|------|-------|-------|
| CMP-H1 | `CompressionService.kt` | 11-18 | Vocab load failure is silent and permanent. `lazy` caches the broken state forever. |
| CMP-H2 | `ArithmeticCoder.kt` | 98, 121, 127-133 | Decompression bomb: 3-byte `numSymbols` up to 16M; each decoded via O(n) linear scan of 16K map. |
| CMP-H3 | `TextCompressor.kt` | 115-126 | 3-byte header fields overflow silently for large inputs. |
| CMP-H4 | `TextCompressor.kt` | 106-108 | Unknown words > 255 bytes truncated mid-UTF-8 sequence. Produces invalid UTF-8. |
| CMP-H5 | `TextCompressor.kt` | 9, 46-47 | Vocab ID 0 collides with ESCAPE_SYMBOL. Most common word decompresses to `<UNK>`. |

### 2.9 Server

| ID | File | Lines | Issue |
|----|------|-------|-------|
| SRV-H1 | `obfuscation.py` (routes) | 140-219 | `ac_token_count` metadata discarded. Stego deobfuscation sends `None` for token count. |
| SRV-H2 | `auth.py` (routes) | 183-226 | Refresh tokens not invalidated on use. Old token replayable for 30 days. [DONE] |
| SRV-H3 | `auth.py` (routes) | all endpoints | No rate limiting on auth. Unlimited brute force and credential stuffing. |
| SRV-H4 | `sessions.py` | 147 | Ephemeral key persisted forever instead of deleted after responder retrieves it. [DONE] |
| SRV-H5 | `e2ee.py` | 264-296 | Server-side X3DH also missing identity key binding. Same weakness as E2EE-C1. |
| SRV-H6 | multiple routes | varies | Error messages leak internal state: `f"Invalid key format: {str(e)}"`. |
| SRV-H7 | `obfuscation.py` (service) | 120-146, 207-231 | Synchronous `requests.post()` blocks async event loop. 180s timeout = total server stall. |

---

## 3. MEDIUM Issues

### 3.1 E2EE

| ID | File | Lines | Issue |
|----|------|-------|-------|
| E2EE-M1 | `E2EEService.kt` | 97-106 | `ed25519Verify` catches all exceptions as `false`. Bugs silently become "invalid signature". |
| E2EE-M2 | `E2EEService.kt` | 277-284 | No AAD in AEAD encryption. No binding to sender/recipient/sequence. Replay possible. |
| E2EE-M3 | `E2EEService.kt` | 295-306 | `processBytes` exception not caught; only `doFinal` is wrapped. |
| E2EE-M4 | `E2EEModels.kt` | 15-21 | `equals()` ignores private keys. Collection/deduplication bugs possible. |
| E2EE-M5 | `E2EEModels.kt` | 11-36 | Data classes expose secrets via `copy()`, destructuring, serialization. |

### 3.2 Key Storage / Auth

| ID | File | Lines | Issue |
|----|------|-------|-------|
| KS-M1 | `SecureKeyStore.kt` | 42 | No `userId` validation. Crafted IDs can cause key namespace collision. |
| KS-M2 | `SecureKeyStore.kt` | 115-146 | No `sessionId` validation. Same namespace collision risk. |
| KS-M3 | `SecureKeyStore.kt` | 158 | `prefs.all` decrypts everything. O(n) on all entries. ANR risk on main thread. |
| KS-M4 | `SecureKeyStore.kt` | 109 | `hasSignedPreKey()` checks 1 of 4 required fields. Partial writes appear complete. |
| KS-M5 | `SecureKeyStore.kt` | 74-187 | No zeroization of key material returned to callers. |
| KS-M6 | `SecureKeyStore.kt` | 75-186 | `Base64.decode()` can throw on corrupted data. None of the getters catch it. |
| KS-M7 | `AuthTokenManager.kt` | 71-72 | No clock-skew tolerance in `isAccessTokenExpired()`. Fast clocks = constant refresh. |
| KS-M8 | `AuthTokenManager.kt` | 66-70 | Regex-based JWT parsing; fails on float `exp`, nested structures. |
| KS-M9 | `AuthTokenManager.kt` | 38 | `apply()` for token writes. Process kill = lost tokens. |
| KS-M10 | `AuthTokenManager.kt` | 56, 63-76 | No thread safety on read-then-act token patterns. `clearAll()` from another thread = NPE. |
| KS-M11 | `AuthTokenManager.kt` | 34-39 | Refresh-token rotation write loss = permanent lockout. |

### 3.3 Repository / Integration

| ID | File | Lines | Issue |
|----|------|-------|-------|
| REPO-M1 | `SecureMessagingRepository.kt` | 347-349 | `firstOrNull` ambiguous: multiple active sessions with same peer. Wrong key used. [DONE] |
| REPO-M2 | `SecureMessagingRepository.kt` | 293-343 | Stego encode/decode fallback paths incompatible. Modal-encoded text can't be server-decoded. |
| REPO-M3 | `SecureMessagingRepository.kt` | 73 | Hardcoded `@example.com` email for registration. |
| REPO-M4 | `SecureMessagingRepository.kt` | 462-466 | Unknown payload flags silently treated as raw UTF-8. Version mismatch = garbled messages. |
| REPO-M5 | `SecureMessagingRepository.kt` | 277 | 16-bit counter limits sessions to 65,536 messages. No auto-rekeying. |
| REPO-M6 | `SecureMessagingRepository.kt` | 276-310 | Counter consumed on server even if send fails. Accelerated exhaustion. |

### 3.4 Network

| ID | File | Lines | Issue |
|----|------|-------|-------|
| NET-M1 | `NetworkModule.kt` | all clients | No retry policy or exponential backoff. Modal cold-start failures = immediate user error. |
| NET-M2 | `NetworkModule.kt` | all clients | Three separate connection pools (15 idle connections total). |
| NET-M3 | `TokenRefreshAuthenticator.kt` | 49 | All exceptions silently swallowed. Impossible to diagnose logout causes. |
| NET-M4 | `TokenRefreshAuthenticator.kt` | 49 | Catches bare `Exception` including `CancellationException`. Breaks structured concurrency. |
| NET-M5 | `AndroidManifest.xml` | 41-51 | `SecureTextActionActivity` exported; no input size limit. Malicious apps can send huge text. |
| NET-M6 | `build.gradle.kts` | 102-106 | Lint disabled for release: `checkReleaseBuilds = false`, `abortOnError = false`. |
| NET-M7 | `AuthInterceptor.kt` | 20 | `path.contains(...)` matching too broad. Future endpoints with auth substrings skip auth. |
| NET-M8 | `TokenRefreshAuthenticator.kt` | 51 | `clearAll()` removes userId/username. User doesn't know which account was logged out. |

### 3.5 UI / Keyboard

| ID | File | Lines | Issue |
|----|------|-------|-------|
| UI-M1 | `KeyboardIME.kt` | 583 | Logs first 100 chars of ciphertext. |
| UI-M2 | `KeyboardIME.kt` | 529, 605-606 | Error messages leak exception details to user. |
| UI-M3 | `SecureMessagingKeyboard.kt` | 47-57 | `_repo` lazy init not thread-safe. Double-init or NPE under race. |
| UI-M4 | `KeyboardIME.kt` | 359-365 | No double-click protection on encrypt/decrypt buttons. |
| UI-M5 | `KeyboardIME.kt` | 107-119 | `initCurrentInputConnection` passes null IC to all sub-keyboards. |
| UI-M6 | `SecureTextActionActivity.kt` | 304 | Clipboard label "Encrypted" is metadata leak. Use generic label. |
| UI-M7 | `SecureTextActionActivity.kt` | 50 | No size limit on PROCESS_TEXT input. OOM vector. |
| UI-M8 | `SecureMessagingKeyboard.kt` | 141 | `btnLogout.setOnClickListener` re-set on every `showState()` call. |
| UI-M9 | `SecureMessagingKeyboard.kt` | 291 | `simplifyError` says "Clear DB" — meaningless to users. |
| UI-M10 | `SecureTextActionActivity.kt`, `SecureAuthActivity.kt` | 59-78, 177 | Silent encrypt/decrypt bypasses session freshness check. [DONE in current `Secure-Keyboard-v2` implementation] |
| UI-M11 | `DecryptCaptureState.kt` | 27 | Strong reference to `AccessibilityService` in singleton. Service leaked if destroyed. |

### 3.6 Accessibility Service

| ID | File | Lines | Issue |
|----|------|-------|-------|
| A11Y-M1 | `overlay_message_picker.xml` | 20-23 | ScrollView `height=0dp` + `weight=1` inside `WRAP_CONTENT` parent. May collapse to 0 height. |
| A11Y-M2 | `DecryptAccessibilityService.kt` | 495 | Picker at `Gravity.BOTTOM` overlaps navigation bar / gesture area. |
| A11Y-M3 | `DecryptAccessibilityService.kt` | 396-403 | Banner at `Gravity.TOP` overlaps status bar / notch. |
| A11Y-M4 | `DecryptAccessibilityService.kt` | 154, 335, 420 | `rootInActiveWindow` returns wrong window in split-screen. |
| A11Y-M5 | `DecryptAccessibilityService.kt` | 428-498 | Unlimited picker candidates. Long conversations = hundreds of TextViews = OOM. |
| A11Y-M6 | `DecryptAccessibilityService.kt` | 191-203 | `findNodeAtCoords` has no depth limit. Deep WebView trees = StackOverflow. |
| A11Y-M7 | `DecryptAccessibilityService.kt` | 94-128 | No timeout on capture overlay. Combined with unreachable cancel = device appears frozen. |
| A11Y-M8 | `DecryptCaptureState.kt` | 33 | Rapid `startCapture` calls leak overlays via race condition. |

### 3.7 Compression

| ID | File | Lines | Issue |
|----|------|-------|-------|
| CMP-M1 | `TextCompressor.kt` | 186-195 | Space reconstruction heuristic broken for quotes. Opening quotes joined to previous word. |
| CMP-M2 | `ArithmeticCoder.kt` | 126-135 | Decode silently truncates on lookup failure (breaks instead of throwing). |
| CMP-M3 | `TextCompressor.kt` | 31-32 | Custom JSON parser fails on nested braces. |
| CMP-M4 | `TextCompressor.kt` | 82-84 | `unescapeJson` only handles `\"` and `\\`. Missing `\n`, `\t`, `\uXXXX`. |
| CMP-M5 | `ArithmeticCoder.kt` | 127-133 | O(n*m) decode from linear scan. 100-word message = ~800K map lookups. |
| CMP-M6 | `ArithmeticCoder.kt` | 33, 100 | Bits stored as boxed Integers. 80K bits = 1.3MB heap for 10KB output. |

### 3.8 Server

| ID | File | Lines | Issue |
|----|------|-------|-------|
| SRV-M1 | `auth.py` (middleware) vs `config.py` | 23, 26 | Token expiration config mismatch: config says 30min, middleware hardcodes 24h. |
| SRV-M2 | `database.py` | 47-55 | `QueuePool` used with SQLite. Concurrent writes = "database is locked". |
| SRV-M3 | `database.py` | 58-64 | Global SQLite pragma listener fires for all engines. |
| SRV-M4 | multiple routes | varies | User enumeration via different error messages for existing vs. non-existing users. |
| SRV-M5 | `obfuscation.py` (routes) | 38-56 | No input size limits on obfuscation payloads. DoS vector. |
| SRV-M6 | `sessions.py` | 235-263, 396-421 | Deactivated sessions still readable via GET endpoints. |
| SRV-M7 | `e2ee.py` | 363-397 | No integrity protection on bare ChaCha20 (server-side too). |
| SRV-M8 | `sessions.py` | 117-135 | New ephemeral key silently discarded for existing sessions. No indication to client. |
| SRV-M9 | `obfuscation.py` (service) | 56-63 | Only 5 hardcoded stego seeds. Traffic analysis trivial. |

---

## 4. LOW Issues

### 4.1 E2EE

| ID | File | Lines | Issue |
|----|------|-------|-------|
| E2EE-L1 | `E2EEModels.kt` | 43-48 | `X3DHResult.equals` ignores ephemeral key. |
| E2EE-L2 | `E2EEService.kt` | 223-227 | Base64 interop fragility with Python server (NO_WRAP vs URL_SAFE). |
| E2EE-L3 | `E2EEService.kt` | 37 | Singleton `SecureRandom` contention under concurrency. |

### 4.2 Key Storage / Auth

| ID | File | Lines | Issue |
|----|------|-------|-------|
| KS-L1 | `SecureKeyStore.kt` | 23 | Not a singleton. Multiple instances can cause inconsistent state. |
| KS-L2 | `SecureKeyStore.kt` | 175-177 | `clearAll()` leaves half-state (no active user but scoped methods still callable). |
| KS-L3 | `AuthTokenManager.kt` | 68 | `Base64.URL_SAFE` should also specify `NO_PADDING` for strict JWT decoding. |
| KS-L4 | `AuthTokenManager.kt` | 34-52 | `saveTokens`/`saveUserInfo` are independent. Crash between them = partial state. |
| KS-L5 | Both | 16-17 | Shared MasterKey alias = correlated failure. One corruption takes out both stores. |

### 4.3 UI / Keyboard

| ID | File | Lines | Issue |
|----|------|-------|-------|
| UI-L1 | `KeyboardIME.kt` | 584 | Toast shows ciphertext length. Minor metadata leak. |
| UI-L2 | `SecureTextActionActivity.kt` | multiple | Hardcoded emoji strings instead of string resources. Breaks localization. |
| UI-L3 | `SecureMessagingKeyboard.kt` | varies | No `contentDescription` on search/clear/back buttons. Screen reader announces "unlabeled button". |
| UI-L4 | 3 files | varies | `simplifyError` duplicated in 3 files with different error coverage. |
| UI-L5 | `SecureMessagingKeyboard.kt` | layout | Username EditText may leak to third-party keyboard dictionaries. Set `textNoSuggestions`. |
| UI-L6 | `SecureMessagingKeyboard.kt` | 199 | No debounce on search button. Rapid taps fire concurrent API calls. |
| UI-L7 | `KeyboardIME.kt` | 298-301 | WEB feature doesn't call `hideMainKeyboard()`. Main keyboard visible behind WebView. |
| UI-L8 | `SecureAuthActivity.kt` | 85-88 | Password remains visible after login. Not cleared in `refreshUI()`. |

### 4.4 Accessibility Service

| ID | File | Lines | Issue |
|----|------|-------|-------|
| A11Y-L1 | `accessibility_service_config.xml` | 5 | `flagRequestEnhancedWebAccessibility` deprecated since API 26. |
| A11Y-L2 | `DecryptAccessibilityService.kt` | 122 | `FLAG_FULLSCREEN` deprecated since API 30. |
| A11Y-L3 | overlay layouts | varies | Hardcoded colors ignore high-contrast/accessibility themes. |
| A11Y-L4 | `DecryptAccessibilityService.kt` | 465-479 | Picker TextViews lack accessibility metadata for TalkBack. |
| A11Y-L5 | `overlay_message_picker.xml` | 8 | `maxHeight` on LinearLayout inconsistently honored across OEMs. |
| A11Y-L6 | `DecryptAccessibilityService.kt` | 517-520 | `safeRecycle` silently swallows all exceptions. Hides bugs. |
| A11Y-L7 | `DecryptAccessibilityService.kt` | 156, 183, etc. | Toast suppressed on some OEM ROMs (MIUI, EMUI) for background services. |

### 4.5 Compression

| ID | File | Lines | Issue |
|----|------|-------|-------|
| CMP-L1 | `CompressionService.kt` | 52-57 | `getCompressionRatio` returns 1.0 when compressedSize=0. Misleading. |
| CMP-L2 | `TextCompressor.kt` | 141, 151 | Corrupted data returns `""` instead of signaling error. |
| CMP-L3 | `TextCompressor.kt` | 22 | Non-ASCII word characters (`\\w`) not grouped into words. |

### 4.6 Server

| ID | File | Lines | Issue |
|----|------|-------|-------|
| SRV-L1 | `keys.py` | 196 | `keys_uploaded_at` returns `last_seen_at` instead of actual upload time. |
| SRV-L2 | `keys.py` | 86, 245 | `__import__('base64')` instead of normal import. |
| SRV-L3 | `sessions.py` | 197-209 | N+1 query in session listing. 100 sessions = 200 extra queries. |
| SRV-L4 | `main.py` | 38 | Deprecated `@app.on_event("startup")`. |
| SRV-L5 | `main.py` | 66-73 | Health endpoint leaks `debug_mode` and `obfuscation_version`. |
| SRV-L6 | `database.py` | 107-113 | No Alembic migration framework. `create_all()` can't modify existing tables. |
| SRV-L7 | `auth.py` (middleware) | 140-167 | Redundant `is_active` check in `get_current_active_user`. |

---

## 5. Recommended Priority Actions

Ordered by impact-to-effort ratio. Addressing these 10 items resolves the majority of CRITICAL and HIGH findings.

### 1. Gate ALL Logging Behind `BuildConfig.DEBUG`

**Resolves:** NET-C3, NET-C4, NET-C5, NET-H2, REPO-H2, REPO-H9, UI-M1
**Effort:** Low (find-replace pattern)
**Action:** Add `if (BuildConfig.DEBUG)` guard to every `Log.d`, `Log.e`, `Log.w` that contains sensitive data. Set `HttpLoggingInterceptor.Level.NONE` for release. Move Chucker to `debugImplementation` dependency.

### 2. Replace GlobalScope with Lifecycle-Scoped Coroutines

**Resolves:** UI-C1, UI-C2, UI-C3, UI-H3
**Effort:** Medium
**Action:** Use `lifecycleScope` in Activities, create `serviceScope` in KeyboardIME cancelled in `onDestroy()`, use `findViewTreeLifecycleOwner()?.lifecycleScope` in Views.

### 3. Switch Bare ChaCha20 to ChaCha20-Poly1305

**Resolves:** E2EE-C3, SRV-M7
**Effort:** Medium (16-byte tag overhead impacts stego bandwidth)
**Action:** Replace `chacha20Encrypt`/`chacha20Decrypt` with `encryptBytes`/`decryptToBytes` in `SecureMessagingRepository`. Accept the tag overhead or add a truncated HMAC.

### 4. Add Keystore Corruption Recovery

**Resolves:** KS-C1, KS-C2, KS-H5
**Effort:** Low
**Action:** Wrap `EncryptedSharedPreferences.create()` in try-catch. On failure, delete corrupted prefs file, retry. Add backup exclusion rules for encrypted prefs files.

### 5. Fix Counter Atomicity on Server

**Resolves:** SRV-C1
**Effort:** Low
**Action:** Replace `session.last_counter += 1; db.commit()` with atomic `UPDATE ... SET last_counter = last_counter + 1 RETURNING last_counter` or `SELECT ... FOR UPDATE`.

### 6. Move URLs to BuildConfig with HTTPS for Release

**Resolves:** NET-C1, NET-C2, NET-C6
**Effort:** Low
**Action:** Add `buildConfigField` in `build.gradle.kts` for debug/release variants. Use HTTPS for production. Remove cleartext exceptions from release `network_security_config.xml`.

### 7. Implement Token Refresh Synchronization

**Resolves:** TOK-H1, TOK-H2
**Effort:** Medium
**Action:** Add `@Synchronized` or `Mutex` around refresh logic. Check if token was already refreshed before calling server. Use `withTimeout` for the `runBlocking` call.

### 8. Add try-catch Around WindowManager Operations

**Resolves:** A11Y-C3, A11Y-C4
**Effort:** Low
**Action:** Wrap every `addView`/`removeView` in try-catch. Post all view operations through `mainHandler`. Roll back state on failure.

### 9. Recycle AccessibilityNodeInfo in Tree Traversals

**Resolves:** A11Y-C2
**Effort:** Medium
**Action:** Create a utility `forEachChild` that wraps `getChild()` in try-finally with `safeRecycle()`. Update all 7 traversal methods.

### 10. Fix Compression or Disable It

**Resolves:** CMP-C1 through CMP-C6, CMP-H1 through CMP-H5
**Effort:** High (if fixing) / Low (if disabling)
**Action:** The compression module has 11 CRITICAL/HIGH issues. For immediate production readiness, disable compression (always use `FLAG_RAW`) and defer the fixes. The module can be re-enabled after rewriting the tokenizer, fixing the arithmetic coder, and adding proper framing.

---

## Appendix: Files Audited

| Component | Files |
|-----------|-------|
| E2EE | `E2EEService.kt`, `E2EEModels.kt` |
| Storage | `SecureKeyStore.kt`, `AuthTokenManager.kt` |
| Repository | `SecureMessagingRepository.kt` |
| Network | `SecureApiService.kt`, `SecureApiDtos.kt`, `AuthInterceptor.kt`, `TokenRefreshAuthenticator.kt`, `NetworkModule.kt`, `BackendApiService.kt`, `ApiService.kt`, `StegoApiService.kt` |
| Config | `network_security_config.xml`, `AndroidManifest.xml`, `build.gradle.kts` |
| UI | `KeyboardIME.kt`, `SecureMessagingKeyboard.kt`, `KeyboardUtil.kt`, `SecureTextActionActivity.kt`, `SecureAuthActivity.kt` |
| Accessibility | `DecryptAccessibilityService.kt`, `DecryptCaptureState.kt`, `overlay_decrypt_capture.xml`, `overlay_message_picker.xml`, `accessibility_service_config.xml` |
| Compression | `CompressionService.kt`, `TextCompressor.kt`, `ArithmeticCoder.kt` |
| Server | `main.py`, `config.py`, `database.py`, `auth.py` (middleware), `auth.py` (routes), `sessions.py`, `keys.py`, `obfuscation.py` (routes), `obfuscation.py` (service), `e2ee.py` |
