---
name: Security Review Document
overview: Create a comprehensive SECURITY_REVIEW.md document at the project root, covering all bugs, security vulnerabilities, edge cases, and critical logic issues found across the entire Secure-Keyboard-v2 codebase and Secure-application backend.
todos:
  - id: write-review
    content: Write the comprehensive SECURITY_REVIEW.md document with all findings organized by severity
    status: pending
isProject: false
---

# Comprehensive Security Review Document

Create `SECURITY_REVIEW.md` at the project root with findings from a full-codebase audit. The document will cover the following sections based on the deep dive already completed:

## Document Structure

### 1. Critical: Unauthenticated Encryption (No MAC)

- The live messaging path in `[SecureMessagingRepository.kt](app/src/main/java/com/frogobox/appkeyboard/data/repository/SecureMessagingRepository.kt)` uses `E2EEService.chacha20Encrypt` / `chacha20Decrypt` -- bare ChaCha20 stream cipher with **no Poly1305 tag or any MAC**
- Ciphertext is malleable: an attacker can flip bits without detection
- The AEAD path (`encryptMessage`/`decryptMessage` with ChaCha20-Poly1305) exists in E2EEService but is **never called** for the actual message flow
- Server-side `e2ee.py` has the same issue

### 2. Critical: Hardcoded and Default Secrets (Server)

- `[Server/config.py](Secure-application/Server/config.py)`: `secret_key = "change-this-in-production"`, `seed_encryption_key = "change-this-in-production"`
- `[Server/app/services/xor_crypto.py](Secure-application/Server/app/services/xor_crypto.py)`: hardcoded `STATIC_XOR_KEY`
- JWT signing uses this default key; any attacker knowing the default can forge tokens

### 3. Critical: Sensitive Data Logging

- `SecureMessagingRepository.kt` logs first 50 chars of **decrypted plaintext**: `"decryptMessage: success plaintext=${plaintext.take(50)}..."`
- `KeyboardIME.kt` logs first 100 chars of ciphertext
- `NetworkModule.kt` logs HTTP headers (including `Authorization: Bearer` tokens)
- `BackendApiService.kt` and `ApiService.kt` use `HttpLoggingInterceptor.Level.BODY` -- full request/response bodies

### 4. High: Session Persistence and Cleanup Bugs

- `secure_active_session` (session_id + recipient_name) stored in **plain SharedPreferences** -- not EncryptedSharedPreferences
- Logout from `SecureAuthActivity` calls `repo.logout()` but does NOT clear `secure_active_session` -- stale session metadata persists
- Only keyboard-panel logout (`SecureMessagingKeyboard`) clears it
- Server session deactivation (`api.deactivateSession()`) is **never called** from the client

### 5. High: No Rate Limiting / Brute Force Protection

- Server has zero rate limiting on any endpoint
- Auth endpoints (register, login, refresh) fully exposed to brute force
- User search endpoint exposed to enumeration

### 6. High: CORS Misconfiguration

- Server: `allow_origins=["*"]` with `allow_credentials=True` -- browsers should reject this combination, but misconfigured clients won't
- No security headers (CSP, HSTS, X-Frame-Options, etc.)

### 7. High: HTTP Cleartext for API Communication

- All API traffic to the secure server uses `http://10.0.2.2:8000/` -- no TLS
- `network_security_config.xml` explicitly allows cleartext for `10.0.2.2`, `localhost`, `127.0.0.1`
- No certificate pinning anywhere
- Only Modal stego endpoints use HTTPS

### 8. Medium: Key Management Weaknesses

- No identity key or signed pre-key rotation
- Shared secrets cached indefinitely with no expiry
- Single signed pre-key (`keyId = 1`) -- never rotated
- `PRNGManager` uses zero salt for HKDF when IKM may have low entropy
- `CryptoService` derives keys via `SHA-256(passphrase)` instead of PBKDF2/Argon2

### 9. Medium: Clipboard Never Cleared

- Decrypted plaintext copied to clipboard via "Copy" button in result dialog
- Clipboard fallback decrypt reads `primaryClip` but never clears it after use
- `SecureTextActionActivity` writes to clipboard, never clears
- Any app with clipboard access can read decrypted messages

### 10. Medium: No Input Validation Before Decryption

- Captured text from accessibility service or clipboard is passed directly to `decryptMessage()` with no format/length validation
- Arbitrary strings trigger stego decode + crypto operations -- resource waste and potential for crashes
- `SecureTextActionActivity` PROCESS_TEXT handler accepts any text from any app

### 11. Medium: Decompression Bomb Risk

- `TextCompressor` header fields (`num_symbols`, `encoded_len`) use 3 bytes each -- up to ~16M
- No upper bound check; malicious input can cause large memory allocation
- `ArithmeticCoder.decode()` allocates arrays proportional to header values

### 12. Medium: Thread Safety / Race Conditions

- `DecryptCaptureState`: only `isCapturing` is `@Volatile`; `recipientName` and `onTextCaptured` are not
- `secure_active_session` SharedPreferences: no locking; concurrent encrypt/decrypt from different threads could read stale values
- `GlobalScope.launch` used throughout -- no lifecycle-scoped coroutines; potential leaks

### 13. Low: Accessibility Service Over-Capture

- Service can capture any on-screen text, not just encrypted messages
- No encrypted-format check before delivering text to decrypt callback
- `snapshotRegions` (captured screen text) is never explicitly cleared from memory
- `FLAG_SECURE` not used on decrypt result dialog or auth activity -- screenshots not blocked

### 14. Low: Token Handling

- JWT `exp` checked client-side without signature verification (server validates)
- No token revocation mechanism; logout clears local tokens but server-side tokens remain valid until expiry
- No `jti` claim or blocklist for refresh tokens

### 15. Low: Server Error Information Leakage

- `detail=f"...{str(e)}"` in multiple route handlers can expose internal error messages
- `debug=True` mode exposes stack traces to clients
- `reload=settings.debug` enables hot reload in production if misconfigured

### 16. Edge Cases

- Stego round-trip is **not guaranteed**: LLM-based encoding can corrupt bits, making messages unrecoverable
- Compression loses letter case (`text.lowercase()`) and truncates unknown words > 255 bytes
- Server fallback for stego decode only works for server-obfuscated messages, not Modal-encoded ones
- `recipient_name` is used as both "who I'm talking to" (encrypt) and "who sent this" (decrypt) -- semantically confusing and correct only for two-party sessions

## Files Changed

- Create one new file: `SECURITY_REVIEW.md` at the project root

