# v4.0 E2EE Integration — Changes Summary

## Overview

Aligned the keyboard Android client and secure messaging server with the **v4.0 simplified E2EE flow**. The core change: **metadata-free obfuscation**. Messages no longer carry `🔐session_id|seed_id` metadata — the server resolves sessions from usernames.

---

## Client-Side Changes (Kotlin)

### [SecureApiDtos.kt](file:///d:/Purdue/Research-Assistant/keyboard/keyboard/app/src/main/java/com/frogobox/appkeyboard/data/remote/dto/SecureApiDtos.kt)

- `CreateSessionRequest`: added `ephemeralPublicKey`
- `ObfuscateRequest`: added `peerUsername`
- `ObfuscateResponse`: removed stale `seedId`, `obfuscationVersion`
- `DeobfuscateRequest`: replaced `seedId` with `senderUsername`
- Added `EphemeralKeyResponse` DTO

### [SecureApiService.kt](file:///d:/Purdue/Research-Assistant/keyboard/keyboard/app/src/main/java/com/frogobox/appkeyboard/data/remote/SecureApiService.kt)

- Added `getKeyBundleByUsername(username)` endpoint
- Added `getEphemeralKey(sessionId)` endpoint

### [SecureMessagingRepository.kt](file:///d:/Purdue/Research-Assistant/keyboard/keyboard/app/src/main/java/com/frogobox/appkeyboard/data/repository/SecureMessagingRepository.kt)

- **`createSession`**: X3DH runs before session creation; sends `ephemeralPublicKey` to server
- **`sendMessage(sessionId, peerUsername, plaintext)`**: passes `peerUsername` to obfuscation; returns **only obfuscated text** (no metadata appended)
- **`decryptMessage(obfuscatedText, senderUsername)`**: takes raw obfuscated text + sender username; server resolves session from usernames; finds session via `listSessions` to get shared secret
- **`getOrEstablishSharedSecretForReceive`**: now `suspend` — fetches ephemeral key from server API
- **`SendResult`**: removed `formattedMessage` and `seedId`; only contains `obfuscatedText`
- Removed `METADATA_PREFIX` and `META_SEP` constants

### [SecureMessagingKeyboard.kt](file:///d:/Purdue/Research-Assistant/keyboard/keyboard/app/src/main/java/com/frogobox/appkeyboard/ui/keyboard/securemessaging/SecureMessagingKeyboard.kt)

- **Send flow**: commits only `obfuscatedText` to the host text field (no metadata)
- **Decrypt flow**: reads sender username from new `et_sender_username` input field; validates both fields; passes `(obfuscatedText, senderUsername)` to repository

### [keyboard_secure_messaging.xml](file:///d:/Purdue/Research-Assistant/keyboard/keyboard/app/src/main/res/layout/keyboard_secure_messaging.xml)

- Added `et_sender_username` EditText to decrypt panel ("Sender's username" input)
- Updated hint text to "Paste obfuscated text here..."

---

## Server-Side Changes (Python)

### [obfuscation.py (service)](file:///d:/Purdue/Research-Assistant/keyboard/keyboard/Secure-application/Server/app/services/obfuscation.py)

- **Fernet key fix**: constructor now reads `seed_encryption_key` from settings automatically (was generating a random key on every restart)
- **Deobfuscation fix**: when `obfuscation_data` is empty (`{}`), tries base64 decode first before falling to stego API

### Database

- Reinitialized with v4.0 schema: `chat_sessions` now includes `encrypted_seed` and `initiator_ephemeral_public` columns

---

## Known Issue: One-Way Decryption

> [!CAUTION]
> **Bidirectional decryption is broken.** The E2EE flow works in one direction (e.g., Alice → Bob decrypts successfully) but fails when Bob → Alice tries to decrypt.
>
> **Likely root cause — X3DH shared secret asymmetry:**
>
> - Only the **session initiator** uploads their ephemeral public key to the server
> - The **responder** (receiver of the first message) fetches this ephemeral key via `GET /sessions/{id}/ephemeral-key` and computes the shared secret
> - When the **responder sends back**, the initiator may already have the shared secret cached — but if the responder tries to send _first_ (before receiving), they may not have established the shared secret yet
> - Additionally, X3DH key agreement produces the **same shared secret on both sides only if both sides use the correct DH inputs**. If the role (initiator vs responder) is confused when computing sessions, the derived keys won't match
>
> **Investigation needed:**
>
> 1. Verify that `getOrEstablishSharedSecretForReceive` correctly identifies who is initiator vs responder
> 2. Check that `E2EEService.x3dhRespond()` uses the correct key ordering (IK_sender, SPK_receiver, EK_sender)
> 3. Confirm the shared secret is identical on both devices by logging its hash during debugging
> 4. Check if the counter state is getting confused between the two directions
