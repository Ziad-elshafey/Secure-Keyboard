# Project Context — Secure Keyboard with Steganographic Messaging

> **Purpose**: Feed this file to an AI assistant at the start of a session to restore full project context without re-explaining.  
> **Last updated**: February 5, 2026

---

## 1. What This Project Is

An **Android custom keyboard (IME)** that provides:
- **Text compression** (arithmetic coding) to reduce message size
- **End-to-end encryption (E2EE)** so the server never sees plaintext
- **Steganographic obfuscation** so even the ciphertext is hidden inside innocent-looking English text on the server

The keyboard types into any app's text field. When the user "sends" a message, it encrypts locally, sends ciphertext to a FastAPI server, and the server wraps the ciphertext in natural language using an LLM-based steganography API. Recipients retrieve the message, the server un-wraps the stego text back to ciphertext, and the recipient's keyboard decrypts locally.

---

## 2. Repository Structure (Key Directories)

```
keyboard/
├── app/                          # Android app module (the keyboard app)
│   └── src/main/java/com/frogobox/appkeyboard/
│       ├── services/KeyboardIME.kt            # Main IME service (extends BaseKeyboardIME)
│       ├── ui/keyboard/                       # Keyboard panel UIs
│       │   ├── autotext/                      # Auto-text templates panel
│       │   ├── compression/                   # Compression demo panel
│       │   ├── demo/                          # Backend upload demo panel (uses Flask backend)
│       │   ├── securemessaging/               # Offline E2EE encrypt/decrypt panel
│       │   ├── movie/, news/, form/, webview/ # Other feature panels
│       │   └── templatetext/                  # Text templates
│       ├── data/
│       │   ├── remote/
│       │   │   ├── BackendApiService.kt       # Retrofit interface → Flask backend
│       │   │   └── ApiService.kt              # Legacy/generic Retrofit factory (unused)
│       │   └── repository/compression/
│       │       └── custom/
│       │           ├── TextCompressor.kt      # Word-level arithmetic coding compressor
│       │           └── ArithmeticCoder.kt     # 32-bit precision arithmetic coder
│       └── core/CryptoService.kt              # XChaCha20-Poly1305 encryption (PRNG keys)
│
├── frogo-keyboard/               # Library module (base keyboard framework)
│   └── src/main/java/com/frogobox/libkeyboard/
│       └── common/core/BaseKeyboardIME.kt     # Base IME service class
│
├── backend/
│   └── server.py                 # Flask mock server (in-memory, no auth, random decoy text)
│
├── Secure-application/           # FastAPI production server + E2EE + steganography
│   ├── Server/
│   │   ├── main.py               # FastAPI app entry point (port 8000)
│   │   ├── config.py             # Settings (stego API URLs, JWT secrets, DB URL)
│   │   ├── app/
│   │   │   ├── database.py       # SQLAlchemy session (PostgreSQL or SQLite)
│   │   │   ├── models/__init__.py # DB models: User, Conversation, Message, SeedsVault
│   │   │   ├── middleware/auth.py # JWT auth (HS256, access=24h, refresh=30d)
│   │   │   ├── routes/
│   │   │   │   ├── auth.py       # POST /api/auth/register, /login, /refresh, /logout
│   │   │   │   ├── users.py      # GET/PUT /api/users/me, search, etc.
│   │   │   │   ├── keys.py       # POST /api/keys/upload, GET /api/keys/bundle/{id}
│   │   │   │   ├── conversations.py # CRUD /api/conversations
│   │   │   │   └── messages.py   # POST /api/messages/send, GET /inbox, GET /{id}/reveal
│   │   │   └── services/
│   │   │       ├── e2ee.py       # X3DH + ChaCha20-Poly1305 (key gen, exchange, encrypt/decrypt)
│   │   │       └── obfuscation.py # Stego API client (encode/decode via Modal-hosted LLM)
│   │   └── tests/                # Various test files
│   ├── demos/server CLI demos/
│   │   ├── alice.py              # CLI demo: sender (register → keygen → X3DH → send 3 msgs)
│   │   ├── bob.py                # CLI demo: receiver (register → keygen → poll → decrypt)
│   │   ├── e2ee_service.py       # Client-side E2EE library (copy of server's e2ee.py)
│   │   └── config.py             # Demo config (server URL)
│   ├── web-client/               # Browser-based test client (HTML/JS)
│   └── docs/                     # API docs, DB schema, message lifecycle, E2EE guide
│
├── Compression-Algorithm/        # LLM-based compression research (Llama 3.2, ~9 bits/word)
├── kotlin/                       # Standalone Kotlin compression tests
│   ├── TextCompressor.kt         # Kotlin compressor (mirrors Android version)
│   ├── ArithmeticCoder.kt        # Arithmetic coder
│   └── TrainOnDailyDialog.kt     # Vocab training script
├── models/                       # Vocabulary JSON files
│   ├── vocab.json                # General vocab (~16K words)
│   └── standard_english_vocab.json
└── app/schemas/                  # Room DB migration schemas
```

---

## 3. The Full Message Flow (Keyboard → Server → Recipient)

### Sending (Alice's Keyboard)
```
1. Alice types plaintext in any app's text field
2. Keyboard reads text from InputConnection
3. Client: shared_secret = X3DH(alice_identity, bob_prekey_bundle)
4. Client: message_key = HKDF-SHA256(shared_secret)
5. Client: nonce = random(12 bytes)
6. Client: ciphertext = ChaCha20-Poly1305.encrypt(message_key, nonce, plaintext)
7. Client → Server: POST /api/messages/send {conversation_id, ciphertext, nonce, ephemeral_public_key}
8. Server: seed = random prompt (e.g., "The history of art is")
9. Server → Stego API: encode(seed, ciphertext_bits) → natural English text
10. Server: stores obfuscated_text + tokens + encrypted_seed in DB
11. Server → Client: returns {obfuscated_text: "The history of art is a fascinating...", ...}
12. Keyboard replaces input field text with the decoy/obfuscated text
```

### Receiving (Bob's Keyboard)
```
1. Bob: GET /api/messages/inbox → sees list of natural-looking English messages
2. Bob: GET /api/messages/{id}/reveal
3. Server: decrypts seed from seeds_vault, calls Stego API decode → ciphertext bytes
4. Server → Bob: {ciphertext, nonce, ephemeral_public_key}
5. Bob: shared_secret = X3DH_respond(bob_prekey_private, alice_ephemeral_public)
6. Bob: message_key = HKDF-SHA256(shared_secret)
7. Bob: plaintext = ChaCha20-Poly1305.decrypt(message_key, nonce, ciphertext)
8. Plaintext displayed in keyboard UI
```

### What the Server Stores vs. Sees
| Data | Stored? | Server can read? |
|------|---------|-----------------|
| Plaintext | ❌ | ❌ |
| E2EE ciphertext | ❌ (obfuscated) | ❌ (can't decrypt) |
| Obfuscated text | ✅ (looks like English) | ✅ (but it's just cover text) |
| Stego tokens/metadata | ✅ | ✅ |
| Encrypted seed | ✅ | ✅ (can decrypt with Fernet key) |
| E2EE public keys | ✅ | ✅ (public halves only) |
| Private keys / shared secret | ❌ | ❌ |

---

## 4. Server API Reference (Secure-application)

### Auth
| Method | Endpoint | Body | Returns |
|--------|----------|------|---------|
| POST | `/api/auth/register` | `{username, email, password}` | `{user_id, access_token, refresh_token}` |
| POST | `/api/auth/login` | `{username, password}` | `{access_token, refresh_token}` |
| POST | `/api/auth/refresh` | `{refresh_token}` | `{access_token, refresh_token}` |

### E2EE Keys
| Method | Endpoint | Body/Params | Returns |
|--------|----------|-------------|---------|
| POST | `/api/keys/upload` | `{identity_key, signed_prekey, signed_prekey_signature}` (all base64) | `{status}` |
| GET | `/api/keys/bundle/{user_id}` | — | `{identity_key, signed_prekey, signed_prekey_signature}` |

### Conversations
| Method | Endpoint | Body | Returns |
|--------|----------|------|---------|
| POST | `/api/conversations` | `{participant_ids: [uuid], title?}` | `{conversation_id, ...}` |
| GET | `/api/conversations` | — | List of conversations |

### Messages
| Method | Endpoint | Body | Returns |
|--------|----------|------|---------|
| POST | `/api/messages/send` | `{conversation_id, ciphertext, nonce, ephemeral_public_key?}` | `{message_id, obfuscated_text, ...}` |
| GET | `/api/messages/inbox` | `?skip=0&limit=50` | List of obfuscated messages |
| GET | `/api/messages/{id}/reveal` | — | `{ciphertext, nonce, ephemeral_public_key}` |

All authenticated endpoints require `Authorization: Bearer <access_token>` header.

---

## 5. Cryptographic Stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Identity keys | Ed25519 | Signing / identity verification |
| Key exchange | X25519 (X3DH) | Derive shared secret between two parties |
| Key derivation | HKDF-SHA256 | Derive message encryption key from shared secret |
| Message encryption | ChaCha20-Poly1305 (AEAD) | Encrypt/decrypt message content |
| Seed encryption | Fernet (AES-128-CBC + HMAC) | Protect stego seeds at rest on server |
| Steganography | LLM arithmetic coding | Hide ciphertext bits in generated English text |

---

## 6. Android Keyboard Architecture

### IME Class Hierarchy
```
InputMethodService (Android SDK)
  └── BaseKeyboardIME (frogo-keyboard library)
        └── KeyboardIME (app module, @AndroidEntryPoint / Hilt)
```

### How Panels Work
- `KeyboardIME` inflates `KeyboardImeBinding` layout with a header menu + swappable panel views
- Each panel is a separate Compose/View-based UI (e.g., `DemoKeyboard`, `SecureMessagingKeyboard`)
- `KeyboardIME.initView()` passes the current `InputConnection` to each panel
- Menu items in `setupFeatureKeyboard()` toggle panel visibility

### Existing Panels of Interest
| Panel | What it does | Network? |
|-------|-------------|----------|
| `DemoKeyboard` | Encrypts text → uploads to Flask backend → replaces with decoy text | ✅ Flask only |
| `SecureMessagingKeyboard` | PRNG-based E2EE encrypt/decrypt (passphrase-derived keys) | ❌ Offline |
| `CompressionKeyboard` | Compresses text using arithmetic coding | ❌ Offline |

### Existing Network Stack
- **Retrofit 2.9.0** + **OkHttp 4.12.0** + **Gson**
- `BackendApiService.kt`: interface with `POST /api/upload`, `POST /api/retrieve`, `GET /api/health`
- Currently points to `http://10.0.2.2:5000/` (Flask, emulator localhost)
- No auth headers, no token management

---

## 7. Text Compression (Current State)

### Algorithm
- **Word-level arithmetic coding** with static frequency vocabulary
- Zero-context model (no n-gram dependencies)
- 32-bit precision arithmetic coder
- Unknown words handled via UTF-8 escape mechanism

### Performance
- **~17 bits/word** on average (target: 8-10 bits/word)
- Vocabulary: ~16,384 words trained on DailyDialog dataset
- Theoretical entropy: ~8 bits/word (gap due to zero-context + overhead)
- LLM-based compression baseline: 9 bits/word (Llama 3.2 1B, too heavy for mobile)
- 6-byte fixed header overhead hurts short messages

### Improvement Opportunities (Identified, Not Yet Implemented)
1. **Bigram/trigram context modeling** → could reach 10-12 bits/word
2. **Variable-length header** (varint) → reduce overhead on short messages
3. **BPE/subword tokenization** → better unknown-word handling
4. **Train n-gram frequency tables** on DailyDialog

---

## 8. Current Integration Plan (Keyboard ↔ Secure-Application Server)

### What Needs to Be Built
1. **`SecureApiService.kt`** — Retrofit interface for all Secure-Application endpoints (auth, keys, conversations, messages)
2. **`E2EEService.kt`** — Android-side X3DH + ChaCha20-Poly1305 (mirroring the Python `e2ee_service.py`)
3. **`SecureMessagingDemoKeyboard`** — New keyboard panel with UI for: register/login, start conversation, type-and-send (encrypt → upload → show decoy), receive-and-decrypt (fetch → reveal → decrypt → display)
4. **Auth token management** — JWT storage in EncryptedSharedPreferences + OkHttp interceptor for Bearer header + refresh logic
5. **Wire into `KeyboardIME`** — Register new panel in the menu

### Open Questions
- Is the Modal-hosted stego API (`nishxnt-97--encode.modal.run`) still live? May need mock fallback.
- Should identity keys persist across sessions (EncryptedSharedPreferences) or regenerate?
- Demo scope: two-device (Alice + Bob) or single-device round-trip?

---

## 9. Key File Paths (Quick Reference)

| What | Path |
|------|------|
| IME Service | `app/src/main/java/com/frogobox/appkeyboard/services/KeyboardIME.kt` |
| Base IME | `frogo-keyboard/src/main/java/com/frogobox/libkeyboard/common/core/BaseKeyboardIME.kt` |
| Demo Keyboard (Flask) | `app/src/main/java/com/frogobox/appkeyboard/ui/keyboard/demo/` |
| Secure Messaging (offline) | `app/src/main/java/com/frogobox/appkeyboard/ui/keyboard/securemessaging/` |
| Compression Keyboard | `app/src/main/java/com/frogobox/appkeyboard/ui/keyboard/compression/` |
| Backend API Service | `app/src/main/java/com/frogobox/appkeyboard/data/remote/BackendApiService.kt` |
| CryptoService | `app/src/main/java/com/frogobox/appkeyboard/core/CryptoService.kt` |
| TextCompressor | `app/src/main/java/com/frogobox/appkeyboard/data/repository/compression/custom/TextCompressor.kt` |
| Flask Backend | `backend/server.py` |
| FastAPI Server | `Secure-application/Server/main.py` |
| Server Obfuscation | `Secure-application/Server/app/services/obfuscation.py` |
| Server E2EE | `Secure-application/Server/app/services/e2ee.py` |
| CLI Demo (Alice) | `Secure-application/demos/server CLI demos/alice.py` |
| CLI Demo (Bob) | `Secure-application/demos/server CLI demos/bob.py` |
| App build.gradle | `app/build.gradle.kts` |
| Version catalog | `gradle/libs.versions.toml` |
| Vocab (DailyDialog) | `app/src/main/assets/dailydialog_vocab.json` |

---

## 10. Tech Stack Summary

| Component | Technology |
|-----------|-----------|
| Android app | Kotlin, Jetpack Compose, Hilt DI, ViewBinding |
| Networking | Retrofit 2.9.0, OkHttp 4.12.0, Gson |
| Crypto (Android) | XChaCha20-Poly1305 (current), needs X25519/Ed25519/HKDF |
| Server | Python, FastAPI, SQLAlchemy, PostgreSQL/SQLite |
| Server auth | JWT (HS256), bcrypt passwords |
| Server crypto | cryptography lib (Ed25519, X25519, ChaCha20-Poly1305, HKDF, Fernet) |
| Steganography | External Modal-hosted LLM API (arithmetic coding stego) |
| Build system | Gradle (Kotlin DSL), AGP |
| Min SDK | Check `app/build.gradle.kts` |
