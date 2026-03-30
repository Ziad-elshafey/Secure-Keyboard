# Plan: Migrate to FlorisBoard

**TL;DR:** Fork FlorisBoard, add your secure messaging + compression as Smartbar QuickActions and Compose panels. ~70% of your code copies as-is (crypto, APIs, services, activities). The main work is rewriting 2 keyboard panels from XML/ViewBinding to Jetpack Compose and adapting the DI from Hilt to FlorisBoard's pattern.

---

## Key architectural differences from frogo-keyboard

| Aspect | Current (frogo) | FlorisBoard |
|---|---|---|
| **UI framework** | XML layouts + ViewBinding | **Jetpack Compose** |
| **DI** | Hilt (@AndroidEntryPoint) | Custom singletons (no Hilt) |
| **Toolbar** | RecyclerView grid header | **Smartbar** with QuickActions system |
| **Panel system** | LinearLayout views toggled visible/gone | **ImeWindow** system with Compose panels |
| **IME service** | BaseKeyboardIME (frogo) | FlorisImeService |
| **License** | Apache-2.0 | **Apache-2.0** (safe for commercial) |

---

## Steps

### Phase 1 — Fork & Dependencies
1. Fork FlorisBoard repo
2. Add crypto dependencies to `build.gradle.kts`: Tink, BouncyCastle, security-crypto
3. Add networking dependencies: Retrofit, OkHttp, Gson converter
4. Verify build compiles on your setup

### Phase 2 — Copy Standalone Code (~70% of work, easy)
5. Copy these into the FlorisBoard project (adjust package names):
   - **Crypto/E2EE**: `E2EEModels.kt`, `E2EEService.kt`, `SecureKeyStore.kt`, `AuthTokenManager.kt`
   - **Repository**: `SecureMessagingRepository.kt`
   - **Compression**: `CompressionService.kt`, `LZMACompressionService.kt`, `ArithmeticCoder.kt`, `TextCompressor.kt`
   - **Network**: `SecureApiService.kt`, `StegoApiService.kt`, `BackendApiService.kt`, `AuthInterceptor.kt`, `TokenRefreshAuthenticator.kt`, `SecureApiDtos.kt`
   - **Accessibility**: `DecryptAccessibilityService.kt`, `DecryptCaptureState.kt`
   - **Activities**: `DecryptResultActivity.kt`, `SecureAuthActivity.kt`, `SecureTextActionActivity.kt`
6. Register `DecryptAccessibilityService` and activities in `AndroidManifest.xml`

### Phase 3 — DI Adaptation
7. Replace Hilt modules with FlorisBoard's pattern — initialize your singletons in `FlorisApplication.kt` or create a `SecureMessagingManager` singleton similar to how FlorisBoard manages `KeyboardManager`, `ClipboardManager`, etc.
8. Wire `SecureMessagingRepository` to be accessible from `FlorisImeService`

### Phase 4 — QuickActions Integration (the main hook)
9. Add new entries to `QuickAction.kt` enum:
   - `SECURE_ENCRYPT` — encrypts current text field content
   - `SECURE_DECRYPT` — triggers accessibility tap-to-capture
   - `SECURE_SESSION` — opens session management panel
   - `COMPRESS` — opens compression panel
10. Add icons for each action (drawable resources)
11. Each QuickAction runs a handler when tapped — wire to your encrypt/decrypt/session logic

### Phase 5 — Compose Panels (~20% of work, requires Compose knowledge)
12. **SecureMessagingPanel** — rewrite `SecureMessagingKeyboard.kt` as a Jetpack Compose panel:
    - Login form (username/password fields)
    - Session search + create
    - Active session display
    - Integrate with FlorisBoard's `ImeWindow` system to show/hide panel
13. **CompressionPanel** — rewrite `CompressionKeyboard.kt` as a Compose panel:
    - Compress/decompress buttons
    - Stats display
    - Text input/output

### Phase 6 — IME Logic Transplant
14. In `FlorisImeService.kt`, add the encrypt/decrypt handler methods:
    - `handleEncryptAction()` — read from `InputConnection`, call `secureRepo.sendMessage()`, replace text
    - `handleDecryptAction()` — check accessibility service → `DecryptCaptureState.startCapture()` → launch `DecryptResultActivity`
    - `performDecryption()` — call `secureRepo.decryptMessage()`, launch result activity
15. These methods read/write `InputConnection` — same API regardless of keyboard base

### Phase 7 — Testing
16. Test encrypt/decrypt on WhatsApp, Telegram, Messages
17. Test accessibility tap-to-decrypt overlay
18. Test compression
19. Test on BlueStacks + physical device
20. Test PROCESS_TEXT actions (text selection menu encrypt/decrypt)

---

## Risks & Challenges

| Risk | Severity | Mitigation |
|---|---|---|
| **Compose learning curve** | Medium | Only 2 panels need Compose; rest copies as-is |
| **No word suggestions** | High | FlorisBoard hasn't shipped this yet — your keyboard won't have autocomplete |
| **FlorisBoard still in beta** | Medium | Architecture may change between versions; pin to a stable tag |
| **ImeWindow panel integration** | Medium | Study clipboard panel as reference implementation |
| **No Hilt support** | Low | Convert to manual DI; FlorisBoard's pattern is straightforward |
| **Rust build toolchain** | Low | Need Rust installed for native libs; or use pre-built dummy libs for dev |

---

## What you gain

- Apache-2.0 license (keep code proprietary)
- Clipboard manager built-in
- Theming system
- Emoji keyboard
- Modern Compose UI
- Active development / community (8.1k stars, 120 contributors)

## What you lose (vs current)

- Word suggestions / autocomplete (not yet in FlorisBoard)
- Glide typing (not yet)
- Simpler codebase (FlorisBoard is more complex)

---

## Files to port (22 files)

### Standalone — copy as-is (rename package)
- `core/DecryptCaptureState.kt`
- `core/e2ee/E2EEModels.kt`
- `core/e2ee/E2EEService.kt`
- `data/repository/SecureMessagingRepository.kt`
- `data/repository/compression/CompressionService.kt`
- `data/repository/compression/LZMACompressionService.kt`
- `data/repository/compression/custom/ArithmeticCoder.kt`
- `data/repository/compression/custom/TextCompressor.kt`
- `data/remote/ApiService.kt`
- `data/remote/AuthInterceptor.kt`
- `data/remote/BackendApiService.kt`
- `data/remote/SecureApiService.kt`
- `data/remote/StegoApiService.kt`
- `data/remote/TokenRefreshAuthenticator.kt`
- `data/remote/dto/SecureApiDtos.kt`
- `data/local/AuthTokenManager.kt`
- `data/local/SecureKeyStore.kt`
- `services/DecryptAccessibilityService.kt`
- `ui/secure/DecryptResultActivity.kt`
- `ui/secure/SecureAuthActivity.kt`
- `ui/secure/SecureTextActionActivity.kt`

### Needs rewriting for Compose
- `ui/keyboard/securemessaging/SecureMessagingKeyboard.kt` → Jetpack Compose panel
- `ui/keyboard/compression/CompressionKeyboard.kt` → Jetpack Compose panel

### Needs adaptation
- `services/KeyboardIME.kt` → logic transplanted into `FlorisImeService.kt`
- `di/` modules → FlorisBoard's DI pattern (no Hilt)

### Dropped (not porting)
- `frogo-keyboard/` module entirely
- NewsKeyboard, MovieKeyboard, FormKeyboard, AutoTextKeyboard, TemplateTextKeyboard, WebViewKeyboard, DemoKeyboard
- All frogo-* library dependencies
- AutoTextDao, AppDatabase (Room — unless compression needs it)
