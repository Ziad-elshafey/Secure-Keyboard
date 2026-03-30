# Secure Messaging Keyboard - Implementation Plan

Based on [arch.md](arch.md) architecture specification.

---

## Overview

Build a local-first secure messaging system into the Android keyboard, implementing crypto primitives and UI before tackling server integration. Follows existing `CompressionKeyboard` patterns.

---

## Phase 1: Crypto Foundation (Local-Only) ⭐ TOP PRIORITY

### 1.1 Add Crypto Dependencies

**File:** `gradle/libs.versions.toml`

```toml
# Add versions
tink = "1.12.0"
securityCrypto = "1.1.0-alpha06"

# Add libraries
google-tink = { group = "com.google.crypto.tink", name = "tink-android", version.ref = "tink" }
androidx-security-crypto = { group = "androidx.security", name = "security-crypto", version.ref = "securityCrypto" }
```

**File:** `app/build.gradle.kts`

```kotlin
dependencies {
    implementation(libs.google.tink)
    implementation(libs.androidx.security.crypto)
}
```

---

### 1.2 Create PRNGManager (Synchronized Random Generator)

**File:** `app/src/main/java/com/frogobox/appkeyboard/crypto/PRNGManager.kt`

**Purpose:** Both keyboards feed Master Secret into HKDF-SHA256 to generate identical nonce/key streams.

```kotlin
class PRNGManager(masterSecret: ByteArray) {
    private val hkdfKey: ByteArray  // Extracted from master secret
    private var counter: Long = 0   // Persisted per-contact
    
    fun generateNonce(length: Int = 24): ByteArray   // 24 bytes for XChaCha20
    fun generateKey(length: Int = 32): ByteArray     // 32 bytes for ChaCha20
    fun getCounter(): Long
    fun setCounter(value: Long)                      // For resync
    fun advance(steps: Int)                          // Crank forward for resync
}
```

**Key Features:**
- [x] HKDF-SHA256 Extract step from master secret
- [x] HKDF-SHA256 Expand step for each nonce/key
- [x] Counter-based determinism (same counter = same output)
- [x] Serializable counter state for persistence

---

### 1.3 Create XChaCha20Poly1305 Encryption Wrapper

**File:** `app/src/main/java/com/frogobox/appkeyboard/crypto/XChaCha20Poly1305.kt`

**Purpose:** Symmetric authenticated encryption for each message.

```kotlin
object XChaCha20Poly1305 {
    // For API 28+ (native support)
    fun encrypt(plaintext: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray
    fun decrypt(ciphertext: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray
    
    // Fallback for API < 28 using Tink
    private fun encryptWithTink(...)
    private fun decryptWithTink(...)
}
```

**Algorithm Details:**
- Key size: 256 bits (32 bytes)
- Nonce size: 192 bits (24 bytes) for XChaCha20
- Auth tag: 128 bits (16 bytes) - Poly1305
- Provides AEAD (Authenticated Encryption with Associated Data)

---

### 1.4 Create SecureKeyStorage

**File:** `app/src/main/java/com/frogobox/appkeyboard/crypto/SecureKeyStorage.kt`

**Purpose:** Securely store Master Secret using Android Keystore.

```kotlin
class SecureKeyStorage(context: Context) {
    private val encryptedPrefs: SharedPreferences  // EncryptedSharedPreferences
    
    fun storeMasterSecret(contactId: String, secret: ByteArray)
    fun getMasterSecret(contactId: String): ByteArray?
    fun deleteMasterSecret(contactId: String)
    fun hasMasterSecret(contactId: String): Boolean
    
    // Store PRNG counter state per contact
    fun storeCounter(contactId: String, counter: Long)
    fun getCounter(contactId: String): Long
}
```

**Security:**
- Uses AndroidKeyStore for key encryption
- EncryptedSharedPreferences for data at rest
- Master secret never leaves secure storage unencrypted

---

### 1.5 Create CryptoService Facade

**File:** `app/src/main/java/com/frogobox/appkeyboard/crypto/CryptoService.kt`

**Purpose:** Simple API combining all crypto components.

```kotlin
object CryptoService {
    fun initialize(context: Context)
    
    // High-level encrypt/decrypt
    fun encryptMessage(plaintext: String, contactId: String): EncryptedMessage
    fun decryptMessage(ciphertext: ByteArray, contactId: String): DecryptedResult
    
    // Contact management
    fun setupContact(contactId: String, masterSecret: ByteArray)
    fun removeContact(contactId: String)
    fun hasContact(contactId: String): Boolean
    
    // Resync (try next N keys if decryption fails)
    fun decryptWithResync(ciphertext: ByteArray, contactId: String, maxAttempts: Int = 20): DecryptedResult
}

data class EncryptedMessage(
    val ciphertext: ByteArray,
    val counter: Long  // For debugging/logging only
)

data class DecryptedResult(
    val plaintext: String?,
    val success: Boolean,
    val attemptsUsed: Int,
    val error: String?
)
```

---

## Phase 2: Data Layer (Local Storage)

### 2.1 Contact Entity

**File:** `app/src/main/java/com/frogobox/appkeyboard/data/local/db/crypto/ContactEntity.kt`

```kotlin
@Entity(tableName = "secure_contacts")
data class ContactEntity(
    @PrimaryKey val contactId: String,      // Unique identifier
    val displayName: String,                 // Human-readable name
    val publicKeyBundle: ByteArray?,         // For X3DH (Phase 4)
    val prngCounter: Long = 0,               // Current PRNG position
    val lastMessageTimestamp: Long = 0,
    val createdAt: Long = System.currentTimeMillis()
)
```

---

### 2.2 Message Entity

**File:** `app/src/main/java/com/frogobox/appkeyboard/data/local/db/crypto/MessageEntity.kt`

```kotlin
@Entity(tableName = "secure_messages")
data class MessageEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val contactId: String,
    val ciphertext: ByteArray,
    val decoyText: String?,                  // Mapped obfuscation text
    val direction: MessageDirection,         // SENT or RECEIVED
    val prngCounterUsed: Long,               // Which counter was used
    val timestamp: Long = System.currentTimeMillis(),
    val status: MessageStatus                // PENDING, SENT, DELIVERED, FAILED
)

enum class MessageDirection { SENT, RECEIVED }
enum class MessageStatus { PENDING, SENT, DELIVERED, FAILED }
```

---

### 2.3 DAOs

**File:** `app/src/main/java/com/frogobox/appkeyboard/data/local/db/crypto/ContactDao.kt`

```kotlin
@Dao
interface ContactDao {
    @Query("SELECT * FROM secure_contacts ORDER BY lastMessageTimestamp DESC")
    fun getAllContacts(): Flow<List<ContactEntity>>
    
    @Query("SELECT * FROM secure_contacts WHERE contactId = :id")
    suspend fun getContact(id: String): ContactEntity?
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertContact(contact: ContactEntity)
    
    @Query("UPDATE secure_contacts SET prngCounter = :counter WHERE contactId = :id")
    suspend fun updateCounter(id: String, counter: Long)
    
    @Delete
    suspend fun deleteContact(contact: ContactEntity)
}
```

**File:** `app/src/main/java/com/frogobox/appkeyboard/data/local/db/crypto/MessageDao.kt`

```kotlin
@Dao
interface MessageDao {
    @Query("SELECT * FROM secure_messages WHERE contactId = :contactId ORDER BY timestamp DESC")
    fun getMessagesForContact(contactId: String): Flow<List<MessageEntity>>
    
    @Insert
    suspend fun insertMessage(message: MessageEntity): Long
    
    @Query("SELECT * FROM secure_messages WHERE decoyText = :decoyText LIMIT 1")
    suspend fun findByDecoyText(decoyText: String): MessageEntity?
    
    @Query("UPDATE secure_messages SET status = :status WHERE id = :id")
    suspend fun updateStatus(id: Long, status: MessageStatus)
}
```

---

### 2.4 Update AppDatabase

**File:** `app/src/main/java/com/frogobox/appkeyboard/data/local/db/AppDatabase.kt`

```kotlin
@Database(
    entities = [
        AutoTextEntity::class,
        ContactEntity::class,    // ADD
        MessageEntity::class     // ADD
    ],
    version = 2,  // INCREMENT
    exportSchema = true
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun autoTextDao(): AutoTextDao
    abstract fun contactDao(): ContactDao      // ADD
    abstract fun messageDao(): MessageDao      // ADD
}
```

---

### 2.5 Create CryptoRepository

**File:** `app/src/main/java/com/frogobox/appkeyboard/data/repository/crypto/CryptoRepository.kt`

```kotlin
interface CryptoRepository {
    // Contacts
    fun getAllContacts(): Flow<List<ContactEntity>>
    suspend fun addContact(contactId: String, displayName: String, masterSecret: ByteArray)
    suspend fun removeContact(contactId: String)
    
    // Encryption
    suspend fun encryptAndStore(plaintext: String, contactId: String): EncryptedMessage
    suspend fun decryptMessage(ciphertext: ByteArray, contactId: String): DecryptedResult
    
    // Sync
    suspend fun updatePrngCounter(contactId: String, counter: Long)
}
```

---

## Phase 3: Keyboard UI Integration

### 3.1 SecureMessagingKeyboard

**File:** `app/src/main/java/com/frogobox/appkeyboard/ui/keyboard/securemessaging/SecureMessagingKeyboard.kt`

```kotlin
class SecureMessagingKeyboard(
    context: Context,
    attrs: AttributeSet?,
) : BaseKeyboard<KeyboardSecureMessagingBinding>(context, attrs) {

    private var selectedContactId: String? = null
    
    override fun initUI() {
        binding.apply {
            btnSelectContact.setOnClickListener { showContactPicker() }
            btnEncrypt.setOnClickListener { encryptCurrentText() }
            btnDecrypt.setOnClickListener { decryptCurrentText() }
            btnAddContact.setOnClickListener { showAddContactDialog() }
        }
    }
    
    private fun encryptCurrentText() {
        val text = currentInputConnection?.getExtractedText(...)?.text ?: return
        val contactId = selectedContactId ?: return
        
        GlobalScope.launch(Dispatchers.Default) {
            val result = CryptoService.encryptMessage(text.toString(), contactId)
            
            withContext(Dispatchers.Main) {
                // Replace input with Base64 encoded ciphertext
                val encoded = Base64.encodeToString(result.ciphertext, Base64.DEFAULT)
                currentInputConnection?.apply {
                    deleteSurroundingText(text.length, 0)
                    commitText(encoded, 1)
                }
                binding.tvStatus.text = "[OK] Encrypted for $contactId"
            }
        }
    }
    
    private fun decryptCurrentText() {
        val text = currentInputConnection?.getExtractedText(...)?.text ?: return
        val contactId = selectedContactId ?: return
        
        GlobalScope.launch(Dispatchers.Default) {
            val ciphertext = Base64.decode(text.toString(), Base64.DEFAULT)
            val result = CryptoService.decryptWithResync(ciphertext, contactId)
            
            withContext(Dispatchers.Main) {
                if (result.success) {
                    binding.tvDecryptedText.text = result.plaintext
                    binding.tvStatus.text = "[OK] Decrypted (${result.attemptsUsed} attempts)"
                } else {
                    binding.tvStatus.text = "[FAIL] ${result.error}"
                }
            }
        }
    }
}
```

---

### 3.2 Layout XML

**File:** `app/src/main/res/layout/keyboard_secure_messaging.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:orientation="vertical"
    android:background="@color/keyboard_background">

    <!-- Toolbar -->
    <LinearLayout
        android:layout_width="match_parent"
        android:layout_height="48dp"
        android:orientation="horizontal"
        android:gravity="center_vertical"
        android:padding="8dp">
        
        <ImageButton android:id="@+id/btn_back" ... />
        <TextView android:id="@+id/tv_toolbar_title" android:text="Secure Messaging" ... />
        <View android:layout_weight="1" ... />
        <Button android:id="@+id/btn_add_contact" android:text="+" ... />
    </LinearLayout>

    <!-- Contact Selector -->
    <Button
        android:id="@+id/btn_select_contact"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Select Contact"
        android:layout_margin="8dp" />

    <!-- Action Buttons -->
    <LinearLayout
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:orientation="horizontal"
        android:padding="8dp">
        
        <Button android:id="@+id/btn_encrypt" android:text="🔒 Encrypt" android:layout_weight="1" ... />
        <Button android:id="@+id/btn_decrypt" android:text="🔓 Decrypt" android:layout_weight="1" ... />
    </LinearLayout>

    <!-- Status Display -->
    <TextView
        android:id="@+id/tv_status"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:padding="8dp"
        android:textColor="@color/status_text" />

    <!-- Decrypted Text Preview -->
    <ScrollView
        android:layout_width="match_parent"
        android:layout_height="120dp"
        android:padding="8dp">
        
        <TextView
            android:id="@+id/tv_decrypted_text"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:hint="Decrypted message will appear here..." />
    </ScrollView>

</LinearLayout>
```

---

### 3.3 Add to KeyboardFeatureType

**File:** `app/src/main/java/com/frogobox/appkeyboard/model/KeyboardFeatureType.kt`

```kotlin
enum class KeyboardFeatureType(...) {
    // ... existing types ...
    COMPRESSION("menu_compression", "Compress Text", R.drawable.ic_menu_auto_text),
    SECURE_MESSAGING("menu_secure", "Secure Message", R.drawable.ic_menu_secure),  // ADD
}
```

---

### 3.4 Wire into KeyboardIME

**File:** `app/src/main/java/com/frogobox/appkeyboard/services/KeyboardIME.kt`

```kotlin
// In showMainKeyboard()
binding.keyboardSecureMessaging.gone()  // ADD

// In feature click handler
KeyboardFeatureType.SECURE_MESSAGING -> {
    binding.keyboardSecureMessaging.visible()
    binding.keyboardSecureMessaging.setInputConnection(currentInputConnection)
    binding.keyboardMain.gone()
}

// In back button handler
binding.keyboardSecureMessaging.binding.btnBack.setOnClickListener {
    showMainKeyboard()
}
```

---

## Phase 4: Server Integration (LOWER PRIORITY)

### 4.1 Nishant API Service

**File:** `app/src/main/java/com/frogobox/appkeyboard/data/remote/NishantApiService.kt`

```kotlin
interface NishantApiService {
    @POST("upload")
    suspend fun blindUpload(@Body ciphertext: ByteArray): UploadResponse
    
    @GET("retrieve/{decoyText}")
    suspend fun retrieveCiphertext(@Path("decoyText") decoyText: String): ByteArray
    
    @GET("prekeys/{userId}")
    suspend fun getPreKeyBundle(@Path("userId") userId: String): PreKeyBundle
    
    @POST("prekeys")
    suspend fun publishPreKeys(@Body bundle: PreKeyBundle): Response<Unit>
}

data class UploadResponse(
    val messageId: String,
    val decoyText: String  // Server-assigned obfuscation text
)
```

---

### 4.2 X3DH Key Exchange

**File:** `app/src/main/java/com/frogobox/appkeyboard/crypto/X3DHKeyExchange.kt`

```kotlin
object X3DHKeyExchange {
    // Generate identity key pair (long-term)
    fun generateIdentityKeyPair(): KeyPair
    
    // Generate signed pre-key (medium-term)
    fun generateSignedPreKey(identityKey: PrivateKey): SignedPreKey
    
    // Generate one-time pre-keys (single use)
    fun generateOneTimePreKeys(count: Int): List<PreKey>
    
    // Perform X3DH as initiator
    fun initiateKeyExchange(
        myIdentityKey: KeyPair,
        theirPreKeyBundle: PreKeyBundle
    ): SharedSecret
    
    // Perform X3DH as responder
    fun respondToKeyExchange(
        myIdentityKey: KeyPair,
        mySignedPreKey: SignedPreKey,
        myOneTimePreKey: PreKey?,
        initiatorMessage: InitialMessage
    ): SharedSecret
}
```

---

## File Structure Summary

```
app/src/main/java/com/frogobox/appkeyboard/
├── crypto/                              # NEW PACKAGE
│   ├── CryptoService.kt                 # Phase 1.5
│   ├── PRNGManager.kt                   # Phase 1.2
│   ├── XChaCha20Poly1305.kt             # Phase 1.3
│   ├── SecureKeyStorage.kt              # Phase 1.4
│   └── X3DHKeyExchange.kt               # Phase 4.2
│
├── data/
│   ├── local/db/
│   │   ├── AppDatabase.kt               # MODIFY (Phase 2.4)
│   │   └── crypto/                      # NEW PACKAGE
│   │       ├── ContactEntity.kt         # Phase 2.1
│   │       ├── ContactDao.kt            # Phase 2.3
│   │       ├── MessageEntity.kt         # Phase 2.2
│   │       └── MessageDao.kt            # Phase 2.3
│   │
│   ├── remote/
│   │   └── NishantApiService.kt         # Phase 4.1
│   │
│   └── repository/
│       └── crypto/                      # NEW PACKAGE
│           ├── CryptoRepository.kt      # Phase 2.5
│           └── CryptoRepositoryImpl.kt
│
├── di/
│   └── CryptoModule.kt                  # Hilt bindings
│
├── model/
│   └── KeyboardFeatureType.kt           # MODIFY (Phase 3.3)
│
├── services/
│   └── KeyboardIME.kt                   # MODIFY (Phase 3.4)
│
└── ui/keyboard/
    └── securemessaging/                 # NEW PACKAGE
        └── SecureMessagingKeyboard.kt   # Phase 3.1

app/src/main/res/layout/
└── keyboard_secure_messaging.xml        # Phase 3.2
```

---

## Implementation Order Checklist

### Week 1: Crypto Core
- [ ] Add dependencies (Tink, Security-Crypto)
- [ ] Implement `PRNGManager.kt`
- [ ] Implement `XChaCha20Poly1305.kt`
- [ ] Implement `SecureKeyStorage.kt`
- [ ] Implement `CryptoService.kt`
- [ ] Write unit tests for crypto functions

### Week 2: Data Layer
- [ ] Create `ContactEntity.kt` and `ContactDao.kt`
- [ ] Create `MessageEntity.kt` and `MessageDao.kt`
- [ ] Update `AppDatabase.kt` with migration
- [ ] Implement `CryptoRepository.kt`
- [ ] Test Room operations

### Week 3: UI Integration
- [ ] Create `keyboard_secure_messaging.xml`
- [ ] Implement `SecureMessagingKeyboard.kt`
- [ ] Add `SECURE_MESSAGING` to enum
- [ ] Wire into `KeyboardIME.kt`
- [ ] Add menu icon drawable
- [ ] Test encrypt/decrypt flow on emulator

### Week 4: Polish & Resync
- [ ] Implement resync logic (try N keys)
- [ ] Add contact picker dialog
- [ ] Add "add contact" dialog (manual secret input)
- [ ] Error handling and edge cases
- [ ] UI polish

### Future: Server Integration
- [ ] Implement `NishantApiService.kt`
- [ ] Implement X3DH key exchange
- [ ] Blind upload flow
- [ ] Decoy text retrieval
- [ ] Message interception for incoming decoys

---

## Notes

1. **Manual Key Exchange First:** Before implementing X3DH, use manual shared secret input (QR code or paste) to test the local crypto.

2. **Counter Persistence Critical:** PRNG counter must survive app restarts. Store in Room per-contact.

3. **API 28+ for Native ChaCha20:** Use Tink as fallback for older devices.

4. **Resync Window:** Try up to 20 PRNG positions if decryption fails (handles skipped messages).
