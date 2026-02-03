package com.frogobox.appkeyboard.crypto

import android.util.Base64
import com.frogobox.appkeyboard.data.repository.compression.CompressionService

/**
 * Main Crypto Service Facade
 * 
 * Combines PRNG and XChaCha20-Poly1305 for easy message encryption/decryption.
 * Integrates compression for smaller encrypted payloads.
 * Each contact has their own PRNG instance derived from a shared master secret.
 */
object CryptoService {
    
    // In-memory cache of PRNGs per contact
    private val prngCache = mutableMapOf<String, PRNGManager>()
    
    // In-memory master secrets (in production, use SecureKeyStorage)
    private val masterSecrets = mutableMapOf<String, ByteArray>()
    
    /**
     * Setup a contact with a shared master secret
     * Both parties must use the same master secret for sync
     */
    fun setupContact(contactId: String, masterSecret: ByteArray) {
        masterSecrets[contactId] = masterSecret.copyOf()
        prngCache[contactId] = PRNGManager(masterSecret)
    }
    
    /**
     * Setup a contact using a passphrase (converts to bytes)
     */
    fun setupContactWithPassphrase(contactId: String, passphrase: String) {
        val masterSecret = deriveKeyFromPassphrase(passphrase)
        setupContact(contactId, masterSecret)
    }
    
    /**
     * Check if a contact is set up
     */
    fun hasContact(contactId: String): Boolean {
        return prngCache.containsKey(contactId)
    }
    
    /**
     * Remove a contact and clear their keys
     */
    fun removeContact(contactId: String) {
        prngCache.remove(contactId)
        masterSecrets.remove(contactId)
    }
    
    /**
     * Get current PRNG counter for a contact
     */
    fun getCounter(contactId: String): Long {
        return prngCache[contactId]?.getCounter() ?: 0L
    }
    
    /**
     * Set PRNG counter for a contact (for restore/sync)
     */
    fun setCounter(contactId: String, counter: Long) {
        prngCache[contactId]?.setCounter(counter)
    }
    
    /**
     * Encrypt + Compress a message for a contact (combines both)
     * Flow: Compress → Encrypt → Base64
     * Returns Base64-encoded ciphertext of compressed data
     */
    fun encryptAndCompress(plaintext: String, contactId: String): EncryptAndCompressResult {
        val prng = prngCache[contactId]
            ?: return EncryptAndCompressResult.failure("Contact not found: $contactId")
        
        return try {
            // Step 1: Compress
            val compressed = CompressionService.compress(plaintext)
            val originalSize = plaintext.toByteArray(Charsets.UTF_8).size
            val compressedSize = compressed.size
            val ratio = if (compressedSize > 0) originalSize.toFloat() / compressedSize else 0f
            val savings = if (originalSize > 0) (1 - compressedSize.toFloat() / originalSize) * 100 else 0f
            
            // Step 2: Encrypt
            val (nonce, key) = prng.generateNonceAndKey()
            val ciphertext = XChaCha20Poly1305.encrypt(compressed, key, nonce)
            
            // Step 3: Combine and encode
            val combined = nonce + ciphertext
            val encoded = Base64.encodeToString(combined, Base64.NO_WRAP)
            
            EncryptAndCompressResult.success(
                ciphertext = encoded,
                counter = prng.getCounter() - 1,
                originalSize = originalSize,
                compressedSize = compressedSize,
                encryptedSize = ciphertext.size,
                ratio = ratio,
                savings = savings
            )
        } catch (e: Exception) {
            EncryptAndCompressResult.failure("Encrypt+Compress failed: ${e.message}")
        }
    }
    
    /**
     * Decrypt + Decompress a message from a contact (combines both)
     * Flow: Base64 → Decrypt → Decompress
     * Expects Base64-encoded input with prepended nonce
     */
    fun decryptAndDecompress(encodedCiphertext: String, contactId: String): DecryptAndDecompressResult {
        val prng = prngCache[contactId]
            ?: return DecryptAndDecompressResult.failure("Contact not found: $contactId")
        
        return try {
            val combined = Base64.decode(encodedCiphertext, Base64.NO_WRAP)
            if (combined.size < 24 + 16) {  // nonce + min auth tag
                return DecryptAndDecompressResult.failure("Ciphertext too short")
            }
            
            val nonce = combined.copyOfRange(0, 24)
            val ciphertext = combined.copyOfRange(24, combined.size)
            
            // Get key for current counter position
            val key = prng.peekKey()
            prng.advance()  // Advance counter after use
            
            // Step 1: Decrypt
            val compressed = XChaCha20Poly1305.decrypt(ciphertext, key, nonce)
            
            // Step 2: Decompress
            val plaintext = CompressionService.decompress(compressed)
            
            DecryptAndDecompressResult.success(
                plaintext = plaintext,
                compressedSize = compressed.size,
                decryptedSize = plaintext.toByteArray(Charsets.UTF_8).size,
                attemptsUsed = 1
            )
        } catch (e: Exception) {
            DecryptAndDecompressResult.failure("Decrypt+Decompress failed: ${e.message}")
        }
    }
    
    /**
     * Decrypt + Decompress with resync - tries multiple PRNG positions
     */
    fun decryptAndDecompressWithResync(
        encodedCiphertext: String, 
        contactId: String, 
        maxAttempts: Int = 20
    ): DecryptAndDecompressResult {
        val prng = prngCache[contactId]
            ?: return DecryptAndDecompressResult.failure("Contact not found: $contactId")
        
        val masterSecret = masterSecrets[contactId]
            ?: return DecryptAndDecompressResult.failure("Master secret not found")
        
        return try {
            val combined = Base64.decode(encodedCiphertext, Base64.NO_WRAP)
            if (combined.size < 24 + 16) {
                return DecryptAndDecompressResult.failure("Ciphertext too short")
            }
            
            val nonce = combined.copyOfRange(0, 24)
            val ciphertext = combined.copyOfRange(24, combined.size)
            
            val startCounter = prng.getCounter()
            
            // Try current position and next N positions
            for (attempt in 0 until maxAttempts) {
                try {
                    // Create temporary PRNG at test position
                    val testPrng = PRNGManager(masterSecret)
                    testPrng.setCounter(startCounter + attempt)
                    val key = testPrng.peekKey()
                    
                    // Step 1: Decrypt
                    val compressed = XChaCha20Poly1305.decrypt(ciphertext, key, nonce)
                    
                    // Step 2: Decompress
                    val plaintext = CompressionService.decompress(compressed)
                    
                    // Success! Update main PRNG counter
                    prng.setCounter(startCounter + attempt + 1)
                    
                    return DecryptAndDecompressResult.success(
                        plaintext = plaintext,
                        compressedSize = compressed.size,
                        decryptedSize = plaintext.toByteArray(Charsets.UTF_8).size,
                        attemptsUsed = attempt + 1
                    )
                } catch (e: Exception) {
                    // Try next position
                    continue
                }
            }
            
            DecryptAndDecompressResult.failure("Decrypt+Decompress failed after $maxAttempts attempts - keys may be out of sync")
        } catch (e: Exception) {
            DecryptAndDecompressResult.failure("Decrypt+Decompress error: ${e.message}")
        }
    }
    
    /**
     * Encrypt a message for a contact
     * Returns Base64-encoded ciphertext
     */
    fun encrypt(plaintext: String, contactId: String): EncryptResult {
        val prng = prngCache[contactId]
            ?: return EncryptResult.failure("Contact not found: $contactId")
        
        return try {
            val (nonce, key) = prng.generateNonceAndKey()
            val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
            val ciphertext = XChaCha20Poly1305.encrypt(plaintextBytes, key, nonce)
            
            // Combine nonce + ciphertext for transmission
            // Format: [24 bytes nonce][N bytes ciphertext+tag]
            val combined = nonce + ciphertext
            val encoded = Base64.encodeToString(combined, Base64.NO_WRAP)
            
            EncryptResult.success(
                ciphertext = encoded,
                counter = prng.getCounter() - 1  // Counter was already advanced
            )
        } catch (e: Exception) {
            EncryptResult.failure("Encryption failed: ${e.message}")
        }
    }
    
    /**
     * Encrypt and return raw bytes (for server communication)
     */
    fun encryptRaw(plaintext: String, contactId: String): ByteArray? {
        val prng = prngCache[contactId] ?: return null
        
        return try {
            val (nonce, key) = prng.generateNonceAndKey()
            val plaintextBytes = plaintext.toByteArray(Charsets.UTF_8)
            val ciphertext = XChaCha20Poly1305.encrypt(plaintextBytes, key, nonce)
            nonce + ciphertext
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Decrypt a message from a contact
     * Expects Base64-encoded input with prepended nonce
     */
    fun decrypt(encodedCiphertext: String, contactId: String): DecryptResult {
        val prng = prngCache[contactId]
            ?: return DecryptResult.failure("Contact not found: $contactId")
        
        return try {
            val combined = Base64.decode(encodedCiphertext, Base64.NO_WRAP)
            if (combined.size < 24 + 16) {  // nonce + min auth tag
                return DecryptResult.failure("Ciphertext too short")
            }
            
            val nonce = combined.copyOfRange(0, 24)
            val ciphertext = combined.copyOfRange(24, combined.size)
            
            // Get key for current counter position
            val key = prng.peekKey()
            prng.advance()  // Advance counter after use
            
            val plaintext = XChaCha20Poly1305.decrypt(ciphertext, key, nonce)
            
            DecryptResult.success(
                plaintext = String(plaintext, Charsets.UTF_8),
                attemptsUsed = 1
            )
        } catch (e: Exception) {
            DecryptResult.failure("Decryption failed: ${e.message}")
        }
    }
    
    /**
     * Decrypt with resync - tries multiple PRNG positions if initial decrypt fails
     * Useful when messages are received out of order or some are skipped
     */
    fun decryptWithResync(
        encodedCiphertext: String, 
        contactId: String, 
        maxAttempts: Int = 20
    ): DecryptResult {
        val prng = prngCache[contactId]
            ?: return DecryptResult.failure("Contact not found: $contactId")
        
        val masterSecret = masterSecrets[contactId]
            ?: return DecryptResult.failure("Master secret not found")
        
        return try {
            val combined = Base64.decode(encodedCiphertext, Base64.NO_WRAP)
            if (combined.size < 24 + 16) {
                return DecryptResult.failure("Ciphertext too short")
            }
            
            val nonce = combined.copyOfRange(0, 24)
            val ciphertext = combined.copyOfRange(24, combined.size)
            
            val startCounter = prng.getCounter()
            
            // Try current position and next N positions
            for (attempt in 0 until maxAttempts) {
                try {
                    // Create temporary PRNG at test position
                    val testPrng = PRNGManager(masterSecret)
                    testPrng.setCounter(startCounter + attempt)
                    val key = testPrng.peekKey()
                    
                    val plaintext = XChaCha20Poly1305.decrypt(ciphertext, key, nonce)
                    
                    // Success! Update main PRNG counter
                    prng.setCounter(startCounter + attempt + 1)
                    
                    return DecryptResult.success(
                        plaintext = String(plaintext, Charsets.UTF_8),
                        attemptsUsed = attempt + 1
                    )
                } catch (e: Exception) {
                    // Try next position
                    continue
                }
            }
            
            DecryptResult.failure("Decryption failed after $maxAttempts attempts - keys may be out of sync")
        } catch (e: Exception) {
            DecryptResult.failure("Decryption error: ${e.message}")
        }
    }
    
    /**
     * Derive a 32-byte key from a passphrase using PBKDF2-like approach
     */
    private fun deriveKeyFromPassphrase(passphrase: String): ByteArray {
        // Simple derivation - in production use PBKDF2 or Argon2
        val hash = java.security.MessageDigest.getInstance("SHA-256")
        return hash.digest(passphrase.toByteArray(Charsets.UTF_8))
    }
    
    /**
     * Generate a random master secret (for initial key exchange)
     */
    fun generateMasterSecret(): ByteArray {
        val secret = ByteArray(32)
        java.security.SecureRandom().nextBytes(secret)
        return secret
    }
    
    /**
     * Convert master secret to shareable hex string
     */
    fun masterSecretToHex(secret: ByteArray): String {
        return secret.joinToString("") { "%02x".format(it) }
    }
    
    /**
     * Parse master secret from hex string
     */
    fun hexToMasterSecret(hex: String): ByteArray {
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}

/**
 * Result of encryption operation
 */
data class EncryptResult(
    val success: Boolean,
    val ciphertext: String?,
    val counter: Long,
    val error: String?
) {
    companion object {
        fun success(ciphertext: String, counter: Long) = EncryptResult(
            success = true,
            ciphertext = ciphertext,
            counter = counter,
            error = null
        )
        
        fun failure(error: String) = EncryptResult(
            success = false,
            ciphertext = null,
            counter = -1,
            error = error
        )
    }
}

/**
 * Result of decryption operation
 */
data class DecryptResult(
    val success: Boolean,
    val plaintext: String?,
    val attemptsUsed: Int,
    val error: String?
) {
    companion object {
        fun success(plaintext: String, attemptsUsed: Int) = DecryptResult(
            success = true,
            plaintext = plaintext,
            attemptsUsed = attemptsUsed,
            error = null
        )
        
        fun failure(error: String) = DecryptResult(
            success = false,
            plaintext = null,
            attemptsUsed = 0,
            error = error
        )
    }
}

/**
 * Result of encrypt+compress operation
 */
data class EncryptAndCompressResult(
    val success: Boolean,
    val ciphertext: String?,
    val counter: Long,
    val originalSize: Int,
    val compressedSize: Int,
    val encryptedSize: Int,
    val ratio: Float,
    val savings: Float,
    val error: String?
) {
    companion object {
        fun success(
            ciphertext: String, 
            counter: Long,
            originalSize: Int,
            compressedSize: Int,
            encryptedSize: Int,
            ratio: Float,
            savings: Float
        ) = EncryptAndCompressResult(
            success = true,
            ciphertext = ciphertext,
            counter = counter,
            originalSize = originalSize,
            compressedSize = compressedSize,
            encryptedSize = encryptedSize,
            ratio = ratio,
            savings = savings,
            error = null
        )
        
        fun failure(error: String) = EncryptAndCompressResult(
            success = false,
            ciphertext = null,
            counter = -1,
            originalSize = 0,
            compressedSize = 0,
            encryptedSize = 0,
            ratio = 0f,
            savings = 0f,
            error = error
        )
    }
}

/**
 * Result of decrypt+decompress operation
 */
data class DecryptAndDecompressResult(
    val success: Boolean,
    val plaintext: String?,
    val compressedSize: Int,
    val decryptedSize: Int,
    val attemptsUsed: Int,
    val error: String?
) {
    companion object {
        fun success(
            plaintext: String, 
            compressedSize: Int,
            decryptedSize: Int,
            attemptsUsed: Int
        ) = DecryptAndDecompressResult(
            success = true,
            plaintext = plaintext,
            compressedSize = compressedSize,
            decryptedSize = decryptedSize,
            attemptsUsed = attemptsUsed,
            error = null
        )
        
        fun failure(error: String) = DecryptAndDecompressResult(
            success = false,
            plaintext = null,
            compressedSize = 0,
            decryptedSize = 0,
            attemptsUsed = 0,
            error = error
        )
    }
}
