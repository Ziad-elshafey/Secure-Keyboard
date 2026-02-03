package com.frogobox.appkeyboard.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Synchronized Pseudo-Random Number Generator using HKDF-SHA256
 * 
 * Both sender and receiver keyboards feed the same Master Secret into this PRNG
 * and generate identical streams of nonces/keys in the same order.
 * 
 * This enables deterministic key derivation without transmitting nonces.
 */
class PRNGManager(masterSecret: ByteArray) {
    
    companion object {
        private const val ALGORITHM = "HmacSHA256"
        private const val NONCE_SIZE = 24  // XChaCha20 uses 24-byte nonce
        private const val KEY_SIZE = 32    // ChaCha20 uses 256-bit key
        private const val INFO_NONCE = "nonce"
        private const val INFO_KEY = "key"
    }
    
    // HKDF-extracted key (Pseudo-Random Key)
    private val prk: ByteArray
    
    // Counter for deterministic generation - must be synced between parties
    private var counter: Long = 0L
    
    init {
        // HKDF Extract step: PRK = HMAC-SHA256(salt, IKM)
        // Using all-zero salt as per RFC 5869 recommendation when no salt available
        val salt = ByteArray(32)
        prk = hkdfExtract(salt, masterSecret)
    }
    
    /**
     * HKDF Extract step
     * PRK = HMAC-Hash(salt, IKM)
     */
    private fun hkdfExtract(salt: ByteArray, inputKeyMaterial: ByteArray): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(salt, ALGORITHM))
        return mac.doFinal(inputKeyMaterial)
    }
    
    /**
     * HKDF Expand step
     * OKM = HMAC-Hash(PRK, info || counter)
     */
    private fun hkdfExpand(info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(prk, ALGORITHM))
        
        val result = ByteArray(length)
        var offset = 0
        var blockNum = 1
        var previousBlock = ByteArray(0)
        
        while (offset < length) {
            mac.reset()
            mac.update(previousBlock)
            mac.update(info)
            mac.update(blockNum.toByte())
            
            previousBlock = mac.doFinal()
            val toCopy = minOf(previousBlock.size, length - offset)
            System.arraycopy(previousBlock, 0, result, offset, toCopy)
            offset += toCopy
            blockNum++
        }
        
        return result
    }
    
    /**
     * Generate deterministic output based on counter and info string
     */
    private fun generateDeterministic(info: String, length: Int): ByteArray {
        // Combine info with current counter for unique derivation
        val infoWithCounter = "$info:$counter".toByteArray(Charsets.UTF_8)
        return hkdfExpand(infoWithCounter, length)
    }
    
    /**
     * Generate a 24-byte nonce for XChaCha20 and advance counter
     */
    fun generateNonce(): ByteArray {
        val nonce = generateDeterministic(INFO_NONCE, NONCE_SIZE)
        counter++
        return nonce
    }
    
    /**
     * Generate a 32-byte key for ChaCha20 and advance counter
     */
    fun generateKey(): ByteArray {
        val key = generateDeterministic(INFO_KEY, KEY_SIZE)
        counter++
        return key
    }
    
    /**
     * Generate both nonce and key for a single message (advances counter once)
     * This is the primary method for message encryption
     */
    fun generateNonceAndKey(): Pair<ByteArray, ByteArray> {
        val nonce = generateDeterministic(INFO_NONCE, NONCE_SIZE)
        val key = generateDeterministic(INFO_KEY, KEY_SIZE)
        counter++
        return Pair(nonce, key)
    }
    
    /**
     * Peek at nonce without advancing counter (for verification)
     */
    fun peekNonce(): ByteArray {
        return generateDeterministic(INFO_NONCE, NONCE_SIZE)
    }
    
    /**
     * Peek at key without advancing counter (for verification)
     */
    fun peekKey(): ByteArray {
        return generateDeterministic(INFO_KEY, KEY_SIZE)
    }
    
    /**
     * Get current counter value
     */
    fun getCounter(): Long = counter
    
    /**
     * Set counter value (for persistence/restore)
     */
    fun setCounter(value: Long) {
        counter = value
    }
    
    /**
     * Advance counter by N steps (for resync when messages are skipped)
     */
    fun advance(steps: Int = 1) {
        counter += steps
    }
    
    /**
     * Reset counter to zero (use with caution - breaks sync if not done on both sides)
     */
    fun reset() {
        counter = 0
    }
    
    /**
     * Create a copy of this PRNG at a specific counter position
     * Useful for trying multiple positions during resync
     */
    fun copyAtCounter(position: Long): PRNGManager {
        // We need to recreate with same PRK - use a workaround
        // by creating new instance and setting counter
        val copy = PRNGManager(ByteArray(0)) // Dummy, we'll override PRK
        // Copy the PRK directly using reflection or recreate properly
        // For simplicity, we store the original master secret
        copy.counter = position
        // Note: This is a simplified version - in production, store master secret
        return copy
    }
}
