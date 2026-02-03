package com.frogobox.appkeyboard.ui.keyboard.securemessaging

import android.content.Context
import android.util.AttributeSet
import android.view.LayoutInflater
import android.widget.LinearLayout
import com.frogobox.appkeyboard.databinding.KeyboardSecureMessagingBinding
import com.frogobox.appkeyboard.crypto.CryptoService
import com.frogobox.libkeyboard.common.core.BaseKeyboard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Secure Messaging Keyboard with Compression + Encryption
 * 
 * Features:
 * - Compress + Encrypt input field text
 * - Decrypt + Decompress received messages
 * - Manual contact setup with shared passphrase
 * - PRNG-based deterministic key derivation
 */
class SecureMessagingKeyboard(
    context: Context,
    attrs: AttributeSet?,
) : BaseKeyboard<KeyboardSecureMessagingBinding>(context, attrs) {

    private var currentContactId: String? = null

    override fun setupViewBinding(inflater: LayoutInflater, parent: LinearLayout): KeyboardSecureMessagingBinding {
        return KeyboardSecureMessagingBinding.inflate(LayoutInflater.from(context), this, true)
    }

    override fun initUI() {
        super.initUI()
        binding.apply {
            tvToolbarTitle.text = "Secure Messaging"
            
            btnSetupContact.setOnClickListener {
                showContactSetupDialog()
            }
            
            btnEncryptCompress.setOnClickListener {
                encryptAndCompressCurrentText()
            }
            
            btnDecryptDecompress.setOnClickListener {
                decryptAndDecompressCurrentText()
            }
            
            updateContactStatus()
        }
    }

    private fun showContactSetupDialog() {
        // For now, use default contact "alice" with simple passphrase
        // In Phase 2, this will show a proper dialog
        val contactId = "alice"
        val passphrase = "our-shared-secret-key-2024"
        
        CryptoService.setupContactWithPassphrase(contactId, passphrase)
        currentContactId = contactId
        
        binding.tvStatus.text = "[OK] Contact '$contactId' setup complete"
        updateContactStatus()
    }

    private fun updateContactStatus() {
        val contactId = currentContactId
        if (contactId != null && CryptoService.hasContact(contactId)) {
            binding.btnSetupContact.text = "Contact: $contactId"
            binding.btnEncryptCompress.isEnabled = true
            binding.btnDecryptDecompress.isEnabled = true
            
            val counter = CryptoService.getCounter(contactId)
            binding.tvContactInfo.text = "PRNG Counter: $counter"
        } else {
            binding.btnSetupContact.text = "Setup Contact"
            binding.btnEncryptCompress.isEnabled = false
            binding.btnDecryptDecompress.isEnabled = false
            binding.tvContactInfo.text = "No contact setup"
        }
    }

    private fun encryptAndCompressCurrentText() {
        val contactId = currentContactId ?: run {
            binding.tvStatus.text = "[ERROR] No contact selected"
            return
        }
        
        val currentText = currentInputConnection?.let { inputConnection ->
            val extracted = inputConnection.getExtractedText(
                android.view.inputmethod.ExtractedTextRequest(), 
                0
            )
            extracted?.text?.toString() ?: ""
        } ?: ""

        if (currentText.isEmpty()) {
            binding.tvStatus.text = "No text to encrypt. Please type something in the input field."
            binding.tvStats.text = ""
            binding.tvDecryptedText.text = ""
            return
        }

        binding.tvStatus.text = "Encrypting + Compressing..."

        GlobalScope.launch(Dispatchers.Default) {
            try {
                val result = CryptoService.encryptAndCompress(currentText, contactId)

                withContext(Dispatchers.Main) {
                    if (result.success) {
                        val stats = """
                        Original size: ${result.originalSize} bytes
                        Compressed size: ${result.compressedSize} bytes
                        Encrypted size: ${result.encryptedSize} bytes
                        Compression ratio: ${String.format("%.2f", result.ratio)}x
                        Space saved: ${String.format("%.1f", result.savings)}%
                        PRNG Counter: ${result.counter}
                        """.trimIndent()

                        binding.apply {
                            tvStatus.text = "[OK] Encrypted + Compressed!"
                            tvStats.text = stats
                            tvDecryptedText.text = ""
                            
                            // Replace input field text with encrypted result
                            currentInputConnection?.apply {
                                deleteSurroundingText(currentText.length, 0)
                                commitText(result.ciphertext, 1)
                            }
                        }
                        
                        updateContactStatus()
                    } else {
                        binding.tvStatus.text = "[ERROR] ${result.error}"
                        binding.tvStats.text = ""
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    binding.tvStatus.text = "[ERROR] ${e.message}"
                }
            }
        }
    }

    private fun decryptAndDecompressCurrentText() {
        val contactId = currentContactId ?: run {
            binding.tvStatus.text = "[ERROR] No contact selected"
            return
        }
        
        val currentText = currentInputConnection?.let { inputConnection ->
            val extracted = inputConnection.getExtractedText(
                android.view.inputmethod.ExtractedTextRequest(), 
                0
            )
            extracted?.text?.toString() ?: ""
        } ?: ""

        if (currentText.isEmpty()) {
            binding.tvStatus.text = "No text to decrypt. Paste encrypted message first."
            return
        }

        binding.tvStatus.text = "Decrypting + Decompressing..."

        GlobalScope.launch(Dispatchers.Default) {
            try {
                // Try with resync for robustness
                val result = CryptoService.decryptAndDecompressWithResync(currentText, contactId)

                withContext(Dispatchers.Main) {
                    if (result.success) {
                        val stats = """
                        Compressed size: ${result.compressedSize} bytes
                        Decrypted size: ${result.decryptedSize} bytes
                        Resync attempts: ${result.attemptsUsed}
                        """.trimIndent()

                        binding.apply {
                            tvStatus.text = "[OK] Decrypted! (${result.attemptsUsed} attempts)"
                            tvStats.text = stats
                            tvDecryptedText.text = result.plaintext
                        }
                        
                        updateContactStatus()
                    } else {
                        binding.tvStatus.text = "[ERROR] ${result.error}"
                        binding.tvStats.text = ""
                        binding.tvDecryptedText.text = ""
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    binding.tvStatus.text = "[ERROR] ${e.message}"
                }
            }
        }
    }
}
