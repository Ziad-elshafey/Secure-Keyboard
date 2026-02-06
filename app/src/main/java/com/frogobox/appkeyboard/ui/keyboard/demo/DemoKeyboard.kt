package com.frogobox.appkeyboard.ui.keyboard.demo

import android.content.Context
import android.util.AttributeSet
import android.view.LayoutInflater
import android.widget.LinearLayout
import com.frogobox.appkeyboard.databinding.KeyboardDemoBinding
import com.frogobox.appkeyboard.crypto.XChaCha20Poly1305
import com.frogobox.appkeyboard.data.remote.BackendApiService
import com.frogobox.appkeyboard.data.remote.UploadRequest
import com.frogobox.libkeyboard.common.core.BaseKeyboard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import android.util.Base64
import java.security.SecureRandom

/**
 * Demo Keyboard - Standalone demo of backend integration
 * 
 * No contact setup required - uses random keys for demo purposes
 * Flow: Compress → Encrypt → Upload → Receive Decoy Text
 */
class DemoKeyboard(
    context: Context,
    attrs: AttributeSet?,
) : BaseKeyboard<KeyboardDemoBinding>(context, attrs) {

    private val apiService: BackendApiService by lazy { BackendApiService.create() }

    override fun setupViewBinding(inflater: LayoutInflater, parent: LinearLayout): KeyboardDemoBinding {
        return KeyboardDemoBinding.inflate(LayoutInflater.from(context), this, true)
    }

    override fun initUI() {
        super.initUI()
        with(binding) {
            btnDemoSend.setOnClickListener {
                demoSendFlow()
            }
        }
    }

    /**
     * Demo Send Flow: Compress → Encrypt → Upload to Server → Show Decoy Text
     * Uses random keys for demo (no contact management needed)
     */
    private fun demoSendFlow() {
        val inputConnection = currentInputConnection ?: return
        
        // Get current text from input field
        val currentText = inputConnection.getExtractedText(
            android.view.inputmethod.ExtractedTextRequest(), 0
        )?.text?.toString() ?: return
        
        if (currentText.isEmpty()) {
            binding.tvStatus.text = "[ERROR] Input field is empty"
            return
        }
        
        binding.tvStatus.text = "⏳ Compressing..."
        
        GlobalScope.launch(Dispatchers.Default) {
            try {
                // Step 1: Compress
                val originalBytes = currentText.toByteArray(Charsets.UTF_8)
                // For demo: skip compression, just encrypt raw text
                val dataToEncrypt = originalBytes
                
                withContext(Dispatchers.Main) {
                    binding.tvStatus.text = "⏳ Encrypting..."
                }
                
                // Step 2: Encrypt with random key/nonce (demo only)
                val random = SecureRandom()
                val key = ByteArray(32).apply { random.nextBytes(this) }
                val nonce = ByteArray(24).apply { random.nextBytes(this) }
                
                val ciphertext = XChaCha20Poly1305.encrypt(dataToEncrypt, key, nonce)
                val ciphertextBase64 = Base64.encodeToString(ciphertext, Base64.NO_WRAP)
                
                // Convert to binary (0s and 1s) for display
                val ciphertextBinary = ciphertext.joinToString("") { byte ->
                    (byte.toInt() and 0xFF).toString(2).padStart(8, '0')
                }
                
                // Step 3: Upload to Server
                withContext(Dispatchers.Main) {
                    binding.tvStatus.text = "⏳ Uploading to server..."
                }
                
                val uploadResponse = apiService.uploadEncrypted(UploadRequest(ciphertextBase64))
                
                if (!uploadResponse.isSuccessful || uploadResponse.body() == null) {
                    withContext(Dispatchers.Main) {
                        binding.tvStatus.text = "[ERROR] Server upload failed: ${uploadResponse.code()}"
                        if (uploadResponse.code() == 404) {
                            binding.tvStats.text = "Make sure Flask backend is running on port 5000"
                        }
                    }
                    return@launch
                }
                
                val decoyText = uploadResponse.body()!!.decoyText
                val messageId = uploadResponse.body()!!.messageId
                
                // Step 4: Replace input with decoy text
                withContext(Dispatchers.Main) {
                    // Clear current text
                    inputConnection.deleteSurroundingText(currentText.length, 0)
                    
                    // Insert decoy text
                    inputConnection.commitText(decoyText, 1)
                    
                    val stats = """
                    Original: ${originalBytes.size} bytes
                    Encrypted: ${ciphertext.size} bytes
                    Message ID: ${messageId.take(8)}...
                    """.trimIndent()
                    
                    // Show binary representation (truncated for display)
                    val binaryDisplay = if (ciphertextBinary.length > 256) {
                        ciphertextBinary.take(256) + "\n... (truncated)"
                    } else {
                        ciphertextBinary
                    }
                    
                    binding.apply {
                        tvStatus.text = "✅ Success! Decoy text displayed in input field"
                        tvStats.text = stats
                        tvDecoyText.text = "🔐 Encrypted Data (Binary):\n\n$binaryDisplay\n\n📝 Decoy Text:\n\"$decoyText\""
                    }
                }
                
            } catch (e: java.net.ConnectException) {
                withContext(Dispatchers.Main) {
                    binding.tvStatus.text = "[ERROR] Cannot connect to server"
                    binding.tvStats.text = "Make sure Flask backend is running:\ncd backend && python server.py"
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    binding.tvStatus.text = "[ERROR] ${e.message}"
                    binding.tvStats.text = "Error: ${e.javaClass.simpleName}"
                }
            }
        }
    }
}
