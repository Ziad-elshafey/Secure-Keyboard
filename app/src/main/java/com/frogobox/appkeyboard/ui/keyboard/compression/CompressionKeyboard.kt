package com.frogobox.appkeyboard.ui.keyboard.compression

import android.content.Context
import android.util.AttributeSet
import android.util.Base64
import android.view.LayoutInflater
import android.widget.LinearLayout
import com.frogobox.appkeyboard.databinding.KeyboardCompressionBinding
import com.frogobox.appkeyboard.data.repository.compression.CompressionService
import com.frogobox.libkeyboard.common.core.BaseKeyboard
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Created for Text Compression Feature
 */

class CompressionKeyboard(
    context: Context,
    attrs: AttributeSet?,
) : BaseKeyboard<KeyboardCompressionBinding>(context, attrs) {

    private var lastCompressed: ByteArray? = null
    private var lastOriginalText: String = ""

    override fun setupViewBinding(inflater: LayoutInflater, parent: LinearLayout): KeyboardCompressionBinding {
        return KeyboardCompressionBinding.inflate(LayoutInflater.from(context), this, true)
    }

    override fun initUI() {
        super.initUI()
        binding.apply {
            tvToolbarTitle.text = "Text Compression"
            btnCompressText.setOnClickListener {
                compressCurrentText()
            }
            btnApplyCompressed.setOnClickListener {
                applyCompressedText()
            }
        }
    }

    private fun compressCurrentText() {
        val currentText = currentInputConnection?.let { inputConnection ->
            // Get the selected text or all text from the input field
            val extracted = inputConnection.getExtractedText(android.view.inputmethod.ExtractedTextRequest(), 0)
            extracted?.text?.toString() ?: ""
        } ?: ""

        if (currentText.isEmpty()) {
            binding.tvCompressionStatus.text = "No text to compress. Please type something in the input field."
            binding.tvCompressionStats.text = ""
            binding.tvDecompressedText.text = ""
            binding.btnApplyCompressed.isEnabled = false
            return
        }

        binding.tvCompressionStatus.text = "Compressing..."

        // Use GlobalScope for compression (since BaseKeyboard is not a LifecycleOwner)
        GlobalScope.launch(Dispatchers.Default) {
            try {
                val originalBytes = currentText.toByteArray(Charsets.UTF_8)
                val compressed = CompressionService.compress(currentText)
                val ratio = CompressionService.getCompressionRatio(originalBytes.size, compressed.size)
                val savings = CompressionService.getSavingsPercent(originalBytes.size, compressed.size)
                val bitsPerWord = CompressionService.getBitsPerWord(currentText, compressed.size)
                val decompressed = CompressionService.decompress(compressed)
                val verified = decompressed == currentText

                withContext(Dispatchers.Main) {
                    val stats = """
                    Original size: ${originalBytes.size} bytes
                    Compressed size: ${compressed.size} bytes
                    Compression ratio: ${String.format("%.2f", ratio)}x
                    Space saved: ${String.format("%.1f", savings)}%
                    Bits per word: ${String.format("%.2f", bitsPerWord)} bits/word
                    Verified: ${if (verified) "[OK]" else "[FAIL]"}
                    """.trimIndent()

                    // Convert compressed data to binary (0s and 1s)
                    val compressedBinary = compressed.joinToString("") { byte ->
                        (byte.toInt() and 0xFF).toString(2).padStart(8, '0')
                    }
                    
                    // Show truncated binary for display
                    val binaryDisplay = if (compressedBinary.length > 256) {
                        compressedBinary.take(256) + "\n... (truncated)"
                    } else {
                        compressedBinary
                    }

                    lastCompressed = compressed
                    lastOriginalText = currentText

                    binding.apply {
                        tvCompressionStatus.text = "[OK] Compression done - Click 'Apply' to replace text"
                        tvCompressionStats.text = stats
                        tvDecompressedText.text = "📦 Compressed Data (Binary):\n\n$binaryDisplay\n\n✅ Decompressed:\n$decompressed"
                        btnApplyCompressed.isEnabled = true
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    binding.tvCompressionStatus.text = "Error: ${e.message}"
                    binding.btnApplyCompressed.isEnabled = false
                }
            }
        }
    }

    private fun applyCompressedText() {
        if (lastCompressed == null) {
            binding.tvCompressionStatus.text = "No compressed text. Compress first."
            return
        }

        try {
            val inputConnection = currentInputConnection ?: return
            
            // Delete the original text
            inputConnection.deleteSurroundingText(lastOriginalText.length, 0)
            
            // Convert compressed data to binary (0s and 1s)
            val compressedBinary = lastCompressed!!.joinToString("") { byte ->
                (byte.toInt() and 0xFF).toString(2).padStart(8, '0')
            }
            inputConnection.commitText(compressedBinary, 1)
            
            binding.tvCompressionStatus.text = "[OK] Compressed text (Binary) applied to input field!"
        } catch (e: Exception) {
            binding.tvCompressionStatus.text = "Error: ${e.message}"
        }
    }

}
