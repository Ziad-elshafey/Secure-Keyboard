package com.frogobox.appkeyboard.data.repository.compression

import android.content.Context
import com.frogobox.appkeyboard.MainApp
import com.frogobox.appkeyboard.data.repository.compression.custom.TextCompressor

object CompressionService {
    
    private val compressor: TextCompressor by lazy {
        TextCompressor().apply {
            try {
                val context = MainApp.getContext()
                val vocabContent = context.assets.open("dailydialog_vocab.json").bufferedReader().use { it.readText() }
                loadVocab(vocabContent)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    /**
     * Compress text using custom Kotlin algorithm (Arithmetic Coding)
     */
    fun compress(text: String): ByteArray {
        if (text.isEmpty()) return byteArrayOf()
        
        return try {
            compressor.compress(text)
        } catch (e: Exception) {
            // If compression fails, return original bytes as fallback
            text.toByteArray(Charsets.UTF_8)
        }
    }
    
    /**
     * Decompress bytes back to text
     */
    fun decompress(compressedBytes: ByteArray): String {
        if (compressedBytes.isEmpty()) return ""
        
        return try {
            compressor.decompress(compressedBytes)
        } catch (e: Exception) {
            // If decompression fails, treat as plain UTF-8 text fallback
            String(compressedBytes, Charsets.UTF_8)
        }
    }
    
    /**
     * Get compression ratio (original_size / compressed_size)
     */
    fun getCompressionRatio(originalSize: Int, compressedSize: Int): Float {
        return if (compressedSize > 0) {
            originalSize.toFloat() / compressedSize
        } else {
            1.0f
        }
    }
    
    /**
     * Get space savings percentage
     */
    fun getSavingsPercent(originalSize: Int, compressedSize: Int): Float {
        return if (originalSize > 0) {
            (1 - compressedSize.toFloat() / originalSize) * 100
        } else {
            0f
        }
    }
}
