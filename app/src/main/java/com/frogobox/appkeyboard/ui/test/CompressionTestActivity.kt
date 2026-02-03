package com.frogobox.appkeyboard.ui.test

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.frogobox.appkeyboard.R
import com.frogobox.appkeyboard.data.repository.compression.CompressionService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class CompressionTestActivity : AppCompatActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_compression_test)
        
        val inputText = findViewById<EditText>(R.id.input_text)
        val btnCompress = findViewById<Button>(R.id.btn_compress)
        val outputText = findViewById<TextView>(R.id.output_text)
        
        btnCompress.setOnClickListener {
            val text = inputText.text.toString()
            if (text.isEmpty()) {
                outputText.text = "Please enter text"
                return@setOnClickListener
            }
            
            lifecycleScope.launch(Dispatchers.Default) {
                val originalBytes = text.toByteArray(Charsets.UTF_8)
                val compressed = CompressionService.compress(text)
                val ratio = CompressionService.getCompressionRatio(originalBytes.size, compressed.size)
                val savings = CompressionService.getSavingsPercent(originalBytes.size, compressed.size)
                val decompressed = CompressionService.decompress(compressed)
                val verified = decompressed == text
                
                withContext(Dispatchers.Main) {
                    outputText.text = """
═══════════════════════════════════════
COMPRESSION STATISTICS
═══════════════════════════════════════
Original bytes: ${originalBytes.size}
Compressed bytes: ${compressed.size}
Compression ratio: ${String.format("%.2f", ratio)}x
Space savings: ${String.format("%.1f", savings)}%
Verified: ${if (verified) "✓ Yes" else "✗ No"}

═══════════════════════════════════════
ORIGINAL TEXT
═══════════════════════════════════════
$text

═══════════════════════════════════════
DECOMPRESSED TEXT
═══════════════════════════════════════
$decompressed
                    """.trimIndent()
                }
            }
        }
    }
}
