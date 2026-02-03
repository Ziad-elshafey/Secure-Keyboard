package compression

import java.io.File

fun main() {
    println("=".repeat(60))
    println("MANUAL TEXT COMPRESSION TEST")
    println("=".repeat(60))
    
    // Load the trained model
    val compressor = TextCompressor(vocabPath = "models/dailydialog_vocab.json")
    
    // Your manual input text here
    val inputText = "Hello! How are you doing today? I hope you're having a great day."
    
    println("\nOriginal Text:")
    println("  \"$inputText\"")
    println("\nOriginal Size: ${inputText.toByteArray().size} bytes")
    
    // Compress
    val compressed = compressor.compress(inputText)
    println("Compressed Size: ${compressed.size} bytes")
    
    val ratio = (compressed.size.toDouble() / inputText.toByteArray().size) * 100
    println("Compression Ratio: %.1f%%".format(ratio))
    println("Space Saved: %.1f%%".format(100 - ratio))
    
    // Decompress
    val decompressed = compressor.decompress(compressed)
    println("\nDecompressed Text:")
    println("  \"$decompressed\"")
    
    // Check if it matches
    val match = inputText.lowercase().trim() == decompressed.lowercase().trim()
    println("\nLossless: ${if (match) "✓ YES" else "✗ NO"}")
    
    if (!match) {
        println("\nDifference:")
        println("  Original:     \"$inputText\"")
        println("  Decompressed: \"$decompressed\"")
    }
}
