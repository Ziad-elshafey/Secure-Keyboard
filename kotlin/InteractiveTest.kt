package compression

import java.io.File

fun main() {
    println("=".repeat(60))
    println("INTERACTIVE TEXT COMPRESSION TEST")
    println("=".repeat(60))
    
    // Load the trained model - using a high-quality global standard English vocabulary
    val compressor = TextCompressor(vocabPath = "../models/standard_english_vocab.json")
    println("\nModel loaded successfully!")
    println("Type 'exit' to quit\n")
    
    while (true) {
        print("Enter text to compress: ")
        val inputText = readLine() ?: break
        
        if (inputText.trim().lowercase() == "exit") {
            println("Goodbye!")
            break
        }
        
        if (inputText.trim().isEmpty()) {
            continue
        }
        
        try {
            // Compress
            val compressed = compressor.compress(inputText)
            val originalSize = inputText.toByteArray().size
            val ratio = (compressed.size.toDouble() / originalSize) * 100
            
            println("\n  Original Size:    $originalSize bytes")
            println("  Compressed Size:  ${compressed.size} bytes")
            println("  Compression:      %.1f%% (saved %.1f%%)".format(ratio, 100 - ratio))
            
            // Decompress
            val decompressed = compressor.decompress(compressed)
            
            // Check match
            val match = inputText.lowercase().trim() == decompressed.lowercase().trim()
            println("  Lossless:         ${if (match) "✓ YES" else "✗ NO"}")
            
            if (!match) {
                println("  Decompressed:     \"$decompressed\"")
            }
            println()
            
        } catch (e: Exception) {
            println("  Error: ${e.message}\n")
        }
    }
}
