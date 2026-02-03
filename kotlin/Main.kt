package compression

import java.io.File

fun main() {
    println("Kotlin Compression Algorithm Demo")
    
    val compressor = TextCompressor("models/kotlin_vocab.json")
    
    // Sample training data
    val trainingTexts = listOf(
        "The quick brown fox jumps over the lazy dog.",
        "To be or not to be, that is the question.",
        "I love coding in Kotlin because it is concise and safe.",
        "Arithmetic coding is a form of entropy encoding used in lossless data compression."
    )

    // Train
    if (!File("models/kotlin_vocab.json").exists()) {
        compressor.train(trainingTexts, minFrequency = 1)
    } else {
        println("Using existing vocabulary.")
    }

    // Compress
    val textToCompress = "The quick brown fox jumps over the lazy dog. Arithmetic coding is concise."
    println("\nOriginal: $textToCompress")
    
    val compressed = compressor.compress(textToCompress)
    println("Compressed size: ${compressed.size} bytes")
    println("Original size: ${textToCompress.toByteArray().size} bytes")
    
    // Decompress
    val decompressed = compressor.decompress(compressed)
    println("Decompressed: $decompressed")

    if (textToCompress.lowercase().replace(Regex("[^a-z ]"), "") == 
        decompressed.lowercase().replace(Regex("[^a-z ]"), "")) {
        println("\nSUCCESS: Decompression matches original (ignoring case/punctuation nuances)")
    } else {
        println("\nWARNING: Decompression mismatch!")
        println("Expected: $textToCompress")
        println("Got:      $decompressed")
    }
}
