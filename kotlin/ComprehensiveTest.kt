package compression

import java.io.File
import kotlin.math.roundToInt

data class TestResult(
    val name: String,
    val originalSize: Int,
    val compressedSize: Int,
    val compressionRatio: Double,
    val success: Boolean,
    val errorMessage: String = ""
)

fun main() {
    println("=".repeat(80))
    println("KOTLIN COMPRESSION ALGORITHM - COMPREHENSIVE TEST SUITE")
    println("=".repeat(80))
    
    val compressor = TextCompressor("models/kotlin_vocab.json")
    
    // Training data
    val trainingTexts = listOf(
        "The quick brown fox jumps over the lazy dog.",
        "To be or not to be, that is the question.",
        "I love coding in Kotlin because it is concise and safe.",
        "Arithmetic coding is a form of entropy encoding used in lossless data compression.",
        "Machine learning and artificial intelligence are transforming technology.",
        "Data compression reduces the size of files for efficient storage and transmission.",
        "The algorithm analyzes patterns in text to achieve better compression ratios.",
        "Software engineering requires careful planning and systematic implementation."
    )
    
    // Train or load vocabulary
    if (!File("models/kotlin_vocab.json").exists()) {
        println("\n[TRAINING PHASE]")
        compressor.train(trainingTexts, minFrequency = 1)
    } else {
        println("\n[LOADING VOCABULARY]")
        println("Using existing vocabulary from models/kotlin_vocab.json")
    }
    
    // Test cases of varying lengths
    val testCases = listOf(
        // Very short texts
        "Hello world." to "Very Short (2 words)",
        "The quick brown fox." to "Short (4 words)",
        
        // Medium texts
        "The quick brown fox jumps over the lazy dog. Arithmetic coding is concise." to "Medium (13 words)",
        "To be or not to be, that is the question. I love coding in Kotlin." to "Medium (16 words)",
        
        // Longer texts
        "The quick brown fox jumps over the lazy dog. Arithmetic coding is a form of entropy encoding used in lossless data compression. Machine learning is transforming technology." to "Long (30 words)",
        
        // Very long text
        """The quick brown fox jumps over the lazy dog. Arithmetic coding is a form of entropy encoding 
        used in lossless data compression. Machine learning and artificial intelligence are transforming 
        technology. Data compression reduces the size of files for efficient storage and transmission. 
        The algorithm analyzes patterns in text to achieve better compression ratios. Software engineering 
        requires careful planning and systematic implementation.""".replace("\n", " ").replace(Regex("\\s+"), " ") to "Very Long (60+ words)",
        
        // Repetitive text (should compress well)
        "The the the the the the the the the the." to "Repetitive (10 words)",
        "Compression compression compression is is is important important important." to "Repetitive with variety",
        
        // Text with unknown words
        "The xyzabc defghi jklmno pqrstu vwxyz." to "With unknown words",
        
        // Mixed case and punctuation
        "Hello! How are you? I am fine, thank you. The weather is nice today." to "Mixed punctuation",
        
        // Numbers and special cases
        "The algorithm processes data in 2024 with 99.9% accuracy." to "With numbers"
    )
    
    println("\n" + "=".repeat(80))
    println("RUNNING TEST CASES")
    println("=".repeat(80))
    
    val results = mutableListOf<TestResult>()
    
    for ((index, testCase) in testCases.withIndex()) {
        val (text, description) = testCase
        val testNum = index + 1
        
        println("\n[TEST $testNum/${ testCases.size}] $description")
        println("-".repeat(80))
        
        try {
            // Show original text (truncated if too long)
            val displayText = if (text.length > 100) text.take(100) + "..." else text
            println("Original: $displayText")
            
            val originalSize = text.toByteArray(Charsets.UTF_8).size
            
            // Compress
            val compressed = compressor.compress(text)
            val compressedSize = compressed.size
            
            // Decompress
            val decompressed = compressor.decompress(compressed)
            
            // Verify correctness (normalize for comparison)
            val normalizedOriginal = text.lowercase().replace(Regex("[^a-z0-9 ]"), "").replace(Regex("\\s+"), " ").trim()
            val normalizedDecompressed = decompressed.lowercase().replace(Regex("[^a-z0-9 ]"), "").replace(Regex("\\s+"), " ").trim()
            
            val success = normalizedOriginal == normalizedDecompressed
            val compressionRatio = (compressedSize.toDouble() / originalSize) * 100
            
            println("Original size:    $originalSize bytes")
            println("Compressed size:  $compressedSize bytes")
            println("Compression ratio: ${compressionRatio.roundToInt()}%")
            println("Space saved:      ${originalSize - compressedSize} bytes (${(100 - compressionRatio).roundToInt()}%)")
            println("Decompression:    ${if (success) "✓ SUCCESS" else "✗ FAILED"}")
            
            if (!success) {
                println("Expected (normalized): $normalizedOriginal")
                println("Got (normalized):      $normalizedDecompressed")
            }
            
            results.add(TestResult(description, originalSize, compressedSize, compressionRatio, success))
            
        } catch (e: Exception) {
            println("✗ ERROR: ${e.message}")
            e.printStackTrace()
            results.add(TestResult(description, 0, 0, 0.0, false, e.message ?: "Unknown error"))
        }
    }
    
    // Generate statistics
    println("\n" + "=".repeat(80))
    println("COMPREHENSIVE STATISTICS")
    println("=".repeat(80))
    
    val successfulTests = results.filter { it.success }
    val failedTests = results.filter { !it.success }
    
    println("\nOVERALL RESULTS:")
    println("  Total tests:      ${results.size}")
    println("  Successful:       ${successfulTests.size} (${(successfulTests.size.toDouble() / results.size * 100).roundToInt()}%)")
    println("  Failed:           ${failedTests.size}")
    
    if (successfulTests.isNotEmpty()) {
        val avgCompressionRatio = successfulTests.map { it.compressionRatio }.average()
        val bestCompression = successfulTests.minByOrNull { it.compressionRatio }
        val worstCompression = successfulTests.maxByOrNull { it.compressionRatio }
        val totalOriginalSize = successfulTests.sumOf { it.originalSize }
        val totalCompressedSize = successfulTests.sumOf { it.compressedSize }
        
        println("\nCOMPRESSION STATISTICS (Successful tests only):")
        println("  Average compression ratio: ${avgCompressionRatio.roundToInt()}%")
        println("  Best compression:  ${bestCompression?.compressionRatio?.roundToInt()}% (${bestCompression?.name})")
        println("  Worst compression: ${worstCompression?.compressionRatio?.roundToInt()}% (${worstCompression?.name})")
        println("  Total original size:    $totalOriginalSize bytes")
        println("  Total compressed size:  $totalCompressedSize bytes")
        println("  Overall space saved:    ${totalOriginalSize - totalCompressedSize} bytes (${((1 - totalCompressedSize.toDouble() / totalOriginalSize) * 100).roundToInt()}%)")
    }
    
    if (failedTests.isNotEmpty()) {
        println("\nFAILED TESTS:")
        failedTests.forEach { test ->
            println("  - ${test.name}: ${test.errorMessage.ifEmpty { "Decompression mismatch" }}")
        }
    }
    
    // Write detailed results to file
    val reportFile = File("test_results.txt")
    reportFile.writeText(buildString {
        appendLine("KOTLIN COMPRESSION ALGORITHM - TEST RESULTS")
        appendLine("Generated: ${java.time.LocalDateTime.now()}")
        appendLine("=".repeat(80))
        appendLine()
        
        appendLine("INDIVIDUAL TEST RESULTS:")
        appendLine("-".repeat(80))
        results.forEachIndexed { index, result ->
            appendLine("Test ${index + 1}: ${result.name}")
            appendLine("  Original size:     ${result.originalSize} bytes")
            appendLine("  Compressed size:   ${result.compressedSize} bytes")
            appendLine("  Compression ratio: ${result.compressionRatio.roundToInt()}%")
            appendLine("  Status:            ${if (result.success) "SUCCESS" else "FAILED"}")
            if (!result.success && result.errorMessage.isNotEmpty()) {
                appendLine("  Error:             ${result.errorMessage}")
            }
            appendLine()
        }
        
        appendLine("=".repeat(80))
        appendLine("SUMMARY STATISTICS")
        appendLine("=".repeat(80))
        appendLine("Total tests:      ${results.size}")
        appendLine("Successful:       ${successfulTests.size}")
        appendLine("Failed:           ${failedTests.size}")
        
        if (successfulTests.isNotEmpty()) {
            val avgCompressionRatio = successfulTests.map { it.compressionRatio }.average()
            val totalOriginalSize = successfulTests.sumOf { it.originalSize }
            val totalCompressedSize = successfulTests.sumOf { it.compressedSize }
            
            appendLine()
            appendLine("Average compression ratio: ${avgCompressionRatio.roundToInt()}%")
            appendLine("Total original size:       $totalOriginalSize bytes")
            appendLine("Total compressed size:     $totalCompressedSize bytes")
            appendLine("Overall space saved:       ${totalOriginalSize - totalCompressedSize} bytes")
        }
    })
    
    println("\n" + "=".repeat(80))
    println("Detailed results saved to: test_results.txt")
    println("=".repeat(80))
}
