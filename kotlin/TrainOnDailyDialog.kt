package compression

import java.io.File
import kotlin.math.roundToInt

fun main() {
    println("=" .repeat(80))
    println("DAILY DIALOG TRAINING & EVALUATION")
    println("=".repeat(80))
    
    val baseDir = File(".").absolutePath
    println("Working directory: $baseDir")
    
    val trainFile = File("train.csv")
    val testFile = File("test.csv")
    val vocabPath = "models/dailydialog_vocab.json"
    
    // Delete old vocab to force fresh training
    val vocabFile = File(vocabPath)
    if (vocabFile.exists()) {
        vocabFile.delete()
        println("Deleted old vocabulary file")
    }
    
    // 1. Parse Training Data
    if (!trainFile.exists()) {
        println("ERROR: train.csv not found at ${trainFile.absolutePath}")
        return
    }
    
    println("\n[STEP 1] Parsing training data...")
    val trainingSentences = parseCsv(trainFile)
    println("Extracted ${trainingSentences.size} sentences from training set")
    
    if (trainingSentences.isEmpty()) {
        println("ERROR: No sentences parsed from training data!")
        return
    }
    
    // Show sample
    println("Sample sentences:")
    trainingSentences.take(3).forEach { println("  - ${it.take(60)}...") }
    
    // 2. Train Model
    println("\n[STEP 2] Training compression model...")
    val compressor = TextCompressor(vocabPath = vocabPath, maxVocabSize = 10000)
    compressor.train(trainingSentences, minFrequency = 3)
    
    // 3. Evaluate on Test Data
    if (!testFile.exists()) {
        println("WARNING: test.csv not found, skipping evaluation")
        return
    }
    
    println("\n[STEP 3] Evaluating on test data...")
    val testSentences = parseCsv(testFile)
    println("Extracted ${testSentences.size} sentences from test set")
    
    // Reload compressor with trained vocab
    val evalCompressor = TextCompressor(vocabPath = vocabPath)
    
    var totalOriginal = 0L
    var totalCompressed = 0L
    var successCount = 0
    var errorCount = 0
    
    val samples = testSentences.take(500)
    
    for (sentence in samples) {
        try {
            val compressed = evalCompressor.compress(sentence)
            val decompressed = evalCompressor.decompress(compressed)
            
            totalOriginal += sentence.toByteArray().size
            totalCompressed += compressed.size
            
            // Check match (normalize for comparison)
            val s1 = sentence.lowercase().replace(Regex("[^a-z0-9 ]"), "").trim()
            val s2 = decompressed.lowercase().replace(Regex("[^a-z0-9 ]"), "").trim()
            if (s1 == s2) successCount++ else errorCount++
        } catch (e: Exception) {
            errorCount++
        }
    }
    
    println("\n" + "=".repeat(80))
    println("RESULTS")
    println("=".repeat(80))
    println("Sentences Tested:   ${samples.size}")
    println("Success Rate:       $successCount / ${samples.size} (${(successCount.toDouble()/samples.size*100).roundToInt()}%)")
    println("Total Original:     $totalOriginal bytes")
    println("Total Compressed:   $totalCompressed bytes")
    
    if (totalOriginal > 0) {
        val ratio = (totalCompressed.toDouble() / totalOriginal) * 100
        println("Compression Ratio:  %.1f%%".format(ratio))
        println("Space Saved:        %.1f%%".format(100 - ratio))
    }
}

fun parseCsv(file: File): List<String> {
    val sentences = mutableListOf<String>()
    val lines = file.readLines().drop(1) // Skip header
    
    // Extract text from dialogue column (format: "['sentence1', 'sentence2', ...]")
    val quoteRegex = Regex("'([^']+)'|\"([^\"]+)\"")
    
    for (line in lines) {
        // Find dialogue part (before the act/emotion columns)
        val dialogEnd = line.lastIndexOf("],")
        if (dialogEnd == -1) continue
        
        val dialogPart = line.substring(0, dialogEnd)
        val matches = quoteRegex.findAll(dialogPart)
        
        for (match in matches) {
            val text = (match.groupValues[1].ifEmpty { match.groupValues[2] }).trim()
            // Filter out very short or metadata-like entries
            if (text.length > 5 && !text.startsWith("[") && !text.all { it.isDigit() || it == ' ' }) {
                sentences.add(text)
            }
        }
    }
    return sentences
}
