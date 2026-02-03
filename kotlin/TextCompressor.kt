package compression

import java.io.File
import kotlin.math.log2

class TextCompressor(
    private val vocabPath: String = "models/vocab.json",
    private val maxVocabSize: Int = 16384
) {
    companion object {
        const val ESCAPE_SYMBOL = 0
    }

    private var wordToId = mutableMapOf<String, Int>()
    private var idToWord = mutableMapOf<Int, String>()
    private var wordFrequencies = mutableMapOf<Int, Int>()
    private var coder: ArithmeticCoder? = null
    var entropy = 0.0
        private set

    init {
        if (File(vocabPath).exists()) {
            loadVocab()
        }
    }

    private fun tokenize(text: String): List<String> {
        // Improved tokenizer that captures ALL characters
        // Pattern: words (with apostrophes) OR single characters (including punctuation, symbols, etc.)
        val regex = Regex("[\\w']+|\\S")
        return regex.findAll(text.lowercase()).map { it.value }.toList()
    }

    fun train(texts: List<String>, minFrequency: Int = 2) {
        println("Building vocabulary...")
        
        val wordCounts = mutableMapOf<String, Int>()
        for (text in texts) {
            for (token in tokenize(text)) {
                wordCounts[token] = wordCounts.getOrDefault(token, 0) + 1
            }
        }

        // Get top words meeting frequency threshold
        val commonWords = wordCounts.toList()
            .filter { it.second >= minFrequency }
            .sortedByDescending { it.second }
            .take(maxVocabSize - 1)

        val commonWordsMap = commonWords.toMap()
        
        // Estimate frequency for unknown words
        var unknownFreq = wordCounts.filterKeys { !commonWordsMap.containsKey(it) }
            .values.sum()
        unknownFreq = maxOf(1, unknownFreq / 10)

        // Build mappings
        wordToId.clear()
        idToWord.clear()
        
        // ID 0 is reserved for ESCAPE_SYMBOL (<UNK>)
        idToWord[ESCAPE_SYMBOL] = "<UNK>"
        
        commonWords.forEachIndexed { index, (word, _) ->
            val id = index + 1
            wordToId[word] = id
            idToWord[id] = word
        }

        // Build frequency table
        wordFrequencies.clear()
        wordFrequencies[ESCAPE_SYMBOL] = unknownFreq
        for ((word, count) in commonWords) {
            wordFrequencies[wordToId[word]!!] = count
        }

        coder = ArithmeticCoder(wordFrequencies)

        // Calculate entropy
        val total = wordFrequencies.values.sum().toDouble()
        entropy = -wordFrequencies.values.filter { it > 0 }
            .sumOf { (it / total) * log2(it / total) }

        val covered = commonWords.sumOf { it.second }
        val totalWords = wordCounts.values.sum()
        val coverage = if (totalWords > 0) (covered.toDouble() / totalWords * 100) else 0.0

        println("  Vocabulary size: ${wordToId.size} words")
        println("  Entropy: %.2f bits/word".format(entropy))
        println("  Coverage: %.1f%%".format(coverage))

        saveVocab()
    }

    private fun saveVocab() {
        val file = File(vocabPath)
        file.parentFile?.mkdirs()
        
        // Simple manual JSON serialization
        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("  \"word_to_id\": {")
        sb.append(wordToId.entries.joinToString(",") { "\"${escapeJson(it.key)}\": ${it.value}" })
        sb.append("},\n")
        
        sb.append("  \"word_frequencies\": {")
        sb.append(wordFrequencies.entries.joinToString(",") { "\"${it.key}\": ${it.value}" })
        sb.append("},\n")
        
        sb.append("  \"entropy\": $entropy\n")
        sb.append("}")
        
        file.writeText(sb.toString())
        println("  Saved to: $vocabPath")
    }

    private fun loadVocab() {
        val content = File(vocabPath).readText()
        
        // Simple manual JSON parsing (assuming trusted source/format)
        // Note: usage of a real JSON library is recommended for production
        try {
            // Extract word_to_id section
            val wtiStart = content.indexOf("\"word_to_id\"")
            val wtiOpen = content.indexOf("{", wtiStart)
            val wtiClose = content.indexOf("}", wtiOpen)
            val wtiContent = content.substring(wtiOpen + 1, wtiClose)
            
            // Parse using regex to handle quoted strings properly
            val kvRegex = Regex("\"((?:[^\"\\\\]|\\\\.)*)\"\\s*:\\s*(\\d+)")
            
            wordToId.clear()
            kvRegex.findAll(wtiContent).forEach { match ->
                val key = unescapeJson(match.groupValues[1])
                val value = match.groupValues[2].toInt()
                wordToId[key] = value
            }
            
            idToWord.clear()
            idToWord[ESCAPE_SYMBOL] = "<UNK>"
            wordToId.forEach { (k, v) -> idToWord[v] = k }

            // Extract word_frequencies section
            val wfStart = content.indexOf("\"word_frequencies\"")
            val wfOpen = content.indexOf("{", wfStart)
            val wfClose = content.indexOf("}", wfOpen)
            val wfContent = content.substring(wfOpen + 1, wfClose)
            
            wordFrequencies.clear()
            kvRegex.findAll(wfContent).forEach { match ->
                val key = match.groupValues[1].toInt()
                val value = match.groupValues[2].toInt()
                wordFrequencies[key] = value
            }

            // Extract entropy
            val entStart = content.indexOf("\"entropy\"")
            val entColon = content.indexOf(":", entStart)
            val entEnd = content.indexOf("\n", entColon)
            val entVal = content.substring(entColon + 1, if (entEnd != -1) entEnd else content.lastIndexOf("}")).trim()
            entropy = entVal.toDoubleOrNull() ?: 0.0

            coder = ArithmeticCoder(wordFrequencies)
            println("Vocabulary loaded: ${wordToId.size} words, entropy: %.2f bits/word".format(entropy))

        } catch (e: Exception) {
            println("Error parsing vocab JSON: ${e.message}")
            e.printStackTrace()
        }
    }

    private fun escapeJson(s: String): String {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
    }

    private fun unescapeJson(s: String): String {
        return s.replace("\\\"", "\"").replace("\\\\", "\\")
    }

    fun compress(text: String): ByteArray {
        coder?.let { c ->
            val words = tokenize(text)
            val symbols = ArrayList<Int>()
            val unknownWords = ArrayList<String>()

            for (word in words) {
                if (wordToId.containsKey(word)) {
                    symbols.add(wordToId[word]!!)
                } else {
                    symbols.add(ESCAPE_SYMBOL)
                    unknownWords.add(word)
                }
            }

            val encoded = c.encode(symbols)
            
            val unknownData = ArrayList<Byte>()
            for (word in unknownWords) {
                val bytes = word.toByteArray(Charsets.UTF_8)
                unknownData.add(bytes.size.toByte())
                bytes.forEach { unknownData.add(it) }
            }

            // Header: [num_symbols (3 bytes), encoded_len (3 bytes)]
            val numSymbols = symbols.size
            val encodedLen = encoded.size
            
            val header = ByteArray(6)
            header[0] = ((numSymbols shr 16) and 0xFF).toByte()
            header[1] = ((numSymbols shr 8) and 0xFF).toByte()
            header[2] = (numSymbols and 0xFF).toByte()
            
            header[3] = ((encodedLen shr 16) and 0xFF).toByte()
            header[4] = ((encodedLen shr 8) and 0xFF).toByte()
            header[5] = (encodedLen and 0xFF).toByte()

            val result = ByteArray(header.size + encoded.size + unknownData.size)
            System.arraycopy(header, 0, result, 0, header.size)
            System.arraycopy(encoded, 0, result, header.size, encoded.size)
            for (i in unknownData.indices) {
                result[header.size + encoded.size + i] = unknownData[i]
            }
            
            return result
        } ?: throw IllegalStateException("No vocabulary. Call train() first.")
    }

    fun decompress(compressed: ByteArray): String {
        coder?.let { c ->
            if (compressed.size < 6) return ""

            val numSymbols = ((compressed[0].toInt() and 0xFF) shl 16) or
                             ((compressed[1].toInt() and 0xFF) shl 8) or
                             (compressed[2].toInt() and 0xFF)
            
            val encodedLen = ((compressed[3].toInt() and 0xFF) shl 16) or
                             ((compressed[4].toInt() and 0xFF) shl 8) or
                             (compressed[5].toInt() and 0xFF)

            val encodedData = ByteArray(encodedLen)
            System.arraycopy(compressed, 6, encodedData, 0, encodedLen)
            
            val unknownDataOffset = 6 + encodedLen
            val unknownData = ByteArray(compressed.size - unknownDataOffset)
            System.arraycopy(compressed, unknownDataOffset, unknownData, 0, unknownData.size)

            val symbols = c.decode(encodedData, numSymbols)
            var unknownOffset = 0
            val words = ArrayList<String>()

            for (symbol in symbols) {
                if (symbol == ESCAPE_SYMBOL) {
                    if (unknownOffset < unknownData.size) {
                        val length = unknownData[unknownOffset].toInt() and 0xFF
                        val wordBytes = ByteArray(length)
                        System.arraycopy(unknownData, unknownOffset + 1, wordBytes, 0, length)
                        words.add(String(wordBytes, Charsets.UTF_8))
                        unknownOffset += 1 + length
                    } else {
                        words.add("<UNK>")
                    }
                } else {
                    words.add(idToWord.getOrDefault(symbol, "<UNK>"))
                }
            }

            val sb = StringBuilder()
            val punctuation = ".,!?;:\"')"
            val openPunctuation = "(\"'"

            for (i in words.indices) {
                val word = words[i]
                if (i > 0 && word !in punctuation && (words[i-1].isEmpty() || words[i-1] !in openPunctuation)) {
                    sb.append(" ")
                }
                sb.append(word)
            }
            
            return sb.toString()

        } ?: throw IllegalStateException("No vocabulary loaded.")
    }
}
