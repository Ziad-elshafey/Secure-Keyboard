import java.io.File

fun main() {
    val currentDir = File(".").absolutePath
    println("Current Directory: $currentDir")
    
    val trainFile = File("train.csv")
    println("train.csv: exists=${trainFile.exists()}, path=${trainFile.absolutePath}, length=${trainFile.length()}")
    
    val testFile = File("test.csv")
    println("test.csv: exists=${testFile.exists()}, path=${testFile.absolutePath}")
    
    val vocabFile = File("models/dailydialog_vocab.json")
    println("vocab file: exists=${vocabFile.exists()}, path=${vocabFile.absolutePath}")
    
    if (vocabFile.exists()) {
        println("Vocab content preview: ${vocabFile.readText().take(100)}")
    }
}
