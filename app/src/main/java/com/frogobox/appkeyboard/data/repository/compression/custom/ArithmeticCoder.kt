package com.frogobox.appkeyboard.data.repository.compression.custom

class ArithmeticCoder(private val frequencies: Map<Int, Int>) {

    companion object {
        const val PRECISION_BITS = 32
        // Use Long to prevent overflow and handle unsigned 32-bit logic
        const val MAX_RANGE = (1L shl PRECISION_BITS) - 1
        const val HALF = 1L shl (PRECISION_BITS - 1)
        const val QUARTER = 1L shl (PRECISION_BITS - 2)
        const val THREE_QUARTERS = HALF + QUARTER
    }

    private val cumFreq = mutableMapOf<Int, Pair<Long, Long>>()
    private val totalFreq: Long

    init {
        var cumulative = 0L
        val sortedKeys = frequencies.keys.sorted()
        
        for (symbol in sortedKeys) {
            val freq = frequencies[symbol]!!.toLong()
            cumFreq[symbol] = Pair(cumulative, cumulative + freq)
            cumulative += freq
        }
        totalFreq = cumulative
    }

    fun encode(symbols: List<Int>): ByteArray {
        var low = 0L
        var high = MAX_RANGE
        var pendingBits = 0
        val bits = ArrayList<Int>()

        for (symbol in symbols) {
            if (!cumFreq.containsKey(symbol)) {
                throw IllegalArgumentException("Unknown symbol: $symbol")
            }

            val rangeSize = high - low + 1
            val (symLow, symHigh) = cumFreq[symbol]!!

            high = low + (rangeSize * symHigh) / totalFreq - 1
            low = low + (rangeSize * symLow) / totalFreq

            while (true) {
                if (high < HALF) {
                    bits.add(0)
                    repeat(pendingBits) { bits.add(1) }
                    pendingBits = 0
                } else if (low >= HALF) {
                    bits.add(1)
                    repeat(pendingBits) { bits.add(0) }
                    pendingBits = 0
                    low -= HALF
                    high -= HALF
                } else if (low >= QUARTER && high < THREE_QUARTERS) {
                    pendingBits++
                    low -= QUARTER
                    high -= QUARTER
                } else {
                    break
                }

                low = low shl 1
                high = (high shl 1) or 1
            }
        }

        // Flush remaining bits
        pendingBits++
        if (low < QUARTER) {
            bits.add(0)
            repeat(pendingBits) { bits.add(1) }
        } else {
            bits.add(1)
            repeat(pendingBits) { bits.add(0) }
        }

        // Pad to byte boundary
        while (bits.size % 8 != 0) {
            bits.add(0)
        }

        // Convert bits to bytes
        val result = ByteArray(bits.size / 8)
        for (i in result.indices) {
            var byteVal = 0
            for (j in 0 until 8) {
                byteVal = (byteVal shl 1) or bits[i * 8 + j]
            }
            result[i] = byteVal.toByte()
        }

        return result
    }

    fun decode(data: ByteArray, numSymbols: Int): List<Int> {
        // Convert bytes to bits
        val bits = ArrayList<Int>()
        for (byte in data) {
            val b = byte.toInt() and 0xFF
            for (i in 7 downTo 0) {
                bits.add((b shr i) and 1)
            }
        }

        var low = 0L
        var high = MAX_RANGE
        var value = 0L

        // Initialize value from first bits
        for (i in 0 until PRECISION_BITS) {
            val bit = if (i < bits.size) bits[i] else 0
            value = (value shl 1) or bit.toLong()
        }

        var bitIndex = PRECISION_BITS
        val symbols = ArrayList<Int>()

        for (n in 0 until numSymbols) {
            val rangeSize = high - low + 1
            val scaledValue = ((value - low + 1) * totalFreq - 1) / rangeSize

            // Find symbol
            var foundSymbol: Int? = null
            for ((symbol, range) in cumFreq) {
                val (symLow, symHigh) = range
                if (scaledValue >= symLow && scaledValue < symHigh) {
                    foundSymbol = symbol
                    break
                }
            }

            if (foundSymbol == null) break

            symbols.add(foundSymbol)
            val (symLow, symHigh) = cumFreq[foundSymbol]!!

            high = low + (rangeSize * symHigh) / totalFreq - 1
            low = low + (rangeSize * symLow) / totalFreq

            while (true) {
                if (high < HALF) {
                    // do nothing
                } else if (low >= HALF) {
                    low -= HALF
                    high -= HALF
                    value -= HALF
                } else if (low >= QUARTER && high < THREE_QUARTERS) {
                    low -= QUARTER
                    high -= QUARTER
                    value -= QUARTER
                } else {
                    break
                }

                low = low shl 1
                high = (high shl 1) or 1
                
                val nextBit = if (bitIndex < bits.size) bits[bitIndex] else 0
                value = (value shl 1) or nextBit.toLong()
                bitIndex++
            }
        }

        return symbols
    }
}
