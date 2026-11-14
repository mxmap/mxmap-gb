package emailtest

import emailtest.dataClassScanData.SCAN.ScanResult
import emailtest.models.*
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import java.io.File
import java.util.*

fun loadScanResult(filePath: String): ScanResult = loadJsonFromFile(ScanResult.serializer(), filePath)

private fun <T> loadJsonFromFile(deserializationStrategy: DeserializationStrategy<T>, filePath: String): ScanResult {
    val jsonFormatter = Json { ignoreUnknownKeys = true }
    val file = File(filePath)

    return file.inputStream().use { stream ->
        jsonFormatter.decodeFromStream<ScanResult>(stream)
    }
}
