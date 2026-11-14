package models

import kotlinx.serialization.Serializable

@Serializable
data class TestSSLResult(
    val host: String,
    val exitCode: Int,
    val consoleLog: String
)
