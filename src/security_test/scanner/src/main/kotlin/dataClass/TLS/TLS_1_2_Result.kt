package dataClass.TLS

import kotlinx.serialization.Serializable

@Serializable
data class TLS_1_2_Result(
    val domain: String,
    val cipherSuite: String,
    val groupName: String,
    val valid: Boolean,
    val errorMessage: String?,
    val keyAlgorithm: String? = null,
    val keyLength: Int? = null,
    val sigAlgorithm: String? = null,
    val tlsData: TLSDataCollector? = null

)
