package dataClass.TLS

import kotlinx.serialization.Serializable

@Serializable
data class TLS_1_2_AllResult(
    val domain: String,
    val resultList: Map<String, TLS_1_2_Result>
)
