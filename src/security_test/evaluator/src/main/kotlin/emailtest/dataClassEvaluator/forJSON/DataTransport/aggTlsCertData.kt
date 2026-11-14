package emailtest.dataClassEvaluator.forJSON.DataTransport

import kotlinx.serialization.Serializable

@Serializable
data class aggTlsCertData(
    val atLeastOneMxValidTlsResult: Boolean,
    val allMxValidTlsResult: Boolean
)