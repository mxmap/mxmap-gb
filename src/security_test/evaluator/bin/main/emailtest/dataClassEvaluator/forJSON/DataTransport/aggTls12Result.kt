package emailtest.dataClassEvaluator.forJSON.DataTransport

import kotlinx.serialization.Serializable

@Serializable
data class aggTls12Result(
    val validTls12AllMta: Boolean,
    val validTls12AtLeastOneMta: Boolean,
    val partlyValidTls12AllMta: Boolean,
    val partlyValidTls12AtLeastOneMta: Boolean
)
