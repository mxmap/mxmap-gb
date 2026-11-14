package emailtest.dataClassEvaluator.forJSON.DataTransport

import kotlinx.serialization.Serializable

@Serializable
data class aggDaneResult(
    val hasValidDaneAllMta: Boolean,
    val hasValidDaneAtLeastOneMta: Boolean,
    val atLeastOneMtaSupportsDane: Boolean
)
