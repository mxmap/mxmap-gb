package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing

import kotlinx.serialization.Serializable

@Serializable
data class aggAntiSpoofingMetadata(

    val isValid: Boolean,
    val mxRecordCount: Int,
    val mxRecordList: List<String>

)
