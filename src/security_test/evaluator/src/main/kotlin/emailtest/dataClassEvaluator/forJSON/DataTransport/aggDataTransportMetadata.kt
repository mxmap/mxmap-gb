package emailtest.dataClassEvaluator.forJSON.DataTransport

import kotlinx.serialization.Serializable

@Serializable
data class aggDataTransportMetadata(

    val isValid: Boolean,
    val mxRecordCount: Int,
    val mxRecords: List<String>,
    val invalidMxCount: Int,
    )