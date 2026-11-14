package emailtest.dataClassScanData.MTASTS

import kotlinx.serialization.Serializable

@Serializable
data class MtaStsDnsRecordResult(
    val domain: String,
    val hasRecord: Boolean,
    val rawRecord: String?,
    var lastCname: String?,
    val errorType: String?,
    var hasADFlag: Boolean? = null,
)