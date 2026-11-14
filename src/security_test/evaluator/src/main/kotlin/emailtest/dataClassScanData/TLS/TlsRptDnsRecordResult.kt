package emailtest.dataClassScanData.TLS

import kotlinx.serialization.Serializable

@Serializable
data class TlsRptDnsRecordResult(
    val domain: String,
    val hasDnsRecord: Boolean,
    val rawRecord: String?,
    var lastCname: String?,
    var errorType: String?,

    // val statt var: Das ist absichtlich anders als beim Scanner
    // , da hier die Liste auch nicht geändert wird
    val adressList: List<TlsRptAdress>?,

    var hasADFlag: Boolean? =null

)