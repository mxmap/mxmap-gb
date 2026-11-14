package dataClass.TLS

import kotlinx.serialization.Serializable

@Serializable
data class TlsRptDnsRecordResult(
    val domain: String,
    val hasDnsRecord: Boolean,
    val rawRecord: String?,
    var lastCname: String?,
    var errorType: String?,
    var adressList: List<TlsRptAdress>?,
    var hasADFlag: Boolean? =null

    )