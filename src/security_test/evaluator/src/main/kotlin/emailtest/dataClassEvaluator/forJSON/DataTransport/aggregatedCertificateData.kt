package emailtest.dataClassEvaluator.forJSON.DataTransport

import kotlinx.serialization.Serializable

@Serializable
data class aggregatedCertificateData(
    val issuerCN: String?,
    val issuerOrgName: String?,
    val issuerCountry: String?,
    val distinctSanCount: Int?,
    val sanDnsMatch : Boolean?,
    val sanStrictIdentifierMatch : Boolean?,
    val validPeriod : Long?,
    val sigAlg: String?,
    val pubKeyAlg: String?,
    val EXPubKeyLen: Int?,
)