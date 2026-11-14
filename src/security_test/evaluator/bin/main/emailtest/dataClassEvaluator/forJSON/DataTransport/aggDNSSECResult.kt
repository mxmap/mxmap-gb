package emailtest.dataClassEvaluator.forJSON.DataTransport

import kotlinx.serialization.Serializable

@Serializable
data class aggDNSSECResultDataTransport(

    val domainDNSSEC: Boolean,
    val domainDNSSECPubResolver: Boolean,
    val domainDNSSECLocalResolver: Boolean,

    val mxAllDNSSEC: Boolean,
    val mxAtLeastOneDNSSEC: Boolean,

    val mtaStsDNSRecordDNSSEC: Boolean?,
    val mtaStsPolicyRecordDNSSEC: Boolean?,

    val tlsRptDNSSEC: Boolean?,

    )
