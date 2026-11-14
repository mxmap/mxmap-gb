package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing

import emailtest.dataClassEvaluator.forJSON.DataTransport.aggDataTransportMetadata
import emailtest.dataClassScanData.DNSSEC.DNSSECResult
import kotlinx.serialization.Serializable

@Serializable
data class aggDomainAntiSpoofing(

    val domain: String,
    val aggDomainAntiSpoofingMetadata: aggAntiSpoofingMetadata,

    val dnssecResult: aggDnssecDataAntiSpoofing? = null,
    val aggDmarcResult: aggDmarcResult? = null,

    val aggSpfResult: aggSpfResult? = null,
    val dkimResult : String? = null

)