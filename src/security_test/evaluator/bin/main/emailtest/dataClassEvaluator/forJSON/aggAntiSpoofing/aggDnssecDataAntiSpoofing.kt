package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing

import kotlinx.serialization.Serializable

@Serializable
data class aggDnssecDataAntiSpoofing(
    val domainDNSSEC: Boolean,
    val domainDNSSECPubResolver: Boolean,
    val domainDNSSECLocalResolver: Boolean,

)
