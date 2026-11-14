package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing

import kotlinx.serialization.Serializable

@Serializable
data class aggDmarcReportingData(

    val reportDomainCount: Int,

    val reportRuaAndRufCount: Int,
    val reportRuaOnlyCount: Int,
    val reportRufOnlyCount: Int,

    val rufAddressCount: Int,
    val ruaAddressCount: Int,

    val externalDomainCount: Int,
    val externalDomainValidatedCount: Int,
    val externalReportAllDNSSEC: Int

)
