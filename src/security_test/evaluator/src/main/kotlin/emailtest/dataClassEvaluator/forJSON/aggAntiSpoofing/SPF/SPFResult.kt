package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.SPF

import kotlinx.serialization.Serializable

@Serializable
data class MechanismCount(
    val a: Int = 0,
    val mx: Int = 0,
    val ptr: Int = 0,
    val ip4: Int = 0,
    val ip6: Int = 0,
    val include: Int = 0,
    val exists: Int = 0
)

@Serializable
data class IncludeData(
    val domain: String,
    val dnsLookups: Int,
    val record: String,
    val voidDnsLookups: Int,
    val mCount: MechanismCount
)

@Serializable
data class RedirectData(
    val domain: String,
    val dnsLookups: Int,
    val record: String,
    val voidDnsLookups: Int,
    val mCount: MechanismCount
)

@Serializable
data class SPFResult(
    val domain: String,
    val spf_General_Data: spfGeneralData,
    val includeData: List<IncludeData> = emptyList(),
    val redirectData: List<RedirectData> = emptyList()
)


@Serializable
data class spfGeneralData(
    val valid: Boolean,
    val record: String?,
    val errorType: String?,
    val warnings: List<String>,
    val lengthWarning: Boolean,
    val oldSPFRecordWarning: Boolean,
    val dnsLookups: Int?,
    val voidDnsLookups: Int?,
    val allQualifier: String?,
    val mCount: MechanismCount,
    val redirectCount: Int?,
)
