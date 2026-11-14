package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.DMARC

import kotlinx.serialization.Serializable

@Serializable
data class DMARCResults(
    val record: String,
    val valid: Boolean,
    val error: String?,
    val tags: Map<String, DMARCTagValue>?,
    val ruaURIList: List<ParsedDMARCReportURI>?,
    val rufURIList: List<ParsedDMARCReportURI>?
)