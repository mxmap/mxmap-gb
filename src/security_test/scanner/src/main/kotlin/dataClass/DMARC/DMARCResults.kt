package dataClass.DMARC

import kotlinx.serialization.Serializable
import java.util.Dictionary

@Serializable
data class DMARCResults(
    val record: String,
    val valid: Boolean,
    val error: String?,
    val tags: Map<String, DMARCTagValue>?,
    val ruaURIList: List<ParsedDMARCReportURI>?,
    val rufURIList: List<ParsedDMARCReportURI>?
)