package dataClass.DMARC

import kotlinx.serialization.Serializable

@Serializable
data class ParsedDMARCReportURI(val scheme: String, val address: String, val domain: String, val size_limit: String?)
