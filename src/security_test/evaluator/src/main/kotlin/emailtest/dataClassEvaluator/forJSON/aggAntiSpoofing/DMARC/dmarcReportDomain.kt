package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.DMARC

import kotlinx.serialization.Serializable

@Serializable
data class dmarcReportDomain(
                             // Domain, für welche die Policy gilt
                             val policyForDomain: String,
                             // Domain, wo Policy gefunden wurde
                             val policyLocationDomain: String,
                             // Domain, an die Reports versendet werden sollen
                             var reportDomain: String,
                             // rua, ruf oder beides
                             var reportVia: String,
                             //val scheme: String,
                             var ruaAddressList: MutableList<ParsedDMARCReportURI> ? = null,
                             var rufAddressList: MutableList<ParsedDMARCReportURI> ? = null,
                             var sameOrgDomain: Boolean = false,
                             var validatedDomain: Boolean = false,
                            var externalADFlag: Boolean? = null,
                             var countryCodeList: String? = null
)


enum class ReportFormat(val stringText: String) {
    Rua("rua"),
    Ruf("ruf"),
    RuaAndRuf("ruaAndRuf")
}