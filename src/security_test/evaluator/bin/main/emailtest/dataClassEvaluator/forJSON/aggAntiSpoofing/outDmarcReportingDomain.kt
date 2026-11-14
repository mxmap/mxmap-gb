package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing

import kotlinx.serialization.Serializable

@Serializable
data class outDmarcReportingDomain(
    // Domain, für welche die Policy gilt
    val policyForDomain: String,
    // Domain, wo Policy gefunden wurde
    val policyLocationDomain: String,
    // Domain, an die Reports versendet werden sollen
    var reportDomain: String,
    // rua, ruf oder beides
    var reportVia: String,
    //val scheme: String,
    var ruaAddressList: List<String> ? = null,
    var rufAddressList: List<String> ? = null,
    var usesSizeLimit: Boolean = false,

    var sameOrgDomain: Boolean = false,
    var validatedDomain: Boolean = false,
    var externalADFlag: Boolean? = null,
    var countryCodeList: String? = null
)
