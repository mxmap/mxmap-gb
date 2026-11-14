package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.DMARC

import kotlinx.serialization.Serializable

@Serializable
data class DMARCPolicy(

                       val domain: String,

                       val generalDMARCData: dmarcGeneralData,
                       
                       var policyTags: Map<String, DMARCTagValue>? = null,

                       var reportDomains: List<dmarcReportDomain>? = null,

)


enum class DMARCFoundAt(val stringText: String) {
    AuthorDomain("AuthorDomain"),
    OrgDomain("OrgDomain"),
    PublicSuffixDomain("PublicSuffixDomain")
}