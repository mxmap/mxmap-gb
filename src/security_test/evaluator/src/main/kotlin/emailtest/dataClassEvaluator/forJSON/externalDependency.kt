package emailtest.dataClassEvaluator.forJSON

import kotlinx.serialization.Serializable

@Serializable
data class externalDependency(val usedByDomain: String,
                              val dependencyType: dependencyType,
                            val hostnamePartOf: domainnamePartOf,
                            val domain: String,
                            val ipCountryCode: String? = null,)




enum class dependencyType {

    cnameMTASTSPolicy,
    cnameMtaStsDnsRecord,

    cnameTLSRPTDnsRecord,
    externalTlsReportDomain,

    externalMxDomain,

    externalDMARCReportDomain,
    cnameDmarcPolicy,

    spfInclude,
    spfRedirect,
    spfMx,
    spfA,

    CAMX,
    CASTSPolicy
}

enum class domainnamePartOf {
    domain,

    mailtoRuf,
    mailtoRua,
    mailtoRuaAndRuf,

    mailtoURI,
    httpsURI,
    mailtoAndHttpsURI,

    caIssuerName,

    invalid
}