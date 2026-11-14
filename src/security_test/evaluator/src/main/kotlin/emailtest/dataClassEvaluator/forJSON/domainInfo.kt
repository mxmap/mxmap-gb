package emailtest.dataClassEvaluator.forJSON

import emailtest.dataClassEvaluator.forJSON.DataTransport.aggDomainDataTransport
import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.aggDomainAntiSpoofing
import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.DMARC.dmarcReportDomain
import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.outDmarcReportingDomain
import kotlinx.serialization.Serializable

@Serializable
data class domainInfo(

    val domainname: String,

    val aggDomainDataTransport: aggDomainDataTransport,
    val mxData: List<MXData>,
    val mtaStsErrorList: List<MtaStsErrorEntry>,

    val aggDomainAntiSpoofing: aggDomainAntiSpoofing,
    val dmarcReportDomain: List<outDmarcReportingDomain>,

    val externalDependencyList: List<externalDependency>


)