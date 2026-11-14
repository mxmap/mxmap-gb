package emailtest.dataClassEvaluator.result

import emailtest.dataClassEvaluator.forJSON.externalDependency
import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.aggDomainAntiSpoofing
import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.outDmarcReportingDomain

data class aggDomainAntiSpoofingResult(

    val aggDomainAntiSpoofing: aggDomainAntiSpoofing,
    val externalDependencyList: List<externalDependency>,
    val dmarcReportingList : List<outDmarcReportingDomain>

)