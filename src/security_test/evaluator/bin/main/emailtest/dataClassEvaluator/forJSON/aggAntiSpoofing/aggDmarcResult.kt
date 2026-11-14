package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing

import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.DMARC.dmarcGeneralData
import kotlinx.serialization.Serializable

@Serializable
data class aggDmarcResult(

    val generalDMARCData: dmarcGeneralData,
    val aggDmarcReportingData: aggDmarcReportingData?,
    val dmarcTagValues: Map<String,String?>?,
    val dmarcTagValueExplicit: Map<String,Boolean?>?,

)


