package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing

import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.SPF.spfGeneralData
import kotlinx.serialization.Serializable

@Serializable
data class aggSpfResult(

    val spfGeneralData: spfGeneralData,

)
