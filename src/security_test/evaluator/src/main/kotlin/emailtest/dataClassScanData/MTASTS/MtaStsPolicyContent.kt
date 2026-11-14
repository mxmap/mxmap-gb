package emailtest.dataClassScanData.MTASTS

import emailtest.dataClassEvaluator.forJSON.DataTransport.MTASTS.MtaStsPolicyObject
import kotlinx.serialization.Serializable

@Serializable
data class MtaStsPolicyContent(
                               val rawPolicy: String?,
                               val errorType: String?,
                                val policyData: MtaStsPolicyObject?

)