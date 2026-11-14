package dataClass.MTASTS

import kotlinx.serialization.Serializable

@Serializable
data class MtaStsPolicyContent(
                               val rawPolicy: String?,
                               val errorType: String?,
                                val policyData: MtaStsPolicyObject?

)