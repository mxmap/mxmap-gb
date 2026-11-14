package emailtest.dataClassEvaluator.forJSON.DataTransport.MTASTS

import kotlinx.serialization.Serializable

@Serializable
data class MtaStsPolicyObject(val max_age: String?,
                              val mode: String?,
                              val mx_list: List<String>)