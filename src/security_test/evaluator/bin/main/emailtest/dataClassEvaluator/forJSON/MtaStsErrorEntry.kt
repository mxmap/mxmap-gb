package emailtest.dataClassEvaluator.forJSON

import emailtest.enums.evaluator.MtaStsGeneralPolicyErrorType
import kotlinx.serialization.Serializable

@Serializable
data class MtaStsErrorEntry(
    val scope: Scope,
    val domainname: String,
    val generalErrorType: MtaStsGeneralPolicyErrorType?,
    val detailedErrorType: String? = null
)

enum class Scope {
    domain,
    mxHost
}