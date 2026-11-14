package emailtest.dataClassEvaluator.forJSON.DataTransport

import kotlinx.serialization.Serializable

@Serializable
data class MtaStsPolicyValidationResult(
    val allMtaValid: Boolean, val atLeastOneMtaValid: Boolean,
    val mtaInvalidTlsCount: Int,
    val mtaNotInPolicyCount: Int,
    val mtaValidCount: Int,
    val mtaValidCountList: List<String>
                                  )