package emailtest.dataClassEvaluator.forJSON.DataTransport

import emailtest.dataClassEvaluator.forJSON.aggregatedTlsCertData
import emailtest.dataClassEvaluator.forJSON.DataTransport.MTASTS.MtaStsPolicyObject
import emailtest.enums.evaluator.MtaStsGeneralPolicyErrorType
import kotlinx.serialization.Serializable

@Serializable
data class MtaStsData(
    val usesMtaSts: Boolean,
    val generalErrorType: MtaStsGeneralPolicyErrorType?,

    // Zur Validierung
    val rawDnsString: String? = null,
    val cnameDnsRecord: String? = null,

    val rawPolicy: String?= null,
    val cnamePolicy: String? = null,
    var ipCountryCode: String? = null,

    val policy: MtaStsPolicyObject? = null,
    val mtaStsPolicyValidation: MtaStsPolicyValidationResult? = null,
    val policytlsData: aggregatedTlsCertData? = null,
)