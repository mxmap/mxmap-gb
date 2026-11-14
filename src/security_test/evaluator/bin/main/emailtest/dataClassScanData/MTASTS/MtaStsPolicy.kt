package emailtest.dataClassScanData.MTASTS

import emailtest.dataClassScanData.TLS.TLSDataCollector
import emailtest.enums.evaluator.MtaStsGeneralPolicyErrorType
import kotlinx.serialization.Serializable

@Serializable
data class MtaStsPolicy(
    val domain: String,
    val hasValidMtaSts: Boolean,
    // Die erste Stufe, bei der ein Fehler auftritt
    val errorGenType: MtaStsGeneralPolicyErrorType?,

    val dnsEntry: emailtest.dataClassScanData.MTASTS.MtaStsPolicyDnsEntry,
    val tlsData: TLSDataCollector?,
    val policyRetrieval: emailtest.dataClassScanData.MTASTS.MtaStsPolicyRetrieval?,
    val policyData: emailtest.dataClassScanData.MTASTS.MtaStsPolicyContent?
    )