package dataClass.MTASTS

import kotlinx.serialization.Serializable
import dataClass.TLS.TLSDataCollector
import models.enums.MtaStsGeneralPolicyErrorType

@Serializable
data class MtaStsPolicy(
    val domain: String,
    val hasValidMtaSts: Boolean,
    // Die erste Stufe, bei der ein Fehler auftritt
    val errorGenType: MtaStsGeneralPolicyErrorType?,

    val dnsEntry: MtaStsPolicyDnsEntry,
    val tlsData: TLSDataCollector?,
    val policyRetrieval: MtaStsPolicyRetrieval?,
    val policyData: MtaStsPolicyContent?
    )