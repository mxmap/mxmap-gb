package dataClass.SCAN

import dataClass.DKIM.DKIMResult
import dataClass.DMARC.DMARCPolicy
import dataClass.DNSSEC.DNSSECResult
import dataClass.MTASTS.MtaStsDnsRecordResult
import dataClass.MTASTS.MtaStsPolicy
import dataClass.SPF.SPFResult
import dataClass.TLS.TLSDataCollector
import dataClass.TLS.TLS_1_2_AllResult
import dataClass.TLS.TlsRptDnsRecordResult
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
import models.DaneCheckResult
import models.DssResult
import models.TestSSLResult

@Serializable
data class ScanResult(

    val scanTime: Instant,

    val mtaStsPolicyResult: List<MtaStsPolicy>,
    val mtaStsDnsRecordResult: List<MtaStsDnsRecordResult>,
    val daneCheckResult: List<DaneCheckResult>,
    val tlsCertTest : List<TLSDataCollector>,
    val tls12Test : List<TLS_1_2_AllResult>,

    val scanData: List<ScanData>,
    val dnssecMX: List<DNSSECResult>,
    val testSSLResult: List<TestSSLResult>,


   // val dssResult: List<DssResult>,
    val tlsRptDnsRecordResult: List<TlsRptDnsRecordResult>,
    val dnssecDomain: List<DNSSECResult>,
    val dkimResult: List<DKIMResult>,
    val spfResult: List<SPFResult>,
    val dmarcResult: List<DMARCPolicy>

)