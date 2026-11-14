package emailtest.dataClassScanData.SCAN


import emailtest.analysis.results.DaneResult
import emailtest.analysis.results.TlsResult
import emailtest.dataClassScanData.DKIM.DKIMResult
import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.DMARC.DMARCPolicy

import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.SPF.SPFResult
import emailtest.dataClassScanData.DNSSEC.DNSSECResult
import emailtest.dataClassScanData.MTASTS.MtaStsDnsRecordResult
import emailtest.dataClassScanData.MTASTS.MtaStsPolicy
import emailtest.dataClassScanData.TLS.TLSDataCollector
import emailtest.dataClassScanData.TLS.TLS_1_2_AllResult
import emailtest.dataClassScanData.TLS.TlsRptDnsRecordResult
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable


@Serializable
data class ScanResult(

    val scanTime: Instant,

    val mtaStsPolicyResult: List<MtaStsPolicy>,
    val mtaStsDnsRecordResult: List<MtaStsDnsRecordResult>,
    val daneCheckResult: List<DaneResult>,
    val tlsCertTest : List<TLSDataCollector>,
    val tls12Test : List<TLS_1_2_AllResult>,

    val scanData: List<ScanData>,
    val dnssecMX: List<DNSSECResult>,
    val testSSLResult: List<TlsResult>,


    // val dssResult: List<DssResult>,
    val tlsRptDnsRecordResult: List<TlsRptDnsRecordResult>,
    val dnssecDomain: List<DNSSECResult>,
    val dkimResult: List<DKIMResult>,
    val spfResult: List<SPFResult>,
    val dmarcResult: List<DMARCPolicy>

)