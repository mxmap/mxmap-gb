package emailtest.dataClassScanData.SCAN


import emailtest.analysis.results.DaneResult
import emailtest.dataClassScanData.DNSSEC.DNSSECResult
import emailtest.dataClassScanData.MTASTS.MtaStsDnsRecordResult
import emailtest.dataClassScanData.MTASTS.MtaStsPolicy
import emailtest.dataClassScanData.TLS.TLSDataCollector
import emailtest.dataClassScanData.TLS.TLS_1_2_AllResult
import emailtest.dataClassScanData.TLS.TlsRptDnsRecordResult
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable


@Serializable
data class ScanResultProvider(val scanTime: Instant,
                              val scanData: List<emailtest.dataClassScanData.SCAN.ScanData>,

                              val tlsCertTest : List<TLSDataCollector>,

                              val tls12Test : List<TLS_1_2_AllResult>,
                              val dnssecDomain: List<DNSSECResult>,
                              val dnssecMX: List<DNSSECResult>,
                              val daneCheckResult: List<DaneResult>,

                              val mtaStsDnsRecordResult: List<MtaStsDnsRecordResult>,
                              val mtaStsPolicyResult: List<MtaStsPolicy>,

                              val tlsRptDnsRecordResult: List<TlsRptDnsRecordResult>)