package dataClass.SCAN

import dataClass.DNSSEC.DNSSECResult
import dataClass.MTASTS.MtaStsDnsRecordResult
import dataClass.MTASTS.MtaStsPolicy
import dataClass.TLS.TLSDataCollector
import dataClass.TLS.TLS_1_2_AllResult
import dataClass.TLS.TlsRptDnsRecordResult
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
import models.DaneCheckResult

@Serializable
data class ScanResultProvider(val scanTime: Instant,
                              val scanData: List<ScanData>,

                              val tlsCertTest : List<TLSDataCollector>,

                              val tls12Test : List<TLS_1_2_AllResult>,
                              val dnssecDomain: List<DNSSECResult>,
                              val dnssecMX: List<DNSSECResult>,
                              val daneCheckResult: List<DaneCheckResult>,

                              val mtaStsDnsRecordResult: List<MtaStsDnsRecordResult>,
                              val mtaStsPolicyResult: List<MtaStsPolicy>,

                              val tlsRptDnsRecordResult: List<TlsRptDnsRecordResult>)