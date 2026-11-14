package emailtest.dataClassScanData.SCAN

import emailtest.analysis.results.DaneResult
import emailtest.analysis.results.DssResult
import emailtest.analysis.results.TlsResult
import emailtest.analysis.results.hasDkim
import emailtest.analysis.results.hasDmarc
import emailtest.analysis.results.hasGoodDmarc
import emailtest.analysis.results.hasGoodSpf
import emailtest.analysis.results.hasMtaDaneForMx
import emailtest.analysis.results.hasSpf
import emailtest.analysis.results.supportsTlsVersion
import emailtest.dataClassScanData.DKIM.DKIMResult
import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.DMARC.DMARCPolicy
import emailtest.dataClassScanData.DNSSEC.DNSSECResult
import emailtest.dataClassScanData.MTASTS.MtaStsDnsRecordResult
import emailtest.dataClassScanData.MTASTS.MtaStsPolicy
import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.SPF.SPFResult
import emailtest.dataClassScanData.TLS.TLSDataCollector
import emailtest.dataClassScanData.TLS.TLS_1_2_AllResult
import emailtest.dataClassScanData.TLS.TlsRptDnsRecordResult
import emailtest.models.TlsVersion
import kotlinx.serialization.Serializable

@Serializable
data class ScanData(val domain: String, val mxRecord: String?, val ipAddress: String?, val adFlagForMx: Boolean?, val adFlagForA: Boolean?, val ipCountryCode: String? = null)

fun List<ScanData>.getAllCountryCodes(): String { return this.mapNotNull{it.ipCountryCode ?: ""}.distinct().joinToString(", ")}

fun ScanData.findTlsVersionRangeResult(tlsResults: List<TlsResult>) = tlsResults.find { it.host == mxRecord  }

fun ScanData.supportsTlsVersion(tlsResults: List<TlsResult>, tlsVersion: TlsVersion): Boolean? =
    findTlsVersionRangeResult(tlsResults)?.supportsTlsVersion(tlsVersion)

fun ScanData.isDaneOk(daneResults: List<DaneResult>): Boolean? {
    val daneResult = findDaneResult(daneResults) ?: return null
    if (adFlagForMx == true && daneResult.hasMtaDaneForMx(mxRecord!!)) return true
    return false
}

fun ScanData.findDaneResult(daneResults: List<DaneResult>) = daneResults.find { it.host == mxRecord }

fun ScanData.findDssResult(dssResults: List<DssResult>) = dssResults.find { it.domain == domain }

fun ScanData.hasDmarc(dssResults: List<DssResult>) = findDssResult(dssResults)?.hasDmarc()

fun ScanData.hasGoodDmarc(dssResults: List<DssResult>) = findDssResult(dssResults)?.hasGoodDmarc()

fun ScanData.hasSpf(dssResults: List<DssResult>) = findDssResult(dssResults)?.hasSpf()

fun ScanData.hasGoodSpf(dssResults: List<DssResult>) = findDssResult(dssResults)?.hasGoodSpf()

fun ScanData.hasDkim(dssResults: List<DssResult>) = findDssResult(dssResults)?.hasDkim()


fun ScanData.findMtaStsDnsResult(mtaStsDnsRecordResults: List<MtaStsDnsRecordResult>) = mtaStsDnsRecordResults.find{it.domain == domain}

// Ausnahme: Wenn kein MtaStsDnsRecord erkannt wurde, wird keine Policy-Prüfung und Policy-Objekt erstellt
fun ScanData.findMtaStsPolicyResult(mtaStsPolicyResults: List<MtaStsPolicy>) = mtaStsPolicyResults.find{ it.domain == domain}

fun ScanData.findTlsRptDnsResult(tlsRptDnsRecordResults: List<TlsRptDnsRecordResult>) = tlsRptDnsRecordResults.find {it.domain == domain}

fun ScanData.findTlsCertResult(tlsCertTestResults: List<TLSDataCollector>) = tlsCertTestResults.find {it.domain == mxRecord }

fun ScanData.findDmarcResult(dmarcResults: List<DMARCPolicy>) = dmarcResults.find{it.domain == domain}

fun ScanData.findSpfResult(spfResult: List<SPFResult>) = spfResult.find{it.domain == domain}

fun ScanData.findDkimResult(dkimResult: List<DKIMResult>) = dkimResult.find {it.domain == domain}

fun ScanData.findDnssecDomainResult(dnssecResult: List<DNSSECResult>) = dnssecResult.find{it.domain == domain}


fun ScanData.findDnssecMxResult(dnssecResult: List<DNSSECResult>) = dnssecResult.find{it.domain == mxRecord}

fun ScanData.findTLS_1_2_Result(tls1_2_result: List<TLS_1_2_AllResult>) = tls1_2_result.find{it.domain == mxRecord}