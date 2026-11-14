package emailtest.dataClassEvaluator.result

import emailtest.analysis.results.DaneResult
import emailtest.analysis.results.TlsResult
import emailtest.dataClassScanData.DKIM.DKIMResult
import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.DMARC.DMARCPolicy
import emailtest.dataClassScanData.DNSSEC.DNSSECResult
import emailtest.dataClassScanData.MTASTS.MtaStsDnsRecordResult
import emailtest.dataClassScanData.MTASTS.MtaStsPolicy
import emailtest.dataClassScanData.SCAN.ScanData
import emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.SPF.SPFResult
import emailtest.dataClassScanData.TLS.TLSDataCollector
import emailtest.dataClassScanData.TLS.TLS_1_2_AllResult
import emailtest.dataClassScanData.TLS.TlsRptDnsRecordResult


data class ResultDatabaseRow(
    val addressObj: ScanData,

    val daneResult: DaneResult,
    val tlsVersionRangeResult: TlsResult,
    //val dssResult: DssResult?,


    val tls12Test : TLS_1_2_AllResult,

    val dmarcResult: DMARCPolicy,
    val spfResult: SPFResult,
    val dkimResult: DKIMResult,


    val dnssecDomain: DNSSECResult,
    val dnssecMX: DNSSECResult,


    val mtaStsDnsRecordResult: MtaStsDnsRecordResult,
    val mtaStsPolicy: MtaStsPolicy?,
    val tlsRptDnsRecordResult: TlsRptDnsRecordResult,
    val tlsCertResult: TLSDataCollector

) {




}

data class ResultDatabaseRowDomain(
    val addressObj: ScanData,

    val daneResult: DaneResult?,
    val tlsVersionRangeResult: TlsResult?,
    //val dssResult: DssResult?,


    val tls12Test : TLS_1_2_AllResult?,

    val dmarcResult: DMARCPolicy,
    val spfResult: SPFResult,
    val dkimResult: DKIMResult,


    val dnssecDomain: DNSSECResult,
    val dnssecMX: DNSSECResult?,


    val mtaStsDnsRecordResult: MtaStsDnsRecordResult,
    val mtaStsPolicy: MtaStsPolicy?,
    val tlsRptDnsRecordResult: TlsRptDnsRecordResult,
    val tlsCertResult: TLSDataCollector?

) {


    fun getNotNull(): ResultDatabaseRow?  {

        if(daneResult != null &&
            tls12Test != null &&
            tlsVersionRangeResult != null &&


            dnssecMX != null &&

            //mtaStsPolicy != null && -> Darf als einzige Ausnahme null sein!

            tlsCertResult != null) {

            return ResultDatabaseRow(
                addressObj,

                daneResult,
                tlsVersionRangeResult ,
                tls12Test ,

                dmarcResult,
                spfResult,
                dkimResult,

                dnssecDomain ,
                dnssecMX ,

                mtaStsDnsRecordResult ,
                mtaStsPolicy,

                tlsRptDnsRecordResult,
                tlsCertResult
            )

        }
        return null
    }


}



data class ResultDatabaseRowNullable(
    val addressObj: ScanData,

    val daneResult: DaneResult?,
    val tlsVersionRangeResult: TlsResult?,

    val tls12Test : TLS_1_2_AllResult?,

    val dmarcResult: DMARCPolicy?,
    val spfResult: SPFResult?,
    val dkimResult: DKIMResult?,


    val dnssecDomain: DNSSECResult?,
    val dnssecMX: DNSSECResult?,


    val mtaStsDnsRecordResult: MtaStsDnsRecordResult?,
    val mtaStsPolicy: MtaStsPolicy?,
    val tlsRptDnsRecordResult: TlsRptDnsRecordResult?,
    val tlsCertResult: TLSDataCollector?

) {


    fun getNotNullDomain(): ResultDatabaseRowDomain?  {

        if(
            dmarcResult != null &&
            spfResult != null &&
            dkimResult != null &&

            dnssecDomain != null &&

            mtaStsDnsRecordResult != null &&
            tlsRptDnsRecordResult != null) {

            return ResultDatabaseRowDomain(
                addressObj,

                daneResult,
                tlsVersionRangeResult ,
                tls12Test ,

                dmarcResult,
                spfResult,
                dkimResult,

                dnssecDomain ,
                dnssecMX ,

                mtaStsDnsRecordResult ,
                mtaStsPolicy,

                tlsRptDnsRecordResult,
                tlsCertResult
            )

        }
        return null
    }




}


