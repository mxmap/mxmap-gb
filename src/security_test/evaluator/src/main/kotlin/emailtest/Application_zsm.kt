package emailtest

import Config
import emailtest.analysis.*
import emailtest.models.*
import emailtest.analysis.results.findDaneResult
import emailtest.analysis.results.findDssResult
import emailtest.analysis.results.findMtaStsDnsResult
import emailtest.analysis.results.findMtaStsPolicyResult
import emailtest.analysis.results.findTlsCertResult
import emailtest.analysis.results.findTlsResult
import emailtest.analysis.results.findTlsRptDnsResult
import emailtest.analysis.results.hasDkim
import emailtest.analysis.results.hasDmarc
import emailtest.analysis.results.hasGoodDmarc
import emailtest.analysis.results.hasGoodSpf
import emailtest.analysis.results.hasSpf
import emailtest.analysis.results.isDaneOk
import emailtest.analysis.results.supportsTlsVersion
import kotlinx.serialization.json.Json
import java.io.File

fun main(args: Array<String>) {
    System.setProperty(org.slf4j.impl.SimpleLogger.DEFAULT_LOG_LEVEL_KEY, Config["LOG_LEVEL"])

    val inputDirectory = File("./evaluator-input")
    inputDirectory.listFiles { file -> file.isFile && file.extension.lowercase() == "json" }?.forEach { file ->
        // load raw data
        val scanResult = loadScanResult(file.absolutePath)
        val fileName = file.nameWithoutExtension
        RunEvaluation.logger.info("loaded scan result from $fileName")

        val addresses = scanResult.scanData
        val daneResults = scanResult.daneCheckResult
        val tlsResults = scanResult.testSSLResult
        //val dssResults = scanResult.dssResult
        /*
        // transform to database row data
        val data = addresses.map {
            DatabaseRow(
                it.domain,
                it.mxRecord,
                it.ipAddress,
                it.isDaneOk(daneResults),
                it.findDaneResult(daneResults)?.consoleLog,
                it.supportsTlsVersion(tlsResults, TlsVersion.SSLV2),
                it.supportsTlsVersion(tlsResults, TlsVersion.SSLV3),
                it.supportsTlsVersion(tlsResults, TlsVersion.TLS1),
                it.supportsTlsVersion(tlsResults, TlsVersion.TLS1_1),
                it.supportsTlsVersion(tlsResults, TlsVersion.TLS1_2),
                it.supportsTlsVersion(tlsResults, TlsVersion.TLS1_3),
                it.findTlsResult(tlsResults)?.consoleLog,
                it.hasDmarc(dssResults),
                it.hasGoodDmarc(dssResults),
                it.hasSpf(dssResults),
                it.hasGoodSpf(dssResults),
                it.hasDkim(dssResults),
                it.findDssResult(dssResults)?.consoleLog,
                it.findMtaStsDnsResult(mtaStsDnsRecordResults),
                it.findMtaStsPolicyResult(mtaStsPolicyResults),
                it.findTlsRptDnsResult(tlsRptDnsRecordResults),
                it.findTlsCertResult(tlsCertTestResults),



            )
        }

        // filter valid test results
        val validData =
            data.filter { it.isTLSValid() && it.isDANEValid() && it.mxrecordName != null && it.ipAddress != null }

        // analyze
        val domainInfo = createDomainInfo(data, validData, daneResults)
        val providerInfo = createProviderInfo(validData, daneResults)
        val mxRecordInfo = createMxRecordInfo(data)

        val evaluation = RunEvaluation(
            scanResult.scanTime,
            domainInfo,
            providerInfo,
            mxRecordInfo
        )

        // save results
        val jsonFormatter = Json { prettyPrint = true }
        val resultJson = jsonFormatter.encodeToString(RunEvaluation.serializer(), evaluation)
        writeJSONFile(resultJson, "./evaluator-result/" + fileName.substringBefore('_') +"_evaluation.json")
        RunEvaluation.logger.info("finished scan result from $fileName")
    }
    RunEvaluation.logger.info("evaluation finished")

*/
    }
}