package emailtest

import Config
import emailtest.analysis.*
import emailtest.analysis.results.TlsResult
import emailtest.dataClassEvaluator.result.ResultDatabaseRow
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
import emailtest.analysis.results.*
import emailtest.analysis.results.supportsTlsVersion
import emailtest.dataClassEvaluator.forJSON.domainInfo
import emailtest.dataClassEvaluator.result.ResultDatabaseRowNullable
import emailtest.dataClassScanData.SCAN.findDaneResult
import emailtest.dataClassScanData.SCAN.findDkimResult
import emailtest.dataClassScanData.SCAN.findDmarcResult
import emailtest.dataClassScanData.SCAN.findDnssecDomainResult
import emailtest.dataClassScanData.SCAN.findDnssecMxResult
import emailtest.dataClassScanData.SCAN.findMtaStsDnsResult
import emailtest.dataClassScanData.SCAN.findMtaStsPolicyResult
import emailtest.dataClassScanData.SCAN.findSpfResult
import emailtest.dataClassScanData.SCAN.findTLS_1_2_Result
import emailtest.dataClassScanData.SCAN.findTlsCertResult
import emailtest.dataClassScanData.SCAN.findTlsRptDnsResult

import emailtest.dataClassScanData.SCAN.findTlsVersionRangeResult
import kotlinx.serialization.json.Json
import java.io.File
import kotlinx.serialization.encodeToString

fun main(args: Array<String>) {
    System.setProperty(org.slf4j.impl.SimpleLogger.DEFAULT_LOG_LEVEL_KEY, Config["LOG_LEVEL"])

    val inputDirectory = File("./evaluator-input")
    println("Das Programm sucht hier: ${inputDirectory.absolutePath}")

    inputDirectory.listFiles { file -> file.isFile &&
            !file.nameWithoutExtension.endsWith("ResultReporting")
            && file.extension.lowercase() == "json" }?.forEach { file ->
        // load raw data
        val scanResult = loadScanResult(file.absolutePath)
        val fileName = file.nameWithoutExtension
        RunEvaluation.logger.info("loaded scan result from $fileName")

        val addresses = scanResult.scanData
        val daneResults = scanResult.daneCheckResult
        val tlsResults = scanResult.testSSLResult

        val tlsCertTestResults = scanResult.tlsCertTest
        val mtaStsDnsRecordResults = scanResult.mtaStsDnsRecordResult
        val mtaStsPolicyResults = scanResult.mtaStsPolicyResult
        val tlsRptDnsRecordResults = scanResult.tlsRptDnsRecordResult

        val dnssecDomainResults = scanResult.dnssecDomain
        val dnssecMXResults = scanResult.dnssecMX
        val tls_1_2_Results = scanResult.tls12Test

        val dmarcResults = scanResult.dmarcResult
        val spfResults = scanResult.spfResult
        val dkimResults = scanResult.dkimResult

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
                it.findTlsCertResult(tlsCertTestResults)
            )
        }

        // filter valid test results
        val validData =
            data.filter { it.isTLSValid() && it.isDANEValid() && it.mxrecordName != null && it.ipAddress != null }
        */

        val dataAddress = addresses.map {
            ResultDatabaseRowNullable(
                it,
                it.findDaneResult(daneResults),
                it.findTlsVersionRangeResult(tlsResults),
                it.findTLS_1_2_Result(tls_1_2_Results),

                it.findDmarcResult(dmarcResults),
                it.findSpfResult(spfResults),
                it.findDkimResult(dkimResults),

                it.findDnssecDomainResult(dnssecDomainResults),
                it.findDnssecMxResult(dnssecMXResults),

                it.findMtaStsDnsResult(mtaStsDnsRecordResults),
                it.findMtaStsPolicyResult(mtaStsPolicyResults),
                it.findTlsRptDnsResult(tlsRptDnsRecordResults),

                it.findTlsCertResult(tlsCertTestResults),
            )
        }

        // Beachte nur vollständige Datensätze
        val validResults = dataAddress.filterNotNull()


        val domainInfoNew = createDomainInfo(validResults)

        // Ausgabe als JSON
        val jsonFormatter = Json { encodeDefaults = true; prettyPrint = true }

        val outFile = File("./evaluator-result/" + fileName.substringBefore('_') + "_domainInfoList.json")

        outFile.bufferedWriter(Charsets.UTF_8).use { out ->
            out.write("[\n")

            // Liste in 200er Blöcke zerteilen
            val chunks = domainInfoNew.chunked(2)

            chunks.forEachIndexed { chunkIndex, batch ->
                batch.forEachIndexed { itemIndex, domainInfo ->
                    // Jede domainInfo serialisieren
                    val jsonStr = jsonFormatter.encodeToString(domainInfo).replace("\n", "\n  ")
                    out.write("  $jsonStr")


                    if (!(chunkIndex == chunks.size - 1 && itemIndex == batch.size - 1)) {
                        out.write(",\n")
                    } else {
                        out.write("\n")
                    }
                }
                out.flush()
            }

            out.write("]\n") // JSON Array schließen
        }

        RunEvaluation.logger.info("finished scan result from $fileName (database written)")
        /*
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
            */
        // save results
        // === NEU: statt Auswertung die Datenbank direkt speichern ===
	//val jsonFormatter = Json { prettyPrint = true }
	//val dbJson = jsonFormatter.encodeToString<List<DatabaseRow>>(data)
	//writeJSONFile(dbJson, "./evaluator-result/" + fileName.substringBefore('_') + "_database.json")
	//writeJSONFile(dbJson, "./evaluator-result/" + fileName.substringBefore('_') + "_database.json")
	//RunEvaluation.logger.info("finished scan result from $fileName (database written)")
    }
    RunEvaluation.logger.info("evaluation finished")
}


