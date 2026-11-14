import dataClass.DKIM.DKIMResult
import dataClass.DMARC.DMARCPolicy
import dataClass.DNSSEC.DNSSECResult
import dataClass.MTASTS.MtaStsDnsRecordResult
import dataClass.MTASTS.MtaStsPolicy
import dataClass.SCAN.ScanData
import dataClass.SCAN.ScanDataNotNullable
import dataClass.SCAN.ScanResult
import dataClass.SCAN.ScanResultProvider
import dataClass.SPF.SPFResult
import dataClass.TLS.TLSDataCollector
import dataClass.TLS.TLS_1_2_AllResult
import dataClass.TLS.TLS_1_2_Result
import dataClass.TLS.TlsRptDnsRecordResult
import kotlinx.datetime.Clock
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import models.DaneCheckResult
import models.TestSSLResult
import org.slf4j.LoggerFactory
import java.io.BufferedWriter
import java.io.File
import kotlin.div

class Application

fun main() {
    System.setProperty(org.slf4j.impl.SimpleLogger.DEFAULT_LOG_LEVEL_KEY, Config["LOG_LEVEL"]);

    // Notwendig wengen TLS 1 Test
    java.security.Security.setProperty(
        "jdk.tls.disabledAlgorithms",
        ""
    )

    val preferIpv4 = System.getProperty("java.net.preferIPv4Stack")
    println(">>> JVM preferIPv4Stack aktiv: $preferIpv4")

    // Optional: Harter Abbruch, falls das Flag jemals fehlen sollte
    check(preferIpv4 == "true") {
        "JVM läuft nicht mit -Djava.net.preferIPv4Stack"
    }


    val inputDirectory = File("./scanner-input")
    inputDirectory.listFiles { file -> file.isFile && file.extension.lowercase() == "json" }?.forEach { file ->

        // 1. Scan über alle in der Datei stehenden Domains
        val fileName = file.nameWithoutExtension
        val domains = Preprocessing.loadUniqueDomainsFromMailList(file.absolutePath)
        val dmarcReportingDomains = executeTestOnDomains(domains, fileName)

        // 2. Scan über alle im ersten Scan erfassten externen DMARC-Reporting-Adressen
        val fileNameExternalReporting = "ext${file.nameWithoutExtension}_extDMARC"
        executeTestOnDomains(dmarcReportingDomains, fileNameExternalReporting)
    }

}


fun executeTestOnDomains(domains: List<String>, outputJSONName: String): List<String> {

    val logger = LoggerFactory.getLogger(Application::class.java)
    val startTime = System.currentTimeMillis()
    logger.info("starting security scan for $outputJSONName")
    logger.info("loaded ${domains.size} unique domains from " + outputJSONName)


    val jsonFormatter = Json { encodeDefaults = true; prettyPrint = true }
    val outDir = File("./scanner-result")
    val outFile = File(outDir, "${outputJSONName}_scanResult.json")

    var domainsExternalDmarcReporting = listOf<String>()

    // Datei als Stream öffnen (UTF-8)
    outFile.bufferedWriter(Charsets.UTF_8).use { out ->
        // JSON Root-Objekt öffnen

        // Notwendig für TLS 1/1.1-Prüfung
        java.security.Security.setProperty("jdk.tls.disabledAlgorithms", "")

        val scanTime = Clock.System.now()
        out.write("{\n")
        out.write("  \"scanTime\": \"$scanTime\",\n")

        // MTA-STS (Abhängigkeit zwischen DNS-Ergebnissen und Policy-Scan)
        // Besonderheit: mtaStsDnsRecordResults wird für die Policy-Abfrage benötigt
        val mtaStsDnsRecordResults = Measurement.mtaStsDnsRecordTest(domains).toMutableList()
        writeAndClearCategory<MtaStsPolicy>(out, jsonFormatter, "mtaStsPolicyResult", Measurement.mtaStsPolicyTest(mtaStsDnsRecordResults).toMutableList())
        writeAndClearCategory<MtaStsDnsRecordResult>(out, jsonFormatter, "mtaStsDnsRecordResult", mtaStsDnsRecordResults) // Jetzt wegschreiben und leeren


        // Alle Mailserver-spezifischen Tests

        val mxRecords = Preprocessing.resolveMXRecords(domains).toMutableList()
        //val uniqueMXRecords = mxRecords.distinctBy { it.mxRecord }
        //logger.info("loaded ${uniqueMXRecords.size} unique mx records")

        val mxRecordsNotNull = mxRecords.filter { it.mxRecord != null }.map { it.mxRecord!! }.distinct().shuffled().toMutableList()

        // SMTP Cert TLS (input mxRecordsNotNull)
        writeAndClearCategory<TLSDataCollector>(out, jsonFormatter, "tlsCertTest", Measurement.mxTlsCertTest(mxRecordsNotNull).toMutableList())

        // DKIM
        writeAndClearCategory<DKIMResult>(out, jsonFormatter, "dkimResult", Measurement.dkimTest(domains).toMutableList())


        // DANE MX (input mxRecordsNotNull)
        writeAndClearCategory<DaneCheckResult>(out, jsonFormatter, "daneCheckResult", Measurement.daneMxTest(mxRecordsNotNull).toMutableList())

        // DNSSEC Domain
        writeAndClearCategory<DNSSECResult>(out, jsonFormatter, "dnssecDomain", Measurement.dnssecTestDomain(mxRecords).toMutableList())



        // TestSSL (TLS-Versionsscan)
        writeAndClearCategory<TestSSLResult>(out, jsonFormatter, "testSSLResult", Measurement.tlsVersionRangeTest(mxRecordsNotNull).toMutableList())


        //Jetzt werden die MX und IP spezifischen Tests gemacht
        val scanData = Preprocessing.resolveIPAddresses(mxRecords).toMutableList()

        logger.info("loaded ${scanData.size} unique combinations of domain + mx + ip")

        // scanData schreiben, Besonderheit: ScanData wird für dnssecMX benötigt
        writeAndClearCategory<ScanData>(out, jsonFormatter, "scanData", scanData, clearListAfterWrite = false)

        // DNSSEC MX
        writeAndClearCategory<DNSSECResult>(out, jsonFormatter, "dnssecMX", Measurement.dnssecTestMXHosts(scanData).toMutableList())

        // TLS-Versionsrange-Scan

        /*
        val uniqueMXAndIP =
            scanData.distinctBy { it.mxRecord + it.ipAddress }.filter { it.mxRecord != null && it.ipAddress != null }
                .map { ScanDataNotNullable(it.domain, it.mxRecord!!, it.ipAddress!!) }.toMutableList()
        logger.info("loaded ${uniqueMXAndIP.size} unique combinations of mx + ip")

        scanData.clear()

        // Key Mailserver -> Value: (Menge an zugehörigen IPs)
        val groupedMX = uniqueMXAndIP.groupBy { it.mxRecord }.toMutableMap()
        val maxIpsForAnyMx = groupedMX.values.maxOfOrNull { it.size } ?: 0

        val interleavedScanList = mutableListOf<ScanDataNotNullable>()

        // Round-Robin  -> Verteile die MX-Hosts: nimm im ersten durchlauf jeweils die erste IP von jedem Mailserver
        // Im zweiten Durchlauf die zweite IP von jedem Mailserver usw.
        for (i in 0 until maxIpsForAnyMx) {
            for (mxList in groupedMX.values) {
                if (i < mxList.size) {
                    interleavedScanList.add(mxList[i])
                }
            }
        }
        */
        // Löschen
        //groupedMX.clear()



        //uniqueMXAndIP.clear()


        // Ab jetzt folgen nur noch Scans auf Domainebene

        // TLS RPT
        writeAndClearCategory<TlsRptDnsRecordResult>(out, jsonFormatter, "tlsRptDnsRecordResult", Measurement.tlsRptDnsRecordTest(domains).toMutableList())


        // TLS 1.2
        writeAndClearCategory<TLS_1_2_AllResult>(out, jsonFormatter, "tls12Test", Measurement.testTLS_1_2Config(mxRecordsNotNull).toMutableList())
        mxRecordsNotNull.clear()

        // SPF
        writeAndClearCategory<SPFResult>(out, jsonFormatter, "spfResult", Measurement.spfTest(domains).toMutableList())

        // DMARC
        val dmarcResults = Measurement.dmarcTest(domains)
        domainsExternalDmarcReporting = dmarcResults.externalDomains.distinct() // Externe Domains sichern
        writeAndClearCategory<DMARCPolicy>(out, jsonFormatter, "dmarcResult", dmarcResults.dmarcResults.toMutableList(), isLast = true)

        // JSON Root-Objekt schließen
        out.write("}\n")
    } // Durch den .use Block wird der Writer hier automatisch sicher geschlossen

    logger.info("security scan for $outputJSONName finished")
    logger.info("total scan time for $outputJSONName is: ${"%.2f".format((System.currentTimeMillis() - startTime) / 1000.0)} seconds")

    return domainsExternalDmarcReporting
}


// Hilfsfunktion zum direkten Streamen und anschließenden Leeren des RAMs.
inline fun <reified T> writeAndClearCategory(
    out: BufferedWriter,
    jsonFormatter: Json,
    categoryName: String,
    list: MutableList<T>,
    clearListAfterWrite: Boolean = true,
    isLast: Boolean = false
) {
    out.write("  \"$categoryName\": [\n")
    list.forEachIndexed { index, item ->
        // Jedes Element einzeln serialisieren
        val jsonStr = jsonFormatter.encodeToString(item).replace("\n", "\n    ")
        out.write("    $jsonStr")
        if (index < list.size - 1) {
            out.write(",\n")
        } else {
            out.write("\n")
        }
    }
    // Als Listenelement anlegen
    if (isLast) {
        out.write("  ]\n")
    } else {
        out.write("  ],\n")
    }

    out.flush() // Zwingt den Puffer, die Daten sofort auf die Festplatte zu schreiben

    if(clearListAfterWrite) {
        // RAM freigeben
        list.clear()
    }

}



