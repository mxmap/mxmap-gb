import enums.DigAnswerStatus
import models.dataClass.DigResult
import java.io.File
import java.util.*
import models.dataClass.DigCmdResult
import org.slf4j.LoggerFactory

object Dig {

    fun createTmpPath(): String {
        return "/tmp/${"dig"}_${UUID.randomUUID()}"
    }

    // Prüft ob die DNS-Abfrage ungleich NOERROR entspricht
    fun digAnswer(domain: String, type: String = "A", resolver: String = Config["DNS_NAMESERVER"]): String {

        val digResult = digCmd(domain,type,resolver)
        val logLines = digResult.resultLog.split("\n")
        val header = logLines.find { it.startsWith(";; ->>HEADER<<-") }

        val adFlag = logLines.find { it.startsWith(";; flags:") }?.contains("ad") == true

        if(header != null ) {


            if( header.contains("status: NOERROR")) {

                if(adFlag) {
                    return DigAnswerStatus.NOERRORandADFlag.stringText
                }
                return DigAnswerStatus.NOERROR.stringText
            }

            if( header.contains("status: NXDOMAIN")) {
                return DigAnswerStatus.NXDOMAIN.stringText
            }


            //RCODE 2 RFC 4035
            if( header.contains("status: SERVFAIL")) {
                return DigAnswerStatus.SERVFAIL.stringText
            }

            // Anderer Headerinhalt
            return header

        }

        // Kein gültiger Headerinhalt in Ausgabe
        return DigAnswerStatus.NOHEADER.stringText
    }

    // Hauptfunktion für die DNS-Abfrage
    fun dig(domain: String, type: String = "A", resolver: String = Config["DNS_NAMESERVER"]): DigResult {
        val domainNormalized = domain.lowercase().removeSuffix(".")
        val digResult = digCmd(domainNormalized, type, resolver)

        // Rufe die neue, testbare Parsing-Methode auf
        return parseDigOutput(digResult, domainNormalized, type)
    }






    // Extrahiere je Record-Typ 1. die relevanten DNS-Einträge und 2. CNAME-Kette
    fun parseDigOutput(digCmdResult: DigCmdResult, domainNormalized: String, type: String): DigResult {

        val logLines = digCmdResult.resultLog.split("\n")

        // ad-Flag als DNSSEC-Indikator
        val adFlag = logLines.find { it.startsWith(";; flags:") }?.contains("ad") == true


        // DNS-Recordwerte extrahieren
        val beginAnswerSection = logLines.indexOfFirst { line ->
           line.contains("ANSWER SECTION", ignoreCase = true)
        }

        // DNS-Recordwerte extrahieren
        var endAnswerSection = logLines.indexOfFirst { line ->
            line.contains("Query time:", ignoreCase = true)
        }

        if (endAnswerSection == -1) {
            endAnswerSection = logLines.size
        }


        if (beginAnswerSection != -1) {
            // Filtere nach allen Antwortzeielen, die nicht leer sind
            val answerSection =
                logLines.filterIndexed { index, s -> index > beginAnswerSection && index < endAnswerSection && s.isNotBlank() }


            val targetTypeDnsRecords = mutableListOf<String>()
            val cnameRecordMapping = mutableMapOf<String,String>()

            for (dnsRecord in answerSection) {

                val recordTokens = dnsRecord.split(Regex("\\s+"))
                if(recordTokens.size < 5) { continue }

                // Erfassen der Metadaten des DNS-Records
                val recordOwnerName = recordTokens[0].removeSuffix(".")
                val recordType = recordTokens[3].uppercase()

                // DNS-Record-Inhalt extrahieren
                when(recordType) {

                    type.uppercase() -> {
                        targetTypeDnsRecords.add(cleanDNSRecordContent(dnsRecord, type))
                    }

                    // CNAME-Kette für jeweilige Domain (ownerName) erfassen
                    "CNAME" -> {
                        cnameRecordMapping[recordOwnerName] = cleanDNSRecordContent(dnsRecord, "CNAME")
                    }

                }

            }

            // Sonderfall erfassen : DNS-Records "liegen" an Alias-Domain (CNAME) -> Rekonstruiere die CNAME-Kette
            val cnameRecordChain = mutableListOf<String>()
            // Beginnend bei der angegebenen Domain
            var tempCurrentCnameOwnerDomain = domainNormalized

            while (cnameRecordMapping.containsKey(tempCurrentCnameOwnerDomain)) {

                val cnameTargetDomain = cnameRecordMapping[tempCurrentCnameOwnerDomain]

                //Füge CNAME-Domainname zu der CNAME-Kette hinzu
                if(cnameTargetDomain != null) {
                    cnameRecordChain.add(cnameTargetDomain)
                    tempCurrentCnameOwnerDomain = cnameTargetDomain

                }else {
                    break
                }

                // Absicherung gegen (theoretische) zyklische Fehlkonfigurationen
                if(cnameRecordChain.size > 100 ) break
            }

            return DigResult(targetTypeDnsRecords, cnameRecordChain, adFlag)

        }
        return DigResult(emptyList(), emptyList(), adFlag)
    }


    // Ausführen des eigentlichen Dig-Befehls
    private fun digCmd(domain: String, type: String = "A", resolver: String = Config["DNS_NAMESERVER"]): DigCmdResult {

        val logfilepath = createTmpPath()


        val pb = ProcessBuilder("timeout", "30", "dig" ,"+dnssec", "@" + resolver , domain, type)


        val logfile = File(logfilepath)
        pb.redirectOutput(ProcessBuilder.Redirect.appendTo(logfile))
        pb.redirectError(ProcessBuilder.Redirect.appendTo(logfile))
        val exitcode = pb.start().waitFor()

        val log = File(logfilepath).readText(Charsets.UTF_8)
        logfile.delete()

        return DigCmdResult(log, exitcode)
    }


    // Gesamten Inhalt eines DNS-Records unter Berücksichtigung seines Typs extrahieren
    private fun cleanDNSRecordContent(dnsRecordContent: String, type: String = "A"): String {

        // Der Record-Inhalt steht ab Index 4 bis zum Ende der Zeile: Verwerfe die Metadaten OwnerName / TTL / IN / TYPE
        val fullRecordTokens = dnsRecordContent.split(Regex("\\s+"))
        val recordData = fullRecordTokens.drop(4).joinToString(" ")

        when (type) {
            "MX" -> {
                // Mailserverpräferenzwert von der Mailserveradresse verwerfen
                val mxDNSPart = recordData.split(Regex("\\s+"))
                if(mxDNSPart.size > 1) {
                    return mxDNSPart[1].lowercase().removeSuffix(".")
                }else {
                    return mxDNSPart[0].lowercase().removeSuffix(".")
                }
            }
            "TXT" -> {
                // Sonderfall: Falls ein großer TXT-Record in mehrere Teilstrings aufgeteilt ist
                val txtDNSRecord = recordData.replace(Regex("\"\\s+\""), "")
                return txtDNSRecord.trim().removePrefix("\"").removeSuffix("\"")
            }
            "CNAME" -> {
                return recordData.lowercase().removeSuffix(".")
            }
            else -> {
                // Defaultannahme: A-Record
                return recordData.lowercase()
            }
        }

    }




    // Frage über Team Cymru den CountryCode und ASN der registrierten IP-Adresse ab
    fun getCCForIP(ip: String?): String? {

        if(ip.isNullOrBlank()) return null

        val reversedIPv4 = reverseIpv4(ip)
        val digResult = Dig.dig(reversedIPv4 + ".origin.asn.cymru.com", "TXT")

        if(digResult.hasAnswer) {
            return extractCountryCode(digResult.getFirstAnswer)
        }

        return null
    }


    private fun reverseIpv4(ip: String): String {
        return ip.split(".")
            .reversed()
            .joinToString(".")
    }


    private fun extractCountryCode(txtRecord: String?): String? {

        if(txtRecord.isNullOrBlank()) return null

        val cleanTxt = txtRecord.removeSurrounding("\"")

        // an den Pipe-Symbolen aufteilen
        val parts = cleanTxt.split("|")

        // Format:
        // 0: ASN |...| 2: Country Code (CC)
        if (parts.size >= 3) {
            return parts[2].trim()
        }

        return null
    }
}


