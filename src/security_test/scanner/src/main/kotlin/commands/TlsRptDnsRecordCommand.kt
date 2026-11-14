package commands

import com.google.common.net.InternetDomainName
import com.google.common.util.concurrent.RateLimiter
import dataClass.SCAN.getAllCountryCodes
import models.dataClass.DigResult
import dataClass.TLS.TlsRptAdress
import dataClass.TLS.TlsRptDnsRecordResult
import models.enums.TlsRptDnsRecordError
import org.apache.commons.validator.routines.EmailValidator
import java.net.URI
import java.net.URISyntaxException

public class TlsRptDnsRecordCommand(domain: String): DnsRecordCommand(domain) {

    // Hauptfunktion: Prüfe, ob Domain einen TLSRPT-Eintrag hinterlegt hat
    public fun getTlsrptDnsRecord(rateLimiter: RateLimiter): TlsRptDnsRecordResult {
        val tlsrptDigResult = fetchDnsRecord()
        //Lasse das Semikolon weg, um absichtlich möglichen Whitespace zwischen Versionswert und Semikolon zu prüfen
        val tlsRptDnsRecordsStrict = tlsrptDigResult.answer.filter { it.startsWith("v=TLSRPTv1", true) }


        // RFC: Nur ein einziger Eintrag darf das Ergebnis sein
        when(tlsRptDnsRecordsStrict.size) {

            0 -> {
                return createTlsRptResultError(domain,false, null,null)
            }
            1 -> {
                val result =  parseDnsRecord(tlsRptDnsRecordsStrict.first())
                result.lastCname = tlsrptDigResult.lastCname
                result.hasADFlag = tlsrptDigResult.adFlag
                checkReportingDomainsHost(rateLimiter, result)
                return result
            }
            else -> {
                return createTlsRptResultError(domain,false, null, TlsRptDnsRecordError.MultipleDnsRecords)
            }

        }

    }

    // Prüft ob Reporting Domain grundlegende Vorrausetzungen erfüllt(über DNS-Einträge), um erreichbar zu sein
    // und sammelt die Country Code Informationen
    public fun checkReportingDomainsHost(rateLimiter: RateLimiter, tlsRptResult: TlsRptDnsRecordResult) {

        val addressList = tlsRptResult.adressList ?: return

        val addressListResult = mutableListOf<TlsRptAdress>()


        for( addressEntry in addressList){



            // Mailto-Reportadresse
            if(addressEntry.schemeMailto) {


                // Prüfe nur für Domainnamen die MX-Records, welche noch nicht geprüft wurden
                if(addressEntry.hostname == domain) {
                    addressListResult.add(addressEntry)
                    continue
                }


                // 1. MX-Record Check
                rateLimiter.acquire()
                val mxRecords = Preprocessing.resolveMXRecords(listOf(addressEntry.hostname))
                // Keine MX-Records gefunden für mailto-Adresse -> Das ist ein Fehler
                if( mxRecords.first().mxRecord == null && mxRecords.size == 1 && tlsRptResult.errorType == null) {
                    tlsRptResult.errorType = TlsRptDnsRecordError.ReportingDomainNoMXRecods.stringText
                    continue
                }



                // 2. Frage nun die IP-Adressdaten für den Mailserver ab
                rateLimiter.acquire()
                val allScanData = Preprocessing.resolveIPAddresses(mxRecords)
                // Keine IP-Adressen für Mailserver -> Fehler
                if( allScanData.first().ipAddress == null && allScanData.size == 1 && tlsRptResult.errorType == null) {
                    tlsRptResult.errorType = TlsRptDnsRecordError.ReportingMXNoIPAddress.stringText
                    continue

                }
                addressEntry.ccData = allScanData.getAllCountryCodes().toMutableList()

            }



            // HTTPS-Reportadresse
            if(addressEntry.schemeHttps) {

                rateLimiter.acquire()
                val aRecords = Dig.dig(addressEntry.hostname, "A")

                // Keine IP-Adressen für HTTPS-Reporting angegeben? -> Fehler
                if(!aRecords.hasAnswer && tlsRptResult.errorType == null) {
                    tlsRptResult.errorType = TlsRptDnsRecordError.ReportingHttpsNoIPAddress.stringText
                    continue
                }

                val ccResult = aRecords.answer.distinct().map{
                    rateLimiter.acquire()
                    Dig.getCCForIP(it)
                }.filterNotNull().distinct()

                addressEntry.ccData = (addressEntry.ccData + ccResult).toMutableList()

            }

            // Keine Doppelten Country Codes
            addressEntry.ccData = addressEntry.ccData.distinct().toMutableList()
            addressListResult.add(addressEntry)

        }

        tlsRptResult.adressList = addressListResult

    }

    public fun fetchDnsRecord(): DigResult {

        val tlsRptDomain = "_smtp._tls.$domain"
        val digResult = Dig.dig(tlsRptDomain, "TXT")
        return digResult

    }


    // Validiere die Syntax des DNS-Records
    public fun parseDnsRecord(rawDnsRecord: String): TlsRptDnsRecordResult {

        // Wurde ein leerer DNS-Record übergeben
        if (rawDnsRecord.isBlank()) {
            return createTlsRptResultError(domain, false, rawDnsRecord, TlsRptDnsRecordError.EmptyDnsRecord)
        }


        // Gesonderte Prüfung für das Versionsfeld
        if(!rawDnsRecord.matches(Regex("^v=TLSRPTv1\\s*;.*"))) {

            return createTlsRptResultError(domain, false, rawDnsRecord, TlsRptDnsRecordError.NoVersionField)

        }else if (!rawDnsRecord.startsWith("v=TLSRPTv1;", ignoreCase = false)) {

            return createTlsRptResultError(domain, true, rawDnsRecord, TlsRptDnsRecordError.VersionValueMatchesABNFOnly)
        }


        // Strikt am Semikolon aufteilen
        val pairs = splitDnsRecord(rawDnsRecord)


        // Token Parsing
        val tlsRptAdressList = mutableListOf<TlsRptAdress>()

        for (part in pairs) {

            // Teile nur am ersten '=' (limit = 2)  wegen (möglichen) Query-Strings von URLs
            val keyValue = part.split("=", limit = 2)


            if(keyValue.size < 2) {
                return createTlsRptResultError(domain, true, rawDnsRecord, TlsRptDnsRecordError.NoKeyValueFormat)
            }


            val key = keyValue[0]
            val value = keyValue[1]

            when(key) {

                "rua" -> {
                    val ruaError = parseRuaValue(value,tlsRptAdressList)
                    if(ruaError != null) {
                        return createTlsRptResultError(domain,true, rawDnsRecord, ruaError)
                    }
                }

                else -> {
                    if(!checkDnsExtensionFields(key, value))
                        return createTlsRptResultError(domain, true, rawDnsRecord, TlsRptDnsRecordError.SyntaxErrorOtherField)
                }
            }

        }

        //Da der Wert des rua-Felds in der Funktion "parseRuaValue" geprüft wird -> Impliziert das ein Fehlen des rua-Felds
        if(tlsRptAdressList.isEmpty()) {
            return createTlsRptResultError(domain, true, rawDnsRecord, TlsRptDnsRecordError.MissingRua)
        }

        return createTlsRptResultValid(domain, rawDnsRecord, tlsRptAdressList)
    }

}


// TLSRPT-Spezifische Hilfsfunktionen

private fun parseRuaValue(value: String, ruaList: MutableList<TlsRptAdress>): TlsRptDnsRecordError? {

    if(value.isBlank()) {
        return TlsRptDnsRecordError.EmptyRuaValue
    }

    // Keine Leerzeichen zu Beginn des rua-Values
    if(value.startsWith(' ')) {
        return  TlsRptDnsRecordError.InvalidRuaValue
    }

    //Mögliche Leerzeichen zwischen den URIs
    val uris = value.split(",").map { it.trim() }

    // Keine Adressen angegeben
    if (uris.isEmpty()) {
        return TlsRptDnsRecordError.EmptyRuaValue
    }

    try {
        // Prüfe jede einzelne URI mit der nativen Java URI Bibliothek
        for (uriString in uris) {

            if(uriString.isBlank()) {
                return TlsRptDnsRecordError.EmptyReportUri
            }

            val forbiddenURIChars = charArrayOf(',', '!', ';')
            if(uriString.any {it in forbiddenURIChars}) {
                return TlsRptDnsRecordError.InvalidReportUri
            }


            val parsedUri = URI(uriString)
            val scheme = parsedUri.scheme?.lowercase()
            var reportDomain = ""
            var schemeHttps = false
            var schemeMailto = false


            if(parsedUri.schemeSpecificPart.isBlank()) {
                return TlsRptDnsRecordError.EmptyReportUri
            }


            when(scheme) {
                "mailto" -> {
                    schemeMailto = true

                    val emailVal = EmailValidator.getInstance()
                    val email = parsedUri.schemeSpecificPart.substringBefore('?')

                    if(!emailVal.isValid(email)) {
                        // Doppelt prüfen
                        return TlsRptDnsRecordError.InvalidReportUri
                    }

                    reportDomain = parsedUri.schemeSpecificPart.substringAfter('@')
                }

                "https" -> {
                    schemeHttps = true

                    if(parsedUri.host == null) {
                        return TlsRptDnsRecordError.InvalidReportUri
                    }

                    reportDomain = parsedUri.host
                }

                else -> {
                    return TlsRptDnsRecordError.InvalidUriScheme
                }


            }
            val entry = ruaList.firstOrNull() { it.hostname == reportDomain }

            if(entry == null) {
                ruaList.add(TlsRptAdress(schemeMailto, schemeHttps, reportDomain))

            }else if(!entry.schemeMailto && schemeMailto){
                entry.schemeMailto = schemeMailto

            }else if(!entry.schemeHttps && schemeHttps){
                entry.schemeHttps  = schemeHttps
            }
        }


    }catch (e: URISyntaxException) {
        // Wenn URI Leer ist
        return TlsRptDnsRecordError.InvalidReportUri
    }
    catch (e: Exception) {
    // Mögliche Exceptions von URI
        return TlsRptDnsRecordError.GeneralRuaError
    }

    //Kein Fehler
    return null

}


// Falls weiteres Versionsfeld vorkommt, Validiere es wie das erste
private fun checkOtherVersionField(value: String): Boolean {
    return value.equals("TLSRPTv1")
}

// Wrapperfunktionen für die Ergebniserstellung
private fun createTlsRptResultError(domain: String, hasDnsRecord: Boolean, rawRecord: String?,
                              errorType: TlsRptDnsRecordError?): TlsRptDnsRecordResult {
    
    return TlsRptDnsRecordResult(domain, hasDnsRecord, rawRecord, null, errorType?.stringText,null)
}



private fun createTlsRptResultValid(domain: String, rawRecord: String?, adressList: List<TlsRptAdress>): TlsRptDnsRecordResult {

    return TlsRptDnsRecordResult(domain, true, rawRecord, null ,null, adressList)
}

