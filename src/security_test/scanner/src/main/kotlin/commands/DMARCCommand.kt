package commands

import com.google.common.net.InternetDomainName
import com.google.common.util.concurrent.RateLimiter
import dataClass.DMARC.DMARCResults
import dataClass.DMARC.ParsedDMARCReportURI
import dataClass.DMARC.TreeWalkResult
import dataClass.DMARC.DMARCFoundAt
import dataClass.DMARC.DMARCPolicy
import dataClass.DMARC.ReportFormat
import dataClass.DMARC.dmarcGeneralData
import dataClass.DMARC.dmarcReportDomain
import dataClass.SCAN.getAllCountryCodes
import dataClass.TLS.TlsRptAdress
import enums.DMARCError
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import models.dataClass.DigResult
import models.enums.TlsRptDnsRecordError
import java.util.concurrent.ConcurrentHashMap
import kotlin.text.contains


// dmarcLookupCache: Liste an Domains und den zugehörigen Ergebnissen, die bereits abgefragt wurden
class DMARCCommand(private val domain: String,
                   private val dmarcLookupCache: ConcurrentHashMap<String,DigResult>) {




    // OrganizationalDomain nach altem Algorithmus (RFC 7489 Kap. 3.2.)
    val oldOrganizationalDomain: String? by lazy {
        determineOldOrganizationalDomain()
    }

     var digResolve: suspend (String,String) -> DigResult =
        { domain , type -> Dig.dig(domain, type) }

    var pythonValidator: suspend (String) -> DMARCResults? = { dmarcRecord ->
        validateDMARCCommand(dmarcRecord)
    }

    suspend fun testDMARC(rateLimiter: RateLimiter):DMARCPolicy {


        // Schritt 1. DNS-Spezifischer TeiL: policyDiscovery und bestimmen der alten Organisational Domain
        // Setzt die Felder domain bis cnameRecord
        val dmarcResult = getDMARCPolicyOld(rateLimiter)
        if(!dmarcResult.generalDMARCData.hasPolicy || dmarcResult.generalDMARCData.errorType != null || dmarcResult.generalDMARCData.rawPolicyOld == null) {
            return dmarcResult
        }


        // Schritt 2. Syntaktische Prüfung (extern) und extrahieren des DNS-Eintrags
        // Aufruf der Syntaxprüfung
        val extarctedDmarc = pythonValidator(dmarcResult.generalDMARCData.rawPolicyOld)


        // Schritt 3. Auswerten der Syntaxprüfung - DNS spezifische Validierung von externen Reportingdomains
        // Setzt die Felder policyTags und reportDomains, überschreibt ggf. errorType und errorMessage
        if(extarctedDmarc != null) {
            reviewDMARCValidationResults(rateLimiter , dmarcResult, extarctedDmarc)
        }


        if(dmarcResult.generalDMARCData.errorType != null && dmarcResult.generalDMARCData.errorType != DMARCError.NotValidatedExternalReporting.stringText) {
            return dmarcResult
        }




        // Schritt 4: Die RFC 9989 spezifischen Prüfungen: Prüfe auf Änderungen zur neuen DMARC-Version
        setDMARCBisChanges(rateLimiter,domain, dmarcPolicy = dmarcResult)


        return dmarcResult
    }


    suspend fun reviewDMARCValidationResults(rateLimiter: RateLimiter, dmarcResult: DMARCPolicy, validatedDmarcResult: DMARCResults) {

        // Syntaxvalidierung war fehlerhaft
        if(validatedDmarcResult.error != null || !validatedDmarcResult.valid) {
            dmarcResult.generalDMARCData.errorType = DMARCError.SyntaxError.stringText
            dmarcResult.generalDMARCData.errorMessage = validatedDmarcResult.error
            return
        }

        // Geparste Tags übernehmen
        dmarcResult.policyTags = validatedDmarcResult.tags


        // Domains extrahieren (Adressen könnten dieselbe Domain besitzen)
        val reportingDomains = extractReportingAddresses(validatedDmarcResult,
            dmarcResult.generalDMARCData.policyLocationDomain!!)
        // Prüft ob Reportingdomains externe Domains sind und ob an sie Reports versendet werden dürfen
        validExternalDestinationValidation(rateLimiter, reportingDomains)


        if(reportingDomains.any{!it.validatedDomain}) {
            dmarcResult.generalDMARCData.errorType = DMARCError.NotValidatedExternalReporting.stringText
        }


        // Grundlegende DNS-basierte Validierung von Reportingadressen
        val reportDestinationError = validateReportDestination(rateLimiter, reportingDomains)
        if(reportDestinationError != null && dmarcResult.generalDMARCData.errorType == null)
        {
            dmarcResult.generalDMARCData.errorType = reportDestinationError
        }
        dmarcResult.reportDomains = reportingDomains


        // Setze die Policy die für die jeweilige Domain gültig ist
        val resultP = dmarcResult.policyTags?.get("p")
        if( resultP != null) {

            if (resultP.explicit) {
                dmarcResult.generalDMARCData.policyMode = resultP.value
            }

            // Fall SP wiegt für Subdomains schwerer
            val resultSP = dmarcResult.policyTags?.get("sp")
            if ( resultSP != null && dmarcResult.generalDMARCData.policyLocation == DMARCFoundAt.OrgDomain.stringText
                /*&& resultSP.explicit */ ) {
                dmarcResult.generalDMARCData.policyMode = dmarcResult.policyTags?.get("sp")?.value
            }

        }

    }

    // Prüfe ob eine Reportingadresse grundsätzliche Anforderungen zur Erreichbarkeit besitzt
    suspend fun validateReportDestination(rateLimiter: RateLimiter, reportingDomains: List<dmarcReportDomain>): String? {

        var dmarcReportingError = ""

        for( addressEntry in reportingDomains){


            // Mailto-Reportadresse
            rateLimiter.acquire()
            val mxRecords = Preprocessing.resolveMXRecords(listOf(addressEntry.reportDomain))
            // Prüfe nur Domainnamen, welche noch nicht geprüft wurden
            if(addressEntry.reportDomain == domain)
                continue

            // Keine MX-Records gefunden für mailto-Adresse -> Das ist ein Fehler
            if( mxRecords.first().mxRecord == null && mxRecords.size == 1 && dmarcReportingError.isEmpty()) {
                dmarcReportingError = DMARCError.ReportingDomainNoMXRecods.stringText
                continue
            }


            // Frage nun die IP-Adressdaten für den Mailserver ab
            rateLimiter.acquire()
            val allScanData = Preprocessing.resolveIPAddresses(mxRecords)

            // Keine IP-Adressen für Mailserver -> Fehler
            if( allScanData.first().ipAddress == null && allScanData.size == 1 && dmarcReportingError.isEmpty()) {
                dmarcReportingError = DMARCError.ReportingMXNoIPAddress.stringText
                continue

            }
                addressEntry.countryCodeList = allScanData.getAllCountryCodes().joinToString(", ")

        }

            return if (dmarcReportingError.isNotEmpty()) { dmarcReportingError } else { null }
    }



    // Ermittelt die dmarc-Policy für die angegebene Domain
    // Nutzt den Lookup-Cache zum Nachschlagen
    // DNS-Ergebnis ist auf DMARC-Ergebnisse gefiltert
    // targetDomain- Domain die auf DMARC-Policy geprüft wird, reportDomain: Domain von externer Reporting-Adresse
    suspend fun retrievePolicy(rateLimiter: RateLimiter, targetDomain: String = domain, reportDomain: String? = null): DigResult {

        // Schaue ob die Abfrage schon einmal gestellt wurde ( Ausnahme externes Reporting)
        if(reportDomain == null && dmarcLookupCache.containsKey(targetDomain) && dmarcLookupCache[targetDomain] != null) {

            // Wurde die Domain schon vorher abgefragt?
            return dmarcLookupCache[targetDomain]!!


        }else {

            // Ist Domain eine externe Reporting-Domain?
            val retrievalDomain = if (reportDomain == null) {"_dmarc.$targetDomain" } else { "$targetDomain._report._dmarc.$reportDomain" }

            // DNS-Abfrage
            rateLimiter.acquire()
            val result = digResolve(retrievalDomain, "TXT")

            // Nehme die Ergebnisse
            // , die einen DMARC Versionstag besitzen (4.8. RFC 9989/ Case-Sensitive Wert (key jedoch nicht))
            val filteredResult = result.filterAnswers{ it.matches(Regex("^v\\s*=\\s*DMARC1.*"))}

            if(reportDomain == null) {
                dmarcLookupCache[targetDomain] = filteredResult
            }

            return filteredResult
        }
    }

    suspend fun retrievePolicyFromMainDomain(rateLimiter: RateLimiter, targetDomain: String = domain): DigResult {

        // Stelle die Anfrage direkt an die Domain (ohne "_dmarc"-Label zu Beginn)
        rateLimiter.acquire()
        val result = digResolve(targetDomain, "TXT")

        // Nehme die Ergebnisse
        // , die einen DMARC Versionstag besitzen (4.8. RFC 9989/ Case-Sensitive Wert (key jedoch nicht))
        val filteredResult = result.filterAnswers{ it.matches(Regex("^v\\s*=\\s*DMARC1.*"))}

        return filteredResult

    }

    fun determineOldOrganizationalDomain(targetDomain: String = domain): String? {

        if (targetDomain.isBlank()) return null

        try {
            var orgDomainOld : String? = null
            val domainName = InternetDomainName.from(targetDomain)
            val publicSuffix = domainName.publicSuffix()

            if(publicSuffix != null) {
                val labelList = domainName.parts()
                val domainLabelCount = labelList.size
                val publicSuffixCount = publicSuffix.parts().size
                // Nur das erste Domainlabel vor dem public Suffix berücksichtigen und vorne anhängen
                if(domainLabelCount > publicSuffixCount) {
                    orgDomainOld = labelList.drop(domainLabelCount - publicSuffixCount - 1).joinToString(".")
                }
            }

            return orgDomainOld
        }catch(e: Exception) {
            println("Error: Konnte Domain nicht parsen: $targetDomain, Fehler: ${e.message}")

        }
        return null
    }


    // Fragt nach Kap 6.6.3. RFC 7489 die DMARC-Policy ab und speichert die Organisational Domain ab
    suspend fun getDMARCPolicyOld(rateLimiter: RateLimiter): DMARCPolicy {

        // Für Author Domain Policy prüfen
        var dmarcPolicy = retrievePolicy(rateLimiter)
        var policyLocation = DMARCFoundAt.AuthorDomain.stringText
        var policyDomain = domain

        // Ermittle die Organisational Domain für Alignment (und ggf. PolicyDiscovery)
        val oldOrgDomain = oldOrganizationalDomain

        // Wenn keine DMARC Policy gefunden, schaue in OrganizationalDomain nach
        if(!dmarcPolicy.hasAnswer && oldOrganizationalDomain != domain && oldOrganizationalDomain != null) {

            dmarcPolicy = retrievePolicy(rateLimiter,oldOrganizationalDomain!!)

            if(dmarcPolicy.hasAnswer) {
                policyLocation = DMARCFoundAt.OrgDomain.stringText
                policyDomain = oldOrganizationalDomain!!
            }

        }

        // Auswertung der Ergebnis(-menge)

        // Keine DMARC Policy gefunden
        if(!dmarcPolicy.hasAnswer) {

            // Prüfe ob an der Hauptdomain (ohne _dmarc-Label) mindestens eine DMARC-Policy hinterlegt ist
            val dmarcAtMainDomain = retrievePolicyFromMainDomain(rateLimiter,domain)
            if(dmarcAtMainDomain.hasAnswer) {

                // hasPolicy bleibt false
                return DMARCPolicy(domain, dmarcGeneralData(
                    false,
                    null,
                    DMARCError.DMARCAtMainDomainLocation.stringText,
                    rawPolicyOld =dmarcAtMainDomain.getFirstAnswer ))

            }

            return DMARCPolicy(domain,dmarcGeneralData(false))
        }

        // Mehrere DMARC Policies unter einer Domain (5.Schritt) -> Keine DMARC-Prüfung anwenden
        if(dmarcPolicy.hasMultipleAnswers) {
            return DMARCPolicy(domain, dmarcGeneralData(false,null, DMARCError.MutlipleRecords.stringText))
        }

        // Erfolgsfall
        return DMARCPolicy(
            domain,
            dmarcGeneralData(
            hasPolicy = true,
            rawPolicyOld = dmarcPolicy.getFirstAnswer,
            hasADFlag = dmarcPolicy.adFlag,

            policyLocation = policyLocation,
            policyLocationDomain = policyDomain,

            cnameRecord = dmarcPolicy.lastCname,
            oldOrgDomain = oldOrganizationalDomain
            )
        )


    }


    // Ruft externes Python-Skript auf, dass die Syntax des DMARC-DNS-Records validiert und den Record geparst zurückgibt
    suspend fun validateDMARCCommand(dmarcRecord: String): DMARCResults? {

        try {

            //
            val pb = ProcessBuilder(
                "python3",
                "/app/SPF_DMARC_Scripts/dmarcSyntaxCheck.py",
                domain,
                dmarcRecord
            )

            pb.redirectErrorStream(true) // Fehler von Python in den normalen Output leiten

            val process = pb.start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            val exitCode = process.waitFor()

            val dmarcResult = Json.decodeFromString<DMARCResults>(output)
            return dmarcResult

        } catch (e: Exception) {
            println("Es gab einen Fehler: ${e.message}")
            return null
        }


    }

    // Fasse die Reportingadressen je Domain zusammen
    fun extractReportingAddresses(dmarcValidationResult: DMARCResults, policyLocationDomain: String ): List<dmarcReportDomain> {

        val allReportList = mutableListOf<dmarcReportDomain>()

        if(dmarcValidationResult.ruaURIList != null) {

            // Suche für
            dmarcValidationResult.ruaURIList.forEach{ ruaResult ->

                val reportListEntry = allReportList.find{ reportData -> reportData.reportDomain == ruaResult.domain}

                if( reportListEntry == null) {

                    allReportList.add(
                        dmarcReportDomain(
                            domain, // Domain für die Policy gilt
                            policyLocationDomain, // Domain wo die Policy gefunden wurde
                        ruaResult.domain, // Domain, an die Reports gesendet wird
                        ReportFormat.Rua.stringText,
                        mutableListOf<ParsedDMARCReportURI>(ruaResult)
                    ))


                }else {

                    // Es können mehrere Adressen eingetragen sein für die selbe Domain
                    reportListEntry.ruaAddressList?.add(ruaResult)

                }



        }


        if(dmarcValidationResult.rufURIList != null) {

            dmarcValidationResult.rufURIList.forEach{ rufResult ->

                val reportListEntry = allReportList.find{ reportData -> reportData.reportDomain == rufResult.domain}

                if( reportListEntry == null) {


                    allReportList.add(
                        dmarcReportDomain(
                            domain, // Domain für die Policy gilt
                            policyLocationDomain, // Domain wo die Policy gefunden wurde
                            rufResult.domain, // Domain, an die Reports gesendet wird
                        ReportFormat.Ruf.stringText,
                        rufAddressList = mutableListOf<ParsedDMARCReportURI>(rufResult),
                    ))


                }else {

                    // Fall: Es ist schon ein rua-Eintrag für die Domain vorhanden
                    if(reportListEntry.reportVia == ReportFormat.Rua.stringText) {
                        reportListEntry.reportVia = ReportFormat.RuaAndRuf.stringText
                    }

                    if(reportListEntry.rufAddressList == null) {
                        reportListEntry.rufAddressList = mutableListOf<ParsedDMARCReportURI>()
                    }

                    reportListEntry.rufAddressList!!.add(rufResult)
                }

                }

            }

        }

        return allReportList

    }



    // Implementierung orientiert sich am RFC 9989 Kapitel 4.10. (Schritte 1. - 10.)
    // Gehe den DNS-Pfad schrittweise "hoch" und speichere alle Domains mit einer DMARC
    // Policy ab
    // Ermittle gleichzeitig ob eine Domain mit einer PSD-Kennung vorhanden ist

    suspend fun executeDnsTreeWalk(rateLimiter: RateLimiter): TreeWalkResult {

        // Übereinstimmend für Policy Discovery 4.10.1. und TreeWalk (4.10.)
        val isPsdDomainPattern = Regex("psd\\s*=\\s*y", RegexOption.IGNORE_CASE)
        val hasStrictSPFAlignment = Regex("aspf\\s*=\\s*s", RegexOption.IGNORE_CASE)
        val hasStrictDKIMAlignment = Regex("adkim\\s*=\\s*s", RegexOption.IGNORE_CASE)

        // Domains die im Rahmen des Tree-Walks ein DMARC-Record zurückgeliefert haben
        val cachedTreeWalkPolicyResults = mutableMapOf<String,DigResult>()


        val result = retrievePolicy(rateLimiter, domain)


        // Speichere nur Ergebnisse ab, die einen DMARC-Eintrag besitzen Kap 4.10 1./2.
        if(result.hasAnswer && !result.hasMultipleAnswers) {

            cachedTreeWalkPolicyResults[domain] = result
            val dmarcRecord = result.getFirstAnswer

            // 2. -> psd-Tag mit Wert y oder n bricht den Tree-Walk ab, Grammatik erlaubt Whitespace
            if(dmarcRecord != null ) {

                // Sollte die Domain selbst schon einen DMARC-Eintrag besitzen mit einem strict- Alignment, dann
                // breche den Treewalk ab. Die Organisational-Domain spielt dann keine Rolle und ist null
                if(hasStopCondition(dmarcRecord)) { //|| dmarcRecord.contains(hasStrictSPFAlignment) && dmarcRecord.contains(hasStrictDKIMAlignment))

                    val tempPsdDomain =  if(dmarcRecord.contains(isPsdDomainPattern)) {
                        domain

                    }else
                    {
                        null
                    }

                    return TreeWalkResult(cachedTreeWalkPolicyResults, tempPsdDomain)
                }

            }

        }


        // Für weitere Schritte zunächst die Domain ggf. abkürzen (Kap. 4.10. 3./4.)
        val domainName = InternetDomainName.from(domain)
        var labels = domainName.parts().toList()

        //entferne das linkeste Label bis es 7 sind: Für den Fall, dass es 8 oder mehr sind (RFC-Vorgabe) 4.10.
        if(labels.size > 7) {
            labels = labels.drop(labels.size - 7)
        }else {
            labels = labels.drop(1)
        }


        val labelCount = labels.size
        var iterationCount = 0

        // Entferne jede Iteration ein Label, gehe Schrittweise entlang des Domainpfades "hoch" Schritte 5./6./7.
        while(labelCount > iterationCount) {

            // entferne für jeden Durchlauf ein Label
            val tempDomain = labels.drop(iterationCount).joinToString(".")
            val result = retrievePolicy(rateLimiter, tempDomain)

            // Speichere nur Ergebnisse ab, die einen DMARC-Eintrag besitzen Kap 4.10 5./6.
            if(result.hasAnswer && !result.hasMultipleAnswers) {

                cachedTreeWalkPolicyResults[tempDomain] = result
                val dmarcRecord = result.getFirstAnswer


                // 6. -> psd-Tag mit Wert y oder n bricht den Tree-Walk ab,
                // Grammatik erlaubt Whitespace
                if(dmarcRecord != null && (hasStopCondition(dmarcRecord) )) {

                    // Zusätzlich: Ermittle gleichzeitig die PSD-Domain (psd=y)
                    val tempPsdDomain =  if(dmarcRecord.contains(isPsdDomainPattern)) {

                        tempDomain

                    }else
                    {
                        null
                    }

                    return TreeWalkResult(cachedTreeWalkPolicyResults, tempPsdDomain)
                }

            }

            iterationCount++
        }

        return TreeWalkResult(cachedTreeWalkPolicyResults, null)

    }


    suspend fun setDMARCBisChanges(rateLimiter: RateLimiter, domain: String, dmarcPolicy: DMARCPolicy) {

        val treeWalkResult = executeDnsTreeWalk(rateLimiter)

        val newOrgDomain = getNewOrganisationalDomain( treeWalkResult)

        dmarcPolicy.generalDMARCData.newOrgDomain = newOrgDomain

        dmarcPolicy.generalDMARCData.newRawDMARCPolicy = getNewDMARCPolicy( domain, treeWalkResult, newOrgDomain)

    }


    suspend fun getNewDMARCPolicy( domain: String, treeWalkResult: TreeWalkResult
    , newOrgDomain: String): String? {

        val cachedTreeWalkPolicyResults = treeWalkResult.cachedTreeWalkPolicyResults

        // 1. Prüfe ob die Domain selbst eine gültige DMARC-Policy besitzt
        if(cachedTreeWalkPolicyResults.containsKey(domain) && cachedTreeWalkPolicyResults[domain] != null) {
            val cached = cachedTreeWalkPolicyResults[domain]
            return cached?.getFirstAnswer
        }

        // 2. Organizational Domain: prüfe ob dort ein gültiger DMARC-Record abgelegt ist
        val policyAtOrgDomain = cachedTreeWalkPolicyResults[newOrgDomain]
        if( policyAtOrgDomain != null) {
             return policyAtOrgDomain.getFirstAnswer
        }

        // 3. Prüfe als leztes ob die PSD eine DMARC-Policy besitzt
        if(treeWalkResult.psdDomain != null) {
            return cachedTreeWalkPolicyResults[treeWalkResult.psdDomain]?.getFirstAnswer
        }


        // sonst wurde keine Policy gefunden
        return null

    }


    // 6. -> psd-Tag mit Wert y oder n bricht den Tree-Walk ab, Grammatik erlaubt Whitespace
    suspend fun hasStopCondition(dmarcRecord: String):Boolean {
        return dmarcRecord != null && (dmarcRecord.contains( Regex("psd\\s*=\\s*(n|y)") ) )
    }



    // Bestimme die OrganisationalDomain
    suspend fun getNewOrganisationalDomain(treeWalkResult: TreeWalkResult): String {

        val cachedTreeWalkPolicyResults = treeWalkResult.cachedTreeWalkPolicyResults

        if(cachedTreeWalkPolicyResults.isEmpty()) {
            // Fall 4. Normalerweise irrelevant,
            // Fallbackmechanismus, wenn Tree Walk kein Ergebnis erzeugen kann
            return domain
        }

        val isPsdDomainPattern = Regex("psd\\s*=\\s*y")
        val isOrgDomainPattern = Regex("psd\\s*=\\s*n")


        // Ermittle die Organisational Domain für die Domain mithilfe der Tree Walk Ergebnisse
        //if(cachedTreeWalkPolicyResults.containsKey(domain)) {

        val result = cachedTreeWalkPolicyResults.entries.reversed()
        var predecessorDomain = ""
        for((tempDomain, dmarcResult) in cachedTreeWalkPolicyResults) {

            if(dmarcResult.getFirstAnswer == null) {continue}

            if(hasStopCondition(dmarcResult.getFirstAnswer!!)) {

                // Fall 1. psd=n
                if(dmarcResult.getFirstAnswer!!.contains(isOrgDomainPattern)) {
                    return tempDomain
                }


                // Fall 2. psd=y und es ist nicht die unterste Domain, dann
                // ist es die nächsttiefere Domain im DNS-Pfad
                if(dmarcResult.getFirstAnswer!!.contains(isPsdDomainPattern)
                    && !tempDomain.equals(domain)) {

                    return predecessorDomain
                }

            }
            predecessorDomain = tempDomain

        }


        // Fall 3. Domain mit DMARC Eintrag und den wenigsten Labels
        return cachedTreeWalkPolicyResults.entries.lastOrNull()!!.key

    }




    // Wurde die Domain, welche das Reporting an eine externe Domain auslagert, von dieser dazu authentifiziert
    suspend fun validExternalDestinationValidation(rateLimiter: RateLimiter, reportList: List<dmarcReportDomain>) {


        for(report in reportList) {
            // Ermittle die OrganizationalDomain von Subadresse
            val orgDomainReport = determineOldOrganizationalDomain(report.reportDomain)

            if(oldOrganizationalDomain.equals(orgDomainReport)) {
                report.sameOrgDomain = true
                report.validatedDomain = true

            }else {

                // Prüfe ob die externe Domain einen Eintrag unter der Authorisierungsdomain hinterlegt hat
                val externalRecordRequest = retrievePolicy(rateLimiter,report.policyLocationDomain, report.reportDomain)
                val externalRecord = externalRecordRequest.getFirstAnswer

                if( externalRecord != null ) {
                    report.externalADFlag = externalRecordRequest.adFlag
                    report.sameOrgDomain = false
                    report.validatedDomain = true

                }else {

                    report.sameOrgDomain = false
                    report.validatedDomain = false
                }

            }

        }
    }

}