package emailtest.analysis

import emailtest.analysis.results.AddressTransport
import emailtest.dataClassEvaluator.forJSON.domainInfo

import emailtest.dataClassEvaluator.forJSON.externalDependency
import emailtest.dataClassEvaluator.forJSON.MtaStsErrorEntry
import emailtest.models.*
import emailtest.analysis.results.DaneResult
import emailtest.analysis.results.DomainAntiSpoofing
import emailtest.analysis.results.DomainTransport
import emailtest.dataClassEvaluator.result.ResultDatabaseRowNullable
import emailtest.dataClassScanData.SCAN.getAllCountryCodes

fun createDomainInfo(data: List<DatabaseRow>, validData: List<DatabaseRow>, daneResults: List<DaneResult>): DomainInfo {
    val domainCountTotal = data.domainsCount()
    val domainCountWithoutMXRecords = data.domainsNoMxRecordCount()
    val domainsNoResolvableMxRecord = data.domainsNoResolvableMxRecord()
    val domainsNoResolvableMxRecordCount = domainsNoResolvableMxRecord.countKeys()

    val domainsOnlyValidResults = data.domainsOnlyValidResults()
    val domainsOnlyValidResultsCount = domainsOnlyValidResults.countKeys()
    val domainsBothValidAndInvalidResults = data.domainsBothValidAndInvalidResults()
    val domainsBothValidAndInvalidResultsCount = domainsBothValidAndInvalidResults.countKeys()
    val domainsNoValidResults = data.domainsNoValidResults()
    val domainsNoValidResultsCount = domainsNoValidResults.countKeys()

    val domainCountValidData = validData.domainsCount()

    val maxTlsVersionAllMtaToDomainsMap = validData.maxTlsVersionAllMtaToDomainMap()
    val maxTlsVersionAllMtaToDomainCountMap = maxTlsVersionAllMtaToDomainsMap.countValueList()
    val maxTlsVersionAtLeastOneMtaToDomainsMap = validData.maxTlsVersionAtLeastOneMtaToDomainMap()
    val maxTlsVersionAtLeastOneMtaToDomainsCountMap = maxTlsVersionAtLeastOneMtaToDomainsMap.countValueList()

    val minTlsVersionAllMtaToDomainsMap = validData.minTlsVersionAllMtaToDomainMap()
    val minTlsVersionAllMtaToDomainCountMap = minTlsVersionAllMtaToDomainsMap.countValueList()
    val minTlsVersionAtLeastOneMtaToDomainsMap = validData.minTlsVersionAtLeastOneMtaToDomainMap()
    val minTlsVersionAtLeastOneMtaToDomainsCountMap = minTlsVersionAtLeastOneMtaToDomainsMap.countValueList()

    val domainsMixedMaxTls = validData.mixedTls(minTls = false)
    val domainsMixedMaxTlsCount = domainsMixedMaxTls.count()
    val domainsMixedMinTls = validData.mixedTls(minTls = true)
    val domainsMixedMinTlsCount = domainsMixedMinTls.count()

    val domainsDaneForAllMta = validData.daneSupportForAllMtaGroupedBy { it.domainName }
    val domainsDaneForAtLeastOneMta = validData.daneSupportForAtLeastOneMtaGroupedBy { it.domainName }
    val domainsDaneForAllMtaCount = domainsDaneForAllMta.count()
    val domainsDaneForAtLeastOneMtaCount = domainsDaneForAtLeastOneMta.count()

    val domainsDaneForAllMtaBasedOnMx = validData.daneSupportForAllMtaBasedOnMxGroupedBy(daneResults) { it.domainName }.reverse()
    val domainsDaneForAllMtaBasedOnMxCount = domainsDaneForAllMtaBasedOnMx.countValueList()
    val domainsDaneForAtLeastOneMtaBasedOnMx = validData.daneSupportForAtLeastOneMtaBasedOnMxGroupedBy(daneResults) { it.domainName }.reverse()
    val domainsDaneForAtLeastOneMtaBasedOnMxCount = domainsDaneForAtLeastOneMtaBasedOnMx.countValueList()

    val domainsDmarc = data.distinctBy { it.domainName }.count { it.hasDmarc == true }
    val domainsGoodDmarc = data.distinctBy { it.domainName }.count { it.hasGoodDmarc == true }
    val domainsSpf = data.distinctBy { it.domainName }.count { it.hasSpf == true }
    val domainsGoodSpf = data.distinctBy { it.domainName }.count { it.hasGoodSpf == true }
    val domainsDkim = data.distinctBy { it.domainName }.count { it.hasDkim == true }

    val domainsSecure = validData.secureDomains()
    val domainCountSecure = domainsSecure.count()

    return DomainInfo(
        domainCountTotal,
        domainCountWithoutMXRecords,
        domainsNoResolvableMxRecordCount,
        domainsOnlyValidResultsCount,
        domainsBothValidAndInvalidResultsCount,
        domainsNoValidResultsCount,
        domainCountValidData,
        //maxTlsVersionAllMtaToDomainsMap,
        maxTlsVersionAllMtaToDomainCountMap,
        //maxTlsVersionAtLeastOneMtaToDomainsMap,
        maxTlsVersionAtLeastOneMtaToDomainsCountMap,
        //minTlsVersionAllMtaToDomainsMap,
        minTlsVersionAllMtaToDomainCountMap,
        //minTlsVersionAtLeastOneMtaToDomainsMap,
        minTlsVersionAtLeastOneMtaToDomainsCountMap,
        //domainsMixedMaxTls,
        domainsMixedMaxTlsCount,
        //domainsMixedMinTls,
        domainsMixedMinTlsCount,
        //domainsDaneForAllMta,
        domainsDaneForAllMtaCount,
        //domainsDaneForAtLeastOneMta,
        domainsDaneForAtLeastOneMtaCount,
        //domainsSecure,
        domainCountSecure,
        //domainsDaneForAllMtaBasedOnMx,
        domainsDaneForAllMtaBasedOnMxCount,
        //domainsDaneForAtLeastOneMtaBasedOnMx,
        domainsDaneForAtLeastOneMtaBasedOnMxCount,
        domainsDmarc,
        domainsGoodDmarc,
        domainsSpf,
        domainsGoodSpf,
        domainsDkim
    )
}

fun createDomainInfo(data: List<ResultDatabaseRowNullable>): List<domainInfo> {

    // Arbeite nur mit Daten, die vollständig sind
    val validDomainResults = data.map{it.getNotNullDomain()}.filterNotNull().groupBy { it.addressObj.domain }
    val domainInfoList = mutableListOf<domainInfo>()
    println(domainInfoList.size)

    // Erstelle je Domain einen Eintrag
    validDomainResults.forEach { (domain, domainResults) ->

        val errorList = mutableListOf<MtaStsErrorEntry>()
        val externalDependencyList = mutableListOf<externalDependency>()

        // Gruppiere die Ergebnisse nach den Mailserveradressen einer Domain
        val completeData = domainResults.map{it.getNotNull()}.filterNotNull()
        val mxRecordResult = completeData.filter{it.addressObj.mxRecord != null}.groupBy { it.addressObj.mxRecord!!}

        // Erstelle für jede Mailserveradresse ein AdressTransport-Objekt
        val mxRecordResultTest : List<AddressTransport> = mxRecordResult.map { (mxRecord, dbRow) ->
            AddressTransport(
                dbRow.first().addressObj.domain,
                mxRecord = dbRow.first().addressObj.mxRecord!!,
                // Alle nicht null-IP-Adressen
                ipAdressList = dbRow.filter{it.addressObj.ipAddress != null }.map{it.addressObj.ipAddress!!},
                ipCountryCodeList = dbRow.filter{it.addressObj.ipAddress != null }.map{it.addressObj}.getAllCountryCodes(),
                tlsCertResult = dbRow.first().tlsCertResult,

                // Alle TLS-Versionsscans
                tlsVersionRangeResult = dbRow.first().tlsVersionRangeResult,

                dnssecMXResult = dbRow.first().dnssecMX,
                dnssecDomain = dbRow.first().dnssecDomain,
                tls12Result = dbRow.first().tls12Test,
                mtaStsPolicy = dbRow.first().mtaStsPolicy,
                daneResult = dbRow.first().daneResult
            )
            }

        // Stelle nun die Ergebnisse auf Mailserverebene für jeden Mailserver einer Domain dar mit Hilfe eines MXData-Objekts
        val mxData = mxRecordResultTest.map{it.createMXData()}


        // Transportsicherheitsübersicht ( Agg. TLS Info, DANE/ DNSSEC)
        val domainResult = domainResults.first()
        val domainTransport = DomainTransport(
            domainResult.addressObj.domain, mxData,
            domainResult.mtaStsPolicy,
            domainResult.mtaStsDnsRecordResult,
            domainResult.tlsRptDnsRecordResult,
            domainResult.dnssecDomain)

        val aggDomainDataTransport = domainTransport.createAggDomainDataTransport()
        if(aggDomainDataTransport.mtaStsErrorList.isNotEmpty()) {
            errorList.addAll(aggDomainDataTransport.mtaStsErrorList)
        }
        if(aggDomainDataTransport.externalDependencyList.isNotEmpty()) {
            externalDependencyList.addAll(aggDomainDataTransport.externalDependencyList)
        }



        // Anti-Spoofing Daten sammeln und aufbereiten

        val domainAntiSpoofing = DomainAntiSpoofing(
            domainResult.addressObj.domain,
            mxData.map{it.mxRecord},
            domainResult.dmarcResult,
            domainResult.spfResult,
            domainResult.dkimResult,
            domainResult.dnssecDomain
        )

        // Aggregierte Anti-Spoofing-Daten: DMARC, SPF, DKIM
        val aggDomainAntiSpoofing = domainAntiSpoofing.createDomainAggAntiSpoofing()


        // Daten über alle erfassten externen DMARC
        if(aggDomainAntiSpoofing.externalDependencyList.isNotEmpty()) {
            externalDependencyList.addAll(aggDomainAntiSpoofing.externalDependencyList)
        }

        // Daten über alle DMARC-ReportingDomains
        val dmarcReportList = aggDomainAntiSpoofing.dmarcReportingList


        val domainInfo = domainInfo(
            domain,

            aggDomainDataTransport.aggDomainDataTransport,
            mxData,
            errorList,

            aggDomainAntiSpoofing.aggDomainAntiSpoofing,
            dmarcReportList,
            externalDependencyList
        )

        domainInfoList.add(domainInfo)

    }

    return domainInfoList
}









fun List<DatabaseRow>.domainsNoResolvableMxRecord() =
    groupBy { it.domainName }.filter { it.value.all { it.mxrecordName != null && it.ipAddress == null } }

private fun List<DatabaseRow>.domainsOnlyValidResults() =
    filter { it.mxrecordName != null && it.ipAddress != null }.groupBy { it.domainName }
        // all MTA for this domain have valid results for TLS and DANE
        .filter { it.value.all { it.isTLSValid() and it.isDANEValid() } }

private fun List<DatabaseRow>.domainsBothValidAndInvalidResults() =
    filter { it.mxrecordName != null && it.ipAddress != null }.groupBy { it.domainName }
        .filter {
            // at least one MTA for this domain has valid results for TLS and DANE
            it.value.any { it.isTLSValid() and it.isDANEValid() } and
                    // but at least one MTA for this domain has an invalid result for TLS or DANE
                    it.value.any { !it.isTLSValid() or !it.isDANEValid() }
        }

private fun List<DatabaseRow>.domainsNoValidResults() =
    filter { it.mxrecordName != null && it.ipAddress != null }.groupBy { it.domainName }
        // no MTA for this domain has a valid result
        .filter { it.value.all { !it.isTLSValid() or !it.isDANEValid() } }


fun List<DatabaseRow>.secureDomains(): List<String> {
    val daneDomains = daneSupportForAllMtaGroupedBy { it.domainName }
    val domainsWithAtLeastTls1_2 = mutableListOf(
        maxTlsVersionAllMtaToDomainMap()[TlsVersion.TLS1_2] ?: listOf(),
        maxTlsVersionAllMtaToDomainMap()[TlsVersion.TLS1_3] ?: listOf()
    ).flatten()

    return daneDomains.filter { domainName -> domainsWithAtLeastTls1_2.contains(domainName) }
}

fun List<DatabaseRow>.maxTlsVersionAllMtaToDomainMap(): Map<TlsVersion, List<String>> {
    val domainToListOfMtaTlsVersion =
        groupBy { it.domainName }.mapValues { it.value.map { it.highestTlsVersion() } }
    val domainToTlsVersion = domainToListOfMtaTlsVersion.mapValues { it.value.lowestTlsVersion() }

    return domainToTlsVersion.reverse()
}

fun List<DatabaseRow>.maxTlsVersionAtLeastOneMtaToDomainMap(): Map<TlsVersion, List<String>> {
    val domainToListOfMtaTlsVersion =
        groupBy { it.domainName }.mapValues { it.value.map { it.highestTlsVersion() } }
    val domainToTlsVersion = domainToListOfMtaTlsVersion.mapValues { it.value.highestTlsVersion() }

    return domainToTlsVersion.reverse()
}

fun List<DatabaseRow>.minTlsVersionAllMtaToDomainMap(): Map<TlsVersion, List<String>> {
    val domainToListOfMtaTlsVersion =
        groupBy { it.domainName }.mapValues { it.value.map { it.lowestTlsVersion() } }
    val domainToTlsVersion = domainToListOfMtaTlsVersion.mapValues { it.value.highestTlsVersion() }

    return domainToTlsVersion.reverse()
}




fun List<DatabaseRow>.minTlsVersionAtLeastOneMtaToDomainMap(): Map<TlsVersion, List<String>> {
    val domainToListOfMtaTlsVersion =
        groupBy { it.domainName }.mapValues { it.value.map { it.lowestTlsVersion() } }
    val domainToTlsVersion = domainToListOfMtaTlsVersion.mapValues { it.value.lowestTlsVersion() }

    return domainToTlsVersion.reverse()
}

fun List<DatabaseRow>.mixedTls(minTls: Boolean): List<String> {
    val func = if (minTls) DatabaseRow::lowestTlsVersion else DatabaseRow::highestTlsVersion

    return groupBy { it.domainName }
        .filter {
            val match = func(it.value.first())
            it.value.any { func(it) !=  match }
        }.map { it.key }
}

fun List<DatabaseRow>.domainsCount() = distinctBy { it.domainName }.count()

fun List<DatabaseRow>.domainsNoMxRecord() =
    groupBy { it.domainName }.filter { it.value.all { it.mxrecordName == null } }

fun List<DatabaseRow>.domainsNoMxRecordCount() = domainsNoMxRecord().count()

