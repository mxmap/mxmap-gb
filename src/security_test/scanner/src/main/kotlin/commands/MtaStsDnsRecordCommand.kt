package commands

import models.dataClass.DigResult
import dataClass.MTASTS.MtaStsDnsRecordResult
import models.enums.MtaStsDnsRecordError


public class MtaStsDnsRecordCommand(domain: String): DnsRecordCommand(domain) {

    public fun getMtaStsDnsRecord(): MtaStsDnsRecordResult {
        val mtaStsDnsDigResult = fetchDnsRecord()
        //Lasse das Semikolon weg, um absichtlich möglichen Whitespace zwischen Versionswert und Semikolon zu prüfen
        val mtaStsDnsRecordsStrict = mtaStsDnsDigResult.answer.filter { it.startsWith("v=STSv1", true) }


        // RFC: Nur ein einziger Eintrag darf das Ergebnis sein
        when(mtaStsDnsRecordsStrict.size) {

            0 -> {
                return createMtaStsDnsResultError(domain,false, null,null)
            }
            1 -> {
                val result =  parseDnsRecord(mtaStsDnsRecordsStrict.first())
                result.lastCname = mtaStsDnsDigResult.lastCname
                result.hasADFlag = mtaStsDnsDigResult.adFlag
                return result
            }
            else -> {
                return createMtaStsDnsResultError(domain,false, null,
                    MtaStsDnsRecordError.MultipleDnsRecords)
            }

        }

    }

    public fun fetchDnsRecord(): DigResult {

        val mtaStsDnsDomain = "_mta-sts.$domain"
        val digResult = Dig.dig(mtaStsDnsDomain, "TXT")
        return digResult

    }

    public fun parseDnsRecord(rawDnsRecord: String): MtaStsDnsRecordResult {

        // Wurde ein leerer DNS-Record übergeben
        if (rawDnsRecord.isBlank()) {
            //return createTlsRptResultError(domain, false, rawDnsRecord, TlsRptDnsRecordError.EmptyDnsRecord)
            return createMtaStsDnsResultError(domain, false, rawDnsRecord,
                MtaStsDnsRecordError.EmptyDnsRecord)
        }


        // Versionscheck
        if(!rawDnsRecord.matches(Regex("^v=STSv1\\s*;.*"))) {

            return createMtaStsDnsResultError(domain, false, rawDnsRecord,
                MtaStsDnsRecordError.NoVersionField)

        }else if (!rawDnsRecord.startsWith("v=STSv1;", ignoreCase = false)) {

            return createMtaStsDnsResultError(domain, true, rawDnsRecord,
                MtaStsDnsRecordError.VersionValueMatchesABNFOnly)
        }


        // Strikt am Semikolon aufteilen
        val pairs = splitDnsRecord(rawDnsRecord)


        // Erfasse den ersten ID-Wert
        var id: String? = null

        for (part in pairs) {
            val keyValue = part.split("=", limit = 2)


            if(keyValue.size < 2) {
                return createMtaStsDnsResultError(domain, true, rawDnsRecord,
                    MtaStsDnsRecordError.NoKeyValueFormat)
            }

            val key = keyValue[0]
            val value = keyValue[1]

            // Beachte nur das erste id-Feld
            if(key == "id" && id == null) {

                if(!parseIDValue(value)) {
                    return createMtaStsDnsResultError(domain, true, rawDnsRecord,
                        MtaStsDnsRecordError.InvalidIDField)
                }
                id = value

            } else {
                // Da einmalig vorkommende Felder gemäß RFC ignoriert werden sollen, werden später folgende
                // ID-Felder wie extension-Felder validiert
                //sts-extension-Field: Alle möglichen weiteren Felder werden ebenfalls gemäß ABNF-Vorgaben validiert
                if (!checkDnsExtensionFields(key, value)) {
                    return createMtaStsDnsResultError(domain, true, rawDnsRecord,
                        MtaStsDnsRecordError.SyntaxErrorOtherField)
                }

            }

        }


        //  RFC verlangt in ABNF die Verfügbarkeit des id-Felds (Wert: 1 bis 32 alphanumerische Zeichen)
        if (id == null) {
            return createMtaStsDnsResultError(domain, true, rawDnsRecord,
                MtaStsDnsRecordError.NoIDField)

        }

        return createMtaStsResultValid(domain,rawDnsRecord)
    }



    private fun parseIDValue(value: String): Boolean {

        return value.matches(Regex("^[a-zA-Z0-9]{1,32}$"))

    }


    private fun createMtaStsDnsResultError(domain: String, hasDnsRecord: Boolean, rawRecord: String?,
                                        errorType: MtaStsDnsRecordError?): MtaStsDnsRecordResult {

        return MtaStsDnsRecordResult(domain, hasDnsRecord, rawRecord,null, errorType?.stringText)
    }


    private fun createMtaStsResultValid(domain: String, rawRecord: String?): MtaStsDnsRecordResult {

        return MtaStsDnsRecordResult(domain, true, rawRecord, null ,null)
    }

}