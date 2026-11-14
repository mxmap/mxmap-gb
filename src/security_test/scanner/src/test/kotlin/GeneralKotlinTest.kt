import Dig.createTmpPath
import com.google.common.net.InternetDomainName
import dataClass.DMARC.DMARCResults
import kotlinx.serialization.json.Json
import kotlinx.serialization.decodeFromString
import models.enums.TlsRptDnsRecordError
import org.apache.commons.validator.routines.EmailValidator
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.net.URI
import java.net.URISyntaxException
import java.util.UUID
import kotlin.test.assertTrue
import kotlinx.serialization.Serializable


class GeneralKotlinTest {

    @Test
    public fun testEmpty() {
        val test = ""
        println("hello")
        assertTrue(test.isEmpty())
    }

    @Test
    public fun uriTest() {
        try{
            val parsedUri = URI("https://*0de.de")
            val parsedEmail = URI("mailto:-----@---")
            val schemeURI = parsedUri.scheme?.lowercase()

            val schemeSpecPart = parsedUri.schemeSpecificPart
            val emailDomain = parsedEmail.schemeSpecificPart

            val host = parsedUri.host
        }catch(e: URISyntaxException){
            e.message
        }

    }



    @Test
    public fun validEmailTest() {
        val email = "abc@domain31.test.jetzt"
        val emailVal = EmailValidator.getInstance()


        if(!emailVal.isValid(email)) {
            // Doppelt prüfen
            println(email)
        }
    }

    @Test
    public fun outerFunction() {
        try {
            innerFunction()
        }catch(e: Exception){
            println("outerFunction")
        }
    }


    public fun innerFunction() {
        try {
            throw Exception()
        }catch(e: Exception){
            println("innerFuncion")
        }
    }


    @Test
    public fun testpublicSuffix() {
        val retGOVUK = domainSuffixTest("email.liverpool.gov.uk")
        assertEquals("liverpool.gov.uk", retGOVUK)

        val retDE = domainSuffixTest("email.liverpool.gov.de")
        assertEquals("gov.de", retDE)
    }


    public fun domainSuffixTest(domain: String):String? {
        val domainName = InternetDomainName.from(domain)
        val publicSuffix = domainName.publicSuffix()

        var orgDomainOld : String? = null

        if(publicSuffix != null) {
            val labelList = domainName.parts()
            val domainLabelCount = labelList.size
            val publicSuffixCount = publicSuffix.parts().size
            // Nur das erste Domainlabel vor dem public Suffix in OrgDomain berücksichtigen
            if(domainLabelCount > publicSuffixCount) {
                orgDomainOld = labelList.drop(domainLabelCount - publicSuffixCount - 1).joinToString(".")
            }
        }

        return orgDomainOld

    }


    @Test
    public fun testDeserialization() {
        val minimalTest = pathDiscovery("v=DMARC1; p=none; pct=10; ri=11")
        //assertEquals(minimal, pathDiscovery())

        val multipleReports = pathDiscovery("v=DMARC1; p=none; rua=mailto:dmarc@test.de, mailto:dmarc@test2.de; ruf=mailto:dmarc@test3.de, mailto:dmarc@test2.de")

        val syntaxError = pathDiscovery("v=DMARC1; p=none; rua=mailto:dmarc@test.de,, mailto:dmarc@test2.de; ruf=mailto:dmarc@test3.de, mailto:dmarc@test2.de")

        val tooHighPercent =  pathDiscovery("v=DMARC1; p=none; rua=mailto:dmarc@test.de, mailto:dmarc@test2.de; ruf=mailto:dmarc@test3.de, mailto:dmarc@test2.de ; pct=101")

        val unknownField = pathDiscovery("v=DMARC1; p=none; un=true; rua=mailto:dmarc@test.de, mailto:dmarc@test2.de; ruf=mailto:dmarc@test3.de, mailto:dmarc@test2.de")

        val wrongTValue = pathDiscovery("v=DMARC1; p=none; t=e ; rua=mailto:dmarc@test.de, mailto:dmarc@test2.de; ruf=mailto:dmarc@test3.de, mailto:dmarc@test2.de ; pct=99")
        //val explicitRiPct = pathDiscovery()

        val explicitPolicyValue = pathDiscovery("v=DMARC1; rua=mailto:dmarc@test.de, mailto:dmarc@test2.de; ruf=mailto:dmarc@test3.de, mailto:dmarc@test2.de ; pct=99")


        val policyAsSecondTag = pathDiscovery("v=DMARC1; rua=mailto:dmarc@test.de, mailto:dmarc@test2.de; p=none; ruf=mailto:dmarc@test3.de, mailto:dmarc@test2.de ; pct=99")

        print(wrongTValue)
        //val ignoreUnknownElement = pathDiscovery()


        //val withReportAddresses = pathDiscovery()


        //val tooHighPercentValue = pathDiscovery()

    }


    public fun pathDiscovery(dmarcRecord: String ): DMARCResults? {

        // Holt den 100% korrekten Pfad direkt vom Betriebssystem (z.B. C:\WINDOWS\system32\cmd.exe)
        val cmdPath = System.getenv("ComSpec") ?: "cmd.exe"

        // Dein Python-Skript
        val scriptFile = File(".\\SPF_DMARC_Scripts\\dmarcSyntaxCheck.py")

        if (!scriptFile.exists()) {
            println("ACHTUNG: Das Skript existiert nicht unter: ${scriptFile.absolutePath}")
        }

        // Wir übergeben cmdPath als allererstes Argument
        val pb = ProcessBuilder(
            cmdPath,
            "/c",
            "python",
            scriptFile.absolutePath,
            "domain.de",
            dmarcRecord
        )

        pb.redirectErrorStream(true) // Fehler von Python in den normalen Output leiten

        try {

            val process = pb.start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            val exitCode = process.waitFor()

            val dmarcResult = Json.decodeFromString<DMARCResults>(output)
            return dmarcResult
            println("=== ERGEBNIS ===")
            println("Exit-Code: $exitCode")
            println("Ausgabe:\n$output")

        } catch (e: Exception) {
            println("Es gab immer noch einen Fehler: ${e.message}")
        }

        return null

        /*
        val pb = ProcessBuilder("C:\\Windows\\System32\\cmd.exe","/c", "python", ".\\SPF_DMARC_Scripts\\dmarcSyntaxCheck.py", "domain.de", "\"v=DMARC1 p=none\"")

        val logfile = File(logfilepath)
        pb.redirectOutput(ProcessBuilder.Redirect.appendTo(logfile))
        pb.redirectError(ProcessBuilder.Redirect.appendTo(logfile))
        val exitcode = pb.start().waitFor()

        val log = File(logfilepath).readText(Charsets.UTF_8)
        print(log)
        logfile.delete()
        */


    }


}

