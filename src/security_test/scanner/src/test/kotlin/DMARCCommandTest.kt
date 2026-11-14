import Measurement.rateLimiterDss
import com.google.common.util.concurrent.RateLimiter
import commands.DMARCCommand
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import models.DssResult
import models.dataClass.DigResult
import org.junit.*
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap





class DMARCCommandTest {



    /*
    @Test
    fun dnsTreeWalkTest() = runTest {
        // Vorbereitung der gefälschten DNS-Zonen

        // psd=n
        val fakeDnsZonePsdN = mapOf(
            "_dmarc.sub.sub.gov.uk" to emptyList(), // Kein DMARC
            "_dmarc.sub.gov.uk" to emptyList(),     // Kein DMARC
            "_dmarc.gov.uk" to listOf("v=DMARC1; p=reject; psd=n"), // DMARC vorhanden + Stop Condition
            "_dmarc.com" to emptyList()                  // Wird nicht mehr erreicht wegen Stop Condition
        )

        // psd=y
        val fakeDnsZonePsdY = mapOf(
            "_dmarc.sub.sub.gov.uk" to emptyList(), // Kein DMARC
            "_dmarc.sub.gov.uk" to listOf("v=DMARC1; p=reject;"),     // DMARC ohne psd-Tag
            "_dmarc.gov.uk" to listOf("v=DMARC1; p=reject; psd=y"), // DMARC vorhanden + Stop Condition
            "_dmarc.com" to listOf("v=DMARC1; p=reject;")            // Wird nicht mehr erreicht wegen Stop Condition
        )

        // psd=y und multiple Records
        val fakeDnsZoneNoPsd = mapOf(
            "_dmarc.sub.sub.gov.uk" to listOf("v=DMARC1; p=reject;"), // DMARC vorhanden
            "_dmarc.sub.gov.uk" to listOf("v=DMARC1; p=reject;", "v=DMARC1; p=reject;"),     // DMARC vorhanden, aber mehrere Einträge
            "_dmarc.gov.uk" to listOf("v=DMARC1; p=reject;"), // DMARC vorhanden
            "_dmarc.uk" to emptyList()
        )


        val fakeDnsZoneMoreThanEightLabels = mapOf(
            "_dmarc.a.b.c.d.e.f.g.h.gov.uk" to listOf("v=DMARC1; p=reject;"), // DMARC vorhanden


            // Diese EInträge sollte NICHT im Ergebnis vorkommen
            "_dmarc.b.c.d.e.f.g.h.gov.uk" to listOf("v=DMARC1; p=reject;"),// DMARC vorhanden
            "_dmarc.c.d.e.f.g.h.gov.uk" to listOf("v=DMARC1; p=reject;"),// DMARC vorhanden

            // Beachte den Sonderfall! Hier müsste vom Programm auf 7 Label +DMARC Label abekürzt werden!
            // Diese EInträge sollten im Lookup Cache wieder vorkommen!
            "_dmarc.d.e.f.g.h.gov.uk" to listOf("v=DMARC1; p=reject;"),// DMARC vorhanden
            "_dmarc.e.f.g.h.gov.uk" to listOf("v=DMARC1; p=reject;"),// DMARC vorhanden
            "_dmarc.f.g.h.gov.uk" to listOf("v=DMARC1; p=reject;"),// DMARC vorhanden
            "_dmarc.g.h.gov.uk" to listOf("v=DMARC1; p=reject;"),// DMARC vorhanden
            "_dmarc.h.gov.uk" to emptyList(),
            "_dmarc.gov.uk" to listOf("v=DMARC1; p=reject;"), // DMARC vorhanden
            "_dmarc.uk" to emptyList()
        )

        val fakeDig = createMockDigFunction(fakeDnsZonePsdN)


        val cache = ConcurrentHashMap<String, DigResult>()
        val rateLimiter = RateLimiter.create(1.0) // Hoher Wert, damit der Test nicht künstlich blockiert

        val command = DMARCCommand(
            domain = "sub.sub.gov.uk",
            dmarcLookupCache = cache
        )

        command.digResolve = fakeDig

        // 2. Act: Führe die Funktion aus
        command.dnsTreeWalkPolicy(rateLimiter)

        // 3. Assert: Überprüfe die Ergebnisse des Tree-Walks

        // Hat er gov.uk im Cache gespeichert?
        assertTrue(command.cachedTreeWalkPolicyResults.containsKey("gov.uk"))

        val cachedRecord = command.cachedTreeWalkPolicyResults["gov.uk"]?.getFirstAnswer
        assertEquals("v=DMARC1; p=reject; psd=n", cachedRecord)
        // Hat er das PSD-Flag korrekt verarbeitet? (psd=n sollte nicht als PSD-Domain gesetzt werden)
        assertNull(command.newPsdDomain)




        // 2. Testfall psd=y

        val fakeDig2 = createMockDigFunction(fakeDnsZonePsdY)

        val cache2 = ConcurrentHashMap<String, DigResult>()

        val command2 = DMARCCommand(
            domain = "sub.sub.gov.uk",
            dmarcLookupCache = cache2
        )

        command2.digResolve = fakeDig2

        // 2. Act: Führe die Funktion aus
        command2.dnsTreeWalkPolicy(rateLimiter)
        assertTrue(command2.cachedTreeWalkPolicyResults.containsKey("gov.uk"))
        assertTrue(!command2.cachedTreeWalkPolicyResults.containsKey("_dmarc.sub.gov.uk")) // Mehrere Einträge
        assertTrue(command2.cachedTreeWalkPolicyResults.containsKey("sub.gov.uk"))
        assertEquals("gov.uk",command2.newPsdDomain)


        val command3 = createDMARCCommandObject(fakeDnsZoneMoreThanEightLabels)

        command3.dnsTreeWalkPolicy(rateLimiter)
        assertTrue(command3.cachedTreeWalkPolicyResults.containsKey("gov.uk"))
        assertTrue(!command3.cachedTreeWalkPolicyResults.containsKey("h.gov.uk"))
        assertNull(command3.newPsdDomain)


    }



    */


    // Mocken von Dig-Command
    private fun createMockDigResult(answers: List<String>, lastcname: String?): DigResult {
        val mockResult = DigResult(
            answers,
            if(lastcname == null) { listOf()} else { listOf(lastcname)},
            false
        )

        return mockResult
    }




    // Mock-DMARC Command  erstellen mit
    suspend fun createDMARCCommandObject(test: DMARCTest, cache: ConcurrentHashMap<String, DigResult>): DMARCCommand {
        val fakeDig = createMockDigFunction(test)

        val command = DMARCCommand(
            // Erster Eintrag ohne dmarc-Prefix
            domain = test.domain,
            dmarcLookupCache = cache
        )

        command.digResolve = fakeDig

        return command
    }


    // Mock Dig-Funktion erstellen
    suspend fun createMockDigFunction(test: DMARCTest): suspend (String, String) -> DigResult {
        // Fake Dig-Command -> Gebe für die angefragte Domain eine Fake
        val fakeDig: suspend (String, String) -> DigResult = { domain, _ ->

            // Sucht in der übergebenen Liste nach dem Eintrag zur Domain
            val records = test.mockEntries[domain] ?: emptyList()

            // Gibt Mock-Objekt für die mit den übergebenen Fake-Einträgen zurück
            createMockDigResult(records, test.lastcname)
        }

        return fakeDig
    }



    // Simuliere einen prallelen Aufruf von checkDmarc

    suspend fun testDmarcTest( test: DMARCTest ,cache: ConcurrentHashMap<String, DigResult>, rateLimiter: RateLimiter) {

        val command = createDMARCCommandObject(test, cache)
        val result = command.testDMARC(rateLimiter)

        // Gebe Ergebnis auf Konsole aus
        val jsonFormat = Json{ prettyPrint = true; encodeDefaults = true }
        println("ERGEBNIS FÜR DOMAIN ${test.domain}:")
        println(jsonFormat.encodeToString(result))
        //Breakpoint

    }


    fun dmarcTestAsync( domainList: List<DMARCTest>) {

        val dmarcTest = mutableListOf<DssResult>()

        val mutex = Mutex()

        val threadCount = Runtime.getRuntime().availableProcessors() * Config.get<Int>("SCAN_THREAD_MULTIPLIER")
        val semaphore = Semaphore(threadCount)

        val logger = LoggerFactory.getLogger(DMARCCommandTest::class.java)

        logger.info("starting to check SPF and DMARC (dss)")
        logger.info("using $threadCount threads")
        logger.info("using a rate limit of ${rateLimiterDss.rate.toInt()} queries per second")
        val starttime = System.currentTimeMillis()

        // "entlade" den RateLimiter
        val rateLimiter = RateLimiter.create(5.0)

        runBlocking {
            var finishCounter = 0
            var startCounter = 0

            val cache: ConcurrentHashMap<String, DigResult> = ConcurrentHashMap()


            domainList.forEach { DMARCTest ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {
                        mutex.withLock {
                            startCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: scan: started ($startCounter from ${domainList.size})")
                        }

                        rateLimiter.acquire()
                        testDmarcTest(DMARCTest, cache, rateLimiter)

                        mutex.withLock {

                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:scan: fully finished ($finishCounter from ${domainList.size})")
                        }


                    }
                }
            }
        }


        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:finished dss scan")
    }




    fun dmarcTestSync( domainList: List<DMARCTest>) {

        val dmarcTest = mutableListOf<DssResult>()

        val mutex = Mutex()

        val threadCount = Runtime.getRuntime().availableProcessors() * Config.get<Int>("SCAN_THREAD_MULTIPLIER")
        val semaphore = Semaphore(threadCount)

        //val logger = LoggerFactory.getLogger(DMARCCommandTest::class.java)

        //logger.info("starting to check SPF and DMARC (dss)")
        //logger.info("using $threadCount threads")
        //logger.info("using a rate limit of ${rateLimiterDss.rate.toInt()} queries per second")
        val starttime = System.currentTimeMillis()

        // "entlade" den RateLimiter
        val rateLimiter = RateLimiter.create(5.0)


        var finishCounter = 0
        var startCounter = 0

        val cache: ConcurrentHashMap<String, DigResult> = ConcurrentHashMap()

        runBlocking{
        domainList.forEach { DMARCTest ->

            rateLimiter.acquire()
            testDmarcTest(DMARCTest, cache, rateLimiter)

        }
        }


        //logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:finished dss scan")
    }




    @Test
    fun testDmarcTestcases() {

        var dmarcTest: (List<DMARCTest>) -> Unit =
            { list -> dmarcTestAsync(list) }


        // Testcase 1:
        val domainList: MutableList<DMARCTest> = mutableListOf<DMARCTest>()


        val fakeBayernDNSPath = mapOf (
            "_dmarc.de" to emptyList(),
            "_dmarc.bayern.de" to listOf("v=DMARC1; p=reject; rua=mailto:dmarc@bayern.de, mailto:dmarc2@bayern.de, mailto:dmarc@externValid.de, mailto:dmarc@externInvalid.de; ruf=mailto:dmarc@bayern.de, mailto:dmarc@bayern.de, mailto:dmarc@externNotAuth.de"),
            "_dmarc.kommune.bayern.de" to emptyList(),
            "bayern.de._report._dmarc.externvalid.de" to listOf("v=DMARC1"),
            "bayern.de._report._dmarc.externinvalid.de" to listOf("c=DMARC1")

        )
        val fakeDNS = fakeBayernDNSPath
        val lastcname = "microsoft.com"

        // DMARC direkt bei DOmain
        println("DMARC direkt bei DOmain")
        domainList.add(DMARCTest("bayern.de", fakeDNS,lastcname))

        // DMARC in übergeordneter Domain
        println("DMARC in übergeordneter Domain")
        domainList.add(DMARCTest("kommune.bayern.de", fakeDNS, lastcname))


        // Caching Test -> Ergebnis sollte wie im Fall 1 sein!
        /*
        val emptyBayernDnsPath = mapOf<String,List<String>> (
            "_dmarc.de" to emptyList(),
            "_dmarc.bayern.de" to emptyList(),
            "_dmarc.kommune.bayern.de" to emptyList(),
            "bayern.de._report._dmarc.externValid.de" to emptyList(),
            "bayern.de._report._dmarc.externInvalid.de" to emptyList()

        )
        */
        println("Caching Test -> Ergebnis sollte wie im Fall 1 sein!")
        domainList.add(DMARCTest("kommune.bayern.de", fakeDNS, lastcname))
        dmarcTest(domainList)
        /*
        // Cache löschen
        domainList.clear()


        val fakeBayernDNSNoDMARC = mapOf<String,List<String>> (
            "_dmarc.de" to emptyList(),
            "_dmarc.bayern.de" to emptyList(),
            "_dmarc.kommune.bayern.de" to emptyList()

        )
        println("Kein DMARC vorhanden!")
        // Kein DMARC vorhanden
        domainList.add(DMARCTest("kommune.bayern.de", fakeBayernDNSNoDMARC, lastcname))

        dmarcTest(domainList)
        domainList.clear()



        val fakeBayernSyntaxError = mapOf<String,List<String>> (
            "_dmarc.de" to emptyList(),
            "_dmarc.bayern.de" to listOf("v=DMARC1; p=reject;", "v=DMARC1; p=reject;"),
            "_dmarc.kommune.bayern.de" to listOf("v=DMARC1; p=f")
        )
        // SyntaxError
        println("Syntax Error!")
        domainList.add(DMARCTest("kommune.bayern.de", fakeBayernSyntaxError, lastcname))

        // Mehrere DMARC-Einträge
        println("Mehrere DMARC-Einträge!")
        domainList.add(DMARCTest("bayern.de", fakeBayernSyntaxError, lastcname))
        dmarcTest(domainList)
        domainList.clear()

        // sp-Policy
        val fakeBayernSPTagSubdomain= mapOf<String,List<String>> (
            "_dmarc.de" to emptyList(),
            "_dmarc.bayern.de" to listOf("v=DMARC1; p=reject; sp=none"),
            "_dmarc.kommune.bayern.de" to listOf()
        )
        println("Sp-Policy für Subdomain")
        domainList.add(DMARCTest("kommune.bayern.de", fakeBayernSPTagSubdomain, lastcname))
        dmarcTest(domainList)
        domainList.clear()


        // psd=n
        val fakeDnsZonePsdN = mapOf(
            "_dmarc.sub.sub.gov.uk" to emptyList(), // Kein DMARC
            "_dmarc.sub.gov.uk" to listOf("v=DMARC1;  p=reject; sp=none;psd=n; pct=1"),     // DMARC vorhanden + Stop Condition
            "_dmarc.gov.uk" to listOf("v=DMARC1; p=none;"), // DMARC
            "_dmarc.com" to emptyList()                  // Wird nicht mehr erreicht wegen Stop Condition
        )

        println("psd=n")
        domainList.add(DMARCTest("sub.sub.gov.uk", fakeDnsZonePsdN, null))
        dmarcTest(domainList)
        domainList.clear()


        // psd=y
        val fakeDnsZonePsdY = mapOf(
            "_dmarc.sub1.sub1.gov.uk" to emptyList(), // Kein DMARC
            "_dmarc.sub1.gov.uk" to listOf("v=DMARC1; p=reject;"),     // DMARC ohne psd-Tag
            "_dmarc.gov.uk" to listOf("v=DMARC1; p=reject; psd=y"), // DMARC vorhanden + Stop Condition
            "_dmarc.uk" to listOf("v=DMARC1; p=reject;")            // Wird nicht mehr erreicht wegen Stop Condition
        )
        println("psd=y")
        domainList.add(DMARCTest("sub1.sub1.gov.uk", fakeDnsZonePsdY, null))
        dmarcTest(domainList)
        domainList.clear()


        // kein psd und multiple Records
        val fakeDnsZoneNoPsd = mapOf(
            "_dmarc.sub2.sub2.gov.uk" to listOf("v=DMARC1; p=reject;"), // DMARC vorhanden
            "_dmarc.sub2.gov.uk" to listOf("v=DMARC1; p=reject;", "v=DMARC1; p=reject;"),     // DMARC vorhanden, aber mehrere Einträge
            "_dmarc.gov.uk" to listOf("v=DMARC1; p=none;"), // DMARC vorhanden
            "_dmarc.uk" to emptyList()
        )
        println("No PSD in hierarchy")
        domainList.add(DMARCTest("sub2.sub2.gov.uk", fakeDnsZoneNoPsd, null))
        dmarcTest(domainList)
        domainList.clear()



        // kein psd und multiple Records
        val fakeDnsZonePsdYFirstDomain = mapOf(
            "_dmarc.sub3.sub3.gov.uk" to listOf("v=DMARC1; p=none; psd =y;"), // DMARC vorhanden
            "_dmarc.sub3.gov.uk" to emptyList(),     // DMARC vorhanden, aber mehrere Einträge
            "_dmarc.gov.uk" to listOf("v=DMARC1; p=reject"), // DMARC vorhanden
            "_dmarc.uk" to emptyList()
        )
        println("PSD FirstElem in hierarchy")
        domainList.add(DMARCTest("sub3.sub3.gov.uk", fakeDnsZonePsdYFirstDomain, null))
        dmarcTest(domainList)
        domainList.clear()


        val fakeDnsZoneMoreThanEightLabels = mapOf(
            "_dmarc.a.b.c.d.e.f.g.h.gov.uk" to emptyList(), // DMARC vorhanden


            // Diese EInträge sollte NICHT im Ergebnis vorkommen
            "_dmarc.b.c.d.e.f.g.h.gov.uk" to listOf("v=DMARC1; p=reject ; psd=n"),// DMARC vorhanden
            "_dmarc.c.d.e.f.g.h.gov.uk" to listOf("v=DMARC1; p=reject ; psd=y"),// DMARC vorhanden

            // Beachte den Sonderfall! Hier müsste vom Programm auf 7 Label +DMARC Label abekürzt werden!
            // Diese EInträge sollten im Lookup Cache wieder vorkommen!
            "_dmarc.d.e.f.g.h.gov.uk" to listOf("v=DMARC1; p=reject; pct=10"),// DMARC vorhanden
            "_dmarc.e.f.g.h.gov.uk" to listOf("v=DMARC1; p=reject;"),// DMARC vorhanden
            "_dmarc.f.g.h.gov.uk" to listOf("v=DMARC1; p=reject;"),// DMARC vorhanden
            "_dmarc.g.h.gov.uk" to listOf("v=DMARC1; p=reject;"),// DMARC vorhanden
            "_dmarc.h.gov.uk" to listOf("v=DMARC1; p=reject; sp=none"),
            "_dmarc.gov.uk" to listOf("v=DMARC1; p=reject;"), // DMARC vorhanden
            "_dmarc.uk" to emptyList()
        )


        println("More than 8 labels domain")
        domainList.add(DMARCTest("a.b.c.d.e.f.g.h.gov.uk", fakeDnsZoneMoreThanEightLabels, null))
        dmarcTest(domainList)
 */
        }


}


data class DMARCTest(val domain: String, val mockEntries: Map<String, List<String>>, val lastcname: String?)

