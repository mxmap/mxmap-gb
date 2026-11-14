
import com.google.common.util.concurrent.RateLimiter
import commands.DKIMCommand
import commands.DMARCCommand
import commands.DNSSECCommand
import commands.MtaStsDnsRecordCommand
import commands.MtaStsPolicyCommand
import commands.SPFCommand
import commands.TLS_1_2_Command
import commands.TlsHttpCertCheck
import commands.TlsRptDnsRecordCommand
import commands.TlsSmtpCertCheck
import dataClass.DKIM.DKIMResult
import dataClass.DMARC.DMARCMeasurementResult
import dataClass.DMARC.DMARCPolicy
import dataClass.DNSSEC.DNSSECResult
import dataClass.SPF.SPFResult
import dataClass.TLS.TLS_1_2_AllResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.asFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import models.DaneCheckResult
import dataClass.SCAN.DomainMX
import models.DssResult
import dataClass.SCAN.ScanData
import dataClass.SCAN.ScanDataNotNullable
import models.TestSSLResult
import models.dataClass.DigResult
import dataClass.MTASTS.MtaStsDnsRecordResult
import dataClass.MTASTS.MtaStsPolicy
import dataClass.TLS.TLSDataCollector
import dataClass.TLS.TlsRptDnsRecordResult
import dataClass.TLS.tlsRequirements
import models.enums.TlsCertError
import org.slf4j.LoggerFactory
import processes.DSSCommand
import processes.DaneCommand
import processes.DaneCommandResult
import processes.DssCommandResult
import processes.TlsCommand
import processes.TlsCommandResult
import java.util.concurrent.ConcurrentHashMap
import kotlin.collections.set
import kotlin.contracts.contract
import kotlin.time.Duration.Companion.seconds

object Measurement {

    val mutex = Mutex()

    val threadCount = Runtime.getRuntime().availableProcessors() * Config.get<Int>("SCAN_THREAD_MULTIPLIER")
    val semaphore = Semaphore(3)

    val logger = LoggerFactory.getLogger(Measurement::class.java)

    val rateLimiterTls = RateLimiter.create(Config["TLS_TRIES_PER_SECOND"])
    val rateLimiterDss = RateLimiter.create(Config["DSS_TRIES_PER_SECOND"])
    val rateLimiterMtaStsPolicy = RateLimiter.create(1.0)
    val rateLimiterDnssec = RateLimiter.create(2.0)
    val rateLimiterSPF = RateLimiter.create(0.15) // vorher 0.25 (für GB)



    // Genereller SMTP-TLS-Check -> Sammle Zertifikatsdaten.
    // Zudem ist der Test notwendig für MTA-STS,
    // denn man benötigt mindestens TLS 1.2. für MTA-STS und ein vertrauenswürdiges Zertifikat!
    fun mxTlsCertTest( mxServer: List<String>):List<TLSDataCollector> {


        logger.info("starting to measure tls and cert data from domains")
        logger.info("using $threadCount threads for resolving MX records")
        logger.info("using a rate limit of ${rateLimiterTls.rate.toInt()} queries per second")

        rateLimiterTls.acquire()

        val starttime = System.currentTimeMillis()

        val smtpCertResults = mutableListOf<TLSDataCollector>()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0

            logger.info("starting tls cert scan")

            mxServer.forEach { mxRecord ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {


                        // Teste mit einem Retry

                        mutex.withLock {
                            startCounter += 1

                        }

                        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:tls cert scan: started for ${mxRecord} ($startCounter from ${mxServer.size})")
                        rateLimiterTls.acquire()
                        val mxTlsCertTest = TlsSmtpCertCheck(mxRecord)
                        var smtpTlsTest = mxTlsCertTest.testSmtpTlsHandshake()

                        if(smtpTlsTest != null && smtpTlsTest?.errorType != null) {
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:tls cert scan encountered an error. retrying once for ${mxRecord}  ($startCounter from ${mxServer.size})")
                            delay(1.seconds)

                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:tls cert scan: started for ${mxRecord} ($startCounter from ${mxServer.size})")
                            rateLimiterTls.acquire()
                            smtpTlsTest = mxTlsCertTest.testSmtpTlsHandshake()

                        }



                        mutex.withLock {
                            if(smtpTlsTest != null) {

                                smtpCertResults.add(smtpTlsTest)

                            }
                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:tls cert scan: finished for ${mxRecord} ($finishCounter from ${mxServer.size})")
                        }


                    }
                }
            }
        }
        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: finished tls cert scan")


        return smtpCertResults
    }


    // Testet, ob eine Domain einen DNS-Eintrag für MTA-STS hinterlegt hat
    fun mtaStsDnsRecordTest( domainList: List<String>):List<MtaStsDnsRecordResult> {


        logger.info("starting to lookup MTASTS dns records for domains")
        logger.info("using $threadCount threads")
        logger.info("using a rate limit of ${rateLimiterDss.rate.toInt()} queries per second")

        rateLimiterDss.acquire()

        val starttime = System.currentTimeMillis()

        val mtaStsResults = mutableListOf<MtaStsDnsRecordResult>()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0


            domainList.forEach { domain ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {


                        mutex.withLock {
                            startCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsDnsRec scan: started for $domain ($startCounter from ${domainList.size})")
                        }


                        rateLimiterDss.acquire()
                        val dnsRecordClass = MtaStsDnsRecordCommand(domain)
                        val dnsRecord = dnsRecordClass.getMtaStsDnsRecord()

                        mutex.withLock {
                            mtaStsResults.add(dnsRecord)
                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsDnsRec scan: finished for $domain ($finishCounter from ${domainList.size})")
                        }


                    }
                }
            }
        }
        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: finished mtaStsDnsRecord scan")


        return mtaStsResults
    }





    // Testet die MTA-STS Policy für Domains, die einen MTA-STS DNS-Eintrag hinterlegt haben
    fun mtaStsPolicyTest( domainList: List<MtaStsDnsRecordResult>):List<MtaStsPolicy> {



        logger.info("starting to test mta-Sts-Policy")
        logger.info("using $threadCount threads")
        logger.info("using a rate limit of ${rateLimiterMtaStsPolicy.rate.toInt()} queries per second")

        rateLimiterMtaStsPolicy.acquire()

        val starttime = System.currentTimeMillis()

        val mtaStsPolicyResults = mutableListOf<MtaStsPolicy>()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0


            domainList.filter{it.hasRecord}.forEach { dnsRes ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {

                        val policy = MtaStsPolicyCommand(dnsRes.domain)


                        mutex.withLock {
                            startCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy scan: started for ${dnsRes.domain} ($startCounter from ${domainList.size})")
                        }
                        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy start fetching A-Record for ${dnsRes.domain}")
                        rateLimiterMtaStsPolicy.acquire()
                        val dnsARecordRes = policy.discoverPolicyARecord()
                        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy scan fetched A-Record for ${dnsRes.domain}")

                        // Nur wenn ein A-Record für die mta-sts. Domain hinterlegt ist, werden die weiteren Tests durchgeführtS
                        val policyResult = if(dnsARecordRes.hasARecord) {

                            // Wo ist IP von der MTA-STS-Policy-Registriert?
                            delay(1.seconds)
                            rateLimiterMtaStsPolicy.acquire()
                            policy.setCCForPolicyIP(dnsARecordRes)


                            // Webserver TLS-Test
                            delay(1.seconds)
                            rateLimiterMtaStsPolicy.acquire()
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy start testing TLS for ${dnsRes.domain}")
                            var tlstestRes = policy.testTLSHandshake()

                            if(tlstestRes != null && tlstestRes?.errorType != null) {
                                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy TLS test encountered an error. retrying once for ${dnsRes.domain}")
                                delay(1.seconds)
                                rateLimiterMtaStsPolicy.acquire()
                                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy start testing TLS for ${dnsRes.domain}")
                                tlstestRes = policy.testTLSHandshake()
                            }
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy tested TLS for ${dnsRes.domain}")


                            // HTTPS-Policy-Abruf
                            delay(1.seconds)
                            rateLimiterMtaStsPolicy.acquire()
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy start retrieving Policy for ${dnsRes.domain}")
                            var retrievalRes = policy.retrievePolicy()

                            if(retrievalRes != null && tlstestRes?.errorType != null) {
                                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy retrieval encountered an error. retrying once for ${dnsRes.domain}")
                                delay(1.seconds)
                                rateLimiterMtaStsPolicy.acquire()
                                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy start retrieving Policy for ${dnsRes.domain}")
                                retrievalRes = policy.retrievePolicy()
                            }
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy finished retrieving Policy for ${dnsRes.domain}")

                            // Validierung der abgerufenen MTA-STS-Policy
                            val validateRes = policy.validatePolicy(retrievalRes.rawPolicy)
                            policy.createPolicyObject(dnsARecordRes, tlstestRes, retrievalRes, validateRes)

                        }else {
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy no A-Record found for ${dnsRes.domain}")
                            policy.createPolicyObject(dnsARecordRes,null, null, null)
                        }


                        mutex.withLock {

                            mtaStsPolicyResults.add(policyResult)
                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:mtaStsPolicy scan: finished for ${dnsRes.domain} ($finishCounter from ${domainList.size})")
                        }


                    }
                }
            }
        }
        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: finished mtaStsPolicy scan")


        return mtaStsPolicyResults
    }

    // Test je Domain auf TLS-Reporting
    fun tlsRptDnsRecordTest( domainList: List<String>):List<TlsRptDnsRecordResult> {


        logger.info("starting to lookup tlsrpt from domains")
        logger.info("using $threadCount threads")
        logger.info("using a rate limit of ${rateLimiterDss.rate.toInt()} queries per second")

        rateLimiterDss.acquire()

        val starttime = System.currentTimeMillis()

        val tlsRptDnsResults = mutableListOf<TlsRptDnsRecordResult>()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0


            domainList.forEach { domain ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {



                        val dnsRecordClass = TlsRptDnsRecordCommand(domain)


                        mutex.withLock {
                            startCounter += 1

                        }
                        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:tlsrptDnsRec scan: started for $domain ($startCounter from ${domainList.size})")
                        rateLimiterDss.acquire()
                        val dnsRecord = dnsRecordClass.getTlsrptDnsRecord(rateLimiterDss)

                        mutex.withLock {

                            tlsRptDnsResults.add(dnsRecord)
                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:tlsrptDnsRec scan: finished for $domain ($finishCounter from ${domainList.size})")
                        }


                    }
                }
            }
        }
        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: finished tlsrpt scan")


        return tlsRptDnsResults
    }


    // Testfunktion für die unterstützten TLS-Versionen
    fun tlsVersionRangeTest( mxRecords: List<String>):List<TestSSLResult> {

        val testSSLResults = mutableListOf<TestSSLResult>()

        logger.info("starting to check supported tls versions")
        logger.info("using $threadCount threads")
        logger.info("using a rate limit of ${rateLimiterTls.rate.toInt()} queries per second")
        val starttime = System.currentTimeMillis()

        //entlade den RateLimiter
        rateLimiterTls.acquire()

        runBlocking {
            mxRecords.forEach { mxRecord ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {
                        // Neu: Prüfe nur noch auf MX-Host-Ebene
                        val tlsResult = testTls(mxRecord, rateLimiterTls, starttime)

                        // Globaler Mutex um Ergebnis der globalen Liste hinzuzufügen
                        mutex.withLock {
                            testSSLResults.add(
                                TestSSLResult(
                                    mxRecord,
                                    tlsResult.exitCode, tlsResult.consoleLog
                                )
                            )
                        }

                        /*
                    // Anlegen bzw. erlangen des Mutexes je Mailserver bzw. IpAdresse
                    val mxMutex = mxMutexes.getOrPut(mxAndIP.mxRecord) { Mutex() }
                    //val ipMutex = ipMutexes.getOrPut(mxAndIP.ipAddress) { Mutex() }

                    // erst MX dann IP sperren. Deadlocks möglichst vermeiden
                    mxMutex.withLock {
                        //ipMutex.withLock {

                            val now = System.currentTimeMillis()
                            val lastMxTime = lastScannedMx[mxAndIP.mxRecord] ?: 0L
                            //val lastIpTime = lastScannedIp[mxAndIP.ipAddress] ?: 0L

                            val timeSinceLastMx = now - lastMxTime
                            //val timeSinceLastIp = now - lastIpTime

                            // Berechne die nötige Wartezeit für MX und IP
                            val delayMx = if (lastMxTime != 0L && timeSinceLastMx < minDelayMX) {
                                minDelayMX - timeSinceLastMx
                            } else {
                                0L
                            }


                            /*
                            val delayIp = if (lastIpTime != 0L && timeSinceLastIp < minDelayIP) {
                                minDelayIP - timeSinceLastIp
                            } else {
                                0L
                            }

                             */

                            // Größtmögliche Wartezeit (je Nachdem, ob Mx oder Ip als letztes verwendet wurde) -> (1 Sekunde mindestens!)
                            val waitTime = maxOf(delayMx,  1L)

                            // Verzögere (prüfe nur zur sicherheit auf pos. Wert)
                            if (waitTime > 0) {
                                delay(waitTime.seconds)
                            }

                            // Semaphor dennoch nötig: Der Codeabschnitt könnte von mehreren Coroutines gleichtzeitig ausgeführt werden
                            semaphoreTls.withPermit {
                                rateLimiter.acquire()

                                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s] started for ${mxAndIP.ipAddress} ${mxAndIP.mxRecord}")

                                val tlsResult = testTls(mxAndIP.mxRecord, mxAndIP.ipAddress, rateLimiterTls, Config["TLS_RETRIES"], starttime )

                                    // Globaler Mutex um Ergebnis der globalen Liste hinzuzufügen
                                    mutex.withLock {
                                        testSSLResults.add(TestSSLResult(mxAndIP.mxRecord, mxAndIP.ipAddress,
                                            tlsResult.exitCode, tlsResult.consoleLog))
                                    }

                                }

                                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s] ended for ${mxAndIP.ipAddress} ${mxAndIP.mxRecord}")
                                // Zeitstempel wann TLS Versions-Scan beendet wurde aktualisieren
                                val completionTime = System.currentTimeMillis()
                                lastScannedMx[mxAndIP.mxRecord] = completionTime
                                lastScannedIp[mxAndIP.ipAddress] = completionTime
                            }
                        }

                     */

                    }

                    }


                }
            }
            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:  finished tls version range scan")
            return testSSLResults
        }






    // Testfunktion für  DMARC
    fun dmarcTest( domainList: List<String>): DMARCMeasurementResult {

        val dmarcResults = mutableListOf<DMARCPolicy>()
        val externalReportingDomains = mutableListOf<String>()

        logger.info("starting to check DMARC")
        logger.info("using $threadCount threads")
        logger.info("using a rate limit of ${rateLimiterDss.rate.toInt()} queries per second")
        val starttime = System.currentTimeMillis()

        // "entlade" den RateLimiter
        rateLimiterDss.acquire(2)

        runBlocking {
            var finishCounter = 0
            var startCounter = 0

            // Dient als Cache für bereits getätigte DMARC-DNS-Abfragen
            val dmarcDnsCache: ConcurrentHashMap<String, DigResult> = ConcurrentHashMap()

            domainList.forEach { domain ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {
                        mutex.withLock {
                            startCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dmarc scan: started for $domain ($startCounter from ${domainList.size})")
                        }

                        val dmarcCommand = DMARCCommand(domain, dmarcDnsCache)
                        val dmarcPolicyResult = dmarcCommand.testDMARC(rateLimiterDss)

                        mutex.withLock {
                            dmarcResults.add(
                                dmarcPolicyResult
                            )

                            dmarcPolicyResult.reportDomains?.forEach { domain -> if(!domain.sameOrgDomain) {externalReportingDomains.add(domain.reportDomain) }}

                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dmarc scan: fully finished for $domain ($finishCounter from ${domainList.size})")
                        }


                    }
                }
            }
        }
        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:finished dmarc scan")


        return DMARCMeasurementResult(dmarcResults, externalReportingDomains)
    }

    // Testfunktion für  DMARC
    fun spfTest( domainList: List<String>):List<SPFResult> {

        logger.info("starting to check SPF")
        logger.info("using $threadCount threads")
        logger.info("using a rate limit of ${rateLimiterSPF.rate.toInt()} queries per second")
        val starttime = System.currentTimeMillis()

        // "entlade" den RateLimiter
        rateLimiterSPF.acquire()
        val spfResults = mutableListOf<SPFResult>()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0

            // Dient als Cache für bereits getätigte DMARC-DNS-Abfragen

            domainList.forEach { domain ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {
                        mutex.withLock {
                            startCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:spf scan: started for $domain ($startCounter from ${domainList.size})")
                        }
                        rateLimiterSPF.acquire()
                        val spfResult = SPFCommand(domain).testSPF()

                        mutex.withLock {
                            if(spfResult != null ) {
                                spfResults.add(
                                    spfResult
                                )

                            }


                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:spf scan: fully finished for $domain ($finishCounter from ${domainList.size})")
                        }


                    }
                }
            }
        }
        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:finished spf scan")


        return spfResults
    }


    // Testfunktion für  DMARC
    fun dkimTest( domainList: List<String>):List<DKIMResult> {

        val dkimResults = mutableListOf<DKIMResult>()

        logger.info("starting to check DKIM")
        logger.info("using $threadCount threads")
        logger.info("using a rate limit of ${rateLimiterDss.rate.toInt()} queries per second")
        val starttime = System.currentTimeMillis()

        // "entlade" den RateLimiter
        rateLimiterDss.acquire()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0

            // Dient als Cache für bereits getätigte DMARC-DNS-Abfragen

            domainList.forEach { domain ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {
                        mutex.withLock {
                            startCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dkim scan: started for $domain ($startCounter from ${domainList.size})")
                        }

                        val dkimResult = DKIMCommand(domain).testDKIM(rateLimiterDss)

                        mutex.withLock {

                                dkimResults.add(
                                    dkimResult
                                )

                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dkim scan: fully finished for $domain ($finishCounter from ${domainList.size})")
                        }


                    }
                }
            }
        }
        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:finished dkim scan")


        return dkimResults
    }





    fun dnssecTestDomain( domainWithMXRecords: List<DomainMX>):List<DNSSECResult> {

        // Für DNSSEC-Test
        // Nur jeweils ein Eintrag je Domain mit AD-Flag-Prüfung für MX-Abfrage
        val domainsWithMXRecords = domainWithMXRecords.distinctBy{it.domain}

        rateLimiterDnssec.acquire(2)
        val dnssecDomain = mutableListOf<DNSSECResult>()

        logger.info("starting to check DNSSEC for Domain")

        val starttime = System.currentTimeMillis()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0

            // Dient als Cache für bereits getätigte DMARC-DNS-Abfragen

            domainsWithMXRecords.forEach { domainMX ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {
                        mutex.withLock {
                            startCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dnssec domain scan: started for ${domainMX.domain} ($startCounter from ${domainWithMXRecords.size})")
                        }


                        var dnssecResult = DNSSECCommand(domainMX.domain, domainMX.adFlagForDNSSECCheck!!).testDNSSEC(rateLimiterDnssec,"MX", "unbound")


                        mutex.withLock {

                            dnssecDomain.add(
                                dnssecResult
                            )

                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dnssec domain scan: fully finished for ${domainMX.domain} ($finishCounter from ${domainWithMXRecords.size})")
                        }

                    }
                }
            }
        }

        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:finished dnssec domain scan")


        return dnssecDomain


    }


    fun dnssecTestMXHosts(scanData: List<ScanData>):List<DNSSECResult> {


        // Für DNSSEC, Nur Einträge für jeweils einen MxRecord aber mit AD-Flag-Prüfung für A-Abfrage
        val  scanDataFiltered = scanData.filter{it.mxRecord != null && it.adFlagForMx != null}.distinctBy { it.mxRecord }


        rateLimiterDnssec.acquire(2)
        val dnssecDomain = mutableListOf<DNSSECResult>()

        logger.info("starting to check DNSSEC for MX")

        val starttime = System.currentTimeMillis()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0

            // Dient als Cache für bereits getätigte DMARC-DNS-Abfragen

            scanDataFiltered.forEach { scanData ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {
                        mutex.withLock {
                            startCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dnssec mx scan: started for ${scanData.mxRecord!!} ($startCounter from ${scanDataFiltered.size})")
                        }


                        var dnssecResult = DNSSECCommand(scanData.mxRecord!!, scanData.adFlagForA!!).testDNSSEC(rateLimiterDnssec,"A", "unbound")


                        mutex.withLock {

                            dnssecDomain.add(
                                dnssecResult
                            )

                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dnssec mx scan: fully finished for ${scanData.mxRecord!!} ($finishCounter from ${scanDataFiltered.size})")
                        }

                    }
                }
            }
        }

        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:finished mx scan")


        return dnssecDomain


    }



    fun dssTest( domainList: List<String>):List<DssResult> {

        val dssResults = mutableListOf<DssResult>()

        logger.info("starting to check SPF and DMARC (dss)")
        logger.info("using $threadCount threads")
        logger.info("using a rate limit of ${rateLimiterDss.rate.toInt()} queries per second")
        val starttime = System.currentTimeMillis()

        // "entlade" den RateLimiter
        rateLimiterDss.acquire()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0


            domainList.forEach { domain ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {
                        mutex.withLock {
                            startCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dss scan: started for $domain ($startCounter from ${domainList.size})")
                        }


                        val dssResult = testDss(domain, rateLimiterDss, Config["TLS_RETRIES"], starttime)

                        mutex.withLock {
                            dssResults.add(
                                DssResult(
                                    domain,
                                    dssResult.exitCode,
                                    dssResult.consoleLog
                                )
                            )


                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dss scan: fully finished for $domain ($finishCounter from ${domainList.size})")
                        }


                    }
                }
            }
        }
        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:finished dss scan")


        return dssResults
    }

    // Testfunktion für DANE
    fun daneMxTest( mxList: List<String>):List<DaneCheckResult> {

        val daneMxResults = mutableListOf<DaneCheckResult>()

        logger.info("starting to test dane for mx")
        logger.info("using $threadCount threads")
        logger.info("using a rate limit of ${rateLimiterTls.rate.toInt()} queries per second")
        val starttime = System.currentTimeMillis()

        // entlade den RateLimiter
        rateLimiterTls.acquire()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0


            mxList.forEach { mxRecord ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {
                        mutex.withLock {
                            startCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dane scan: started for $mxRecord ($startCounter from ${mxList.size})")
                        }


                        val daneCommandResult = testDane(mxRecord, rateLimiterTls)

                        mutex.withLock {
                            daneMxResults.add(
                                DaneCheckResult(
                                    mxRecord,
                                    daneCommandResult.exitCode,
                                    daneCommandResult.console_output
                                )
                            )


                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dane scan: fully finished for $mxRecord ($finishCounter from ${mxList.size})")
                        }


                    }
                }
            }
        }
        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:finished dane scan")


        return daneMxResults
    }

    fun testTLS_1_2Config( mxList: List<String>):List<TLS_1_2_AllResult> {

        val tls_1_2Results = mutableListOf<TLS_1_2_AllResult>()

        rateLimiterTls.acquire()

        logger.info("starting to test dane for mx")
        logger.info("using $threadCount threads")
        logger.info("using a rate limit of ${rateLimiterTls.rate.toInt()} queries per second")
        val starttime = System.currentTimeMillis()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0


            mxList.forEach { mxRecord ->
                launch(Dispatchers.IO) {
                    semaphore.withPermit {


                        mutex.withLock {
                            startCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:tls 1_2 scan scan: started for $mxRecord ($startCounter from ${mxList.size})")
                        }

                        val tls_1_2_test = TLS_1_2_Command()
                        val result = tls_1_2_test.testTlsBSI(mxRecord, rateLimiterTls)

                        mutex.withLock {
                            tls_1_2Results.add(result)
                            finishCounter += 1
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:tls 1_2 scan: fully finished for $mxRecord ($finishCounter from ${mxList.size})")
                        }


                    }
                }

            }
        }
        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:finished tls 1_2 scan")


        return tls_1_2Results
    }



    // Übernommene Hilfsfunktionen:
    // Geändert: Prüfe pro Mailserver auf TLS-Versionen 1.0 bis 1.2 ohne Validierung des Zertifikats
    suspend fun testTls(mxrecord: String, rateLimiter: RateLimiter, starttime : Long): TlsCommandResult {



            delay(1.seconds)

            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:  $mxrecord  tls version 1.0 scan started")

            val smtpCheckTls1 = TlsSmtpCertCheck(mxrecord )
            rateLimiter.acquire()
            val testTlsv1 = smtpCheckTls1.testSmtpTlsHandshake(tlsRequirements("TLSv1"), ignoreCertValidity = true)
            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:  $mxrecord  tls version 1.0 scan finished")

            if(testTlsv1!!.errorType != null && testTlsv1.errorType!!.startsWith(TlsCertError.SmtpErrorNoSTARTTLSOffered.stringText)){
                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: $mxrecord has offered no starttls!")
                return TlsCommandResult(1,testTlsv1.errorType!!)
            }

            delay(10.seconds)

            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:  $mxrecord  tls version 1.1 scan started")
            val smtpCheckTls1_1 = TlsSmtpCertCheck(mxrecord )
            rateLimiter.acquire()
            val testTlsv1_1 = smtpCheckTls1_1.testSmtpTlsHandshake(tlsRequirements("TLSv1.1"), ignoreCertValidity = true)
            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:  $mxrecord  tls version 1.1 scan finished")

            delay(10.seconds)

            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:  $mxrecord  tls version 1.2 scan started")
            val smtpCheckTls1_2 = TlsSmtpCertCheck(mxrecord )
            rateLimiter.acquire()
            val testTlsv1_2 = smtpCheckTls1_2.testSmtpTlsHandshake(tlsRequirements("TLSv1.2"), ignoreCertValidity = true)
            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:  $mxrecord  tls version 1.2 scan finished")



            val hasTlsv1_2 = testTlsv1_2!!.errorType == null
            val hasTlsv1_1 = testTlsv1_1!!.errorType == null
            val hasTlsv1 = testTlsv1.errorType == null

            if(!hasTlsv1_2 && !hasTlsv1_1 && !hasTlsv1 )
            {
                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:  $mxrecord  tls version scan finished with general error")
                return TlsCommandResult(1,testTlsv1_2.errorType!!)
            }

            val hasTlsv1_2_string = if(hasTlsv1_2){"yes"}else{"no"}
            val hasTlsv1_1_string = if (hasTlsv1_1) {"yes"} else {"no"}
            val hasTlsv1_string = if (hasTlsv1) {"yes"} else {"no"}



            return TlsCommandResult(0,"PROTOS_OFFERED: tls1:$hasTlsv1_string tls1_1:$hasTlsv1_1_string tls1_2:$hasTlsv1_2_string")


            /*

            if(testTlsv1_1!!.errorType != null && testTlsv1_1.errorType!!.startsWith(TlsCertError.SmtpErrorNoSTARTTLSOffered.stringText) ){
                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:  $mxrecord has offered no starttls!")
                return TlsCommandResult(1,testTlsv1_1.errorType!!)
            }

            if(testTlsv1_2!!.errorType != null && testTlsv1_2.errorType!!.startsWith(TlsCertError.SmtpErrorNoSTARTTLSOffered.stringText)) {
                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:  $mxrecord has offered no starttls!")
                return TlsCommandResult(1,testTlsv1_2.errorType!!)
            }
             */

    }

    suspend fun testDss(domain: String, rateLimiter: RateLimiter, retries: Int, starttime: Long): DssCommandResult {
        var last: DssCommandResult? = null
        return try {
            (0 until retries).asFlow().map { attempt ->
                if (attempt > 0) {
                    delay(1.seconds) // 1 Sekunde warten vor neuem Versuch auf dieselbe Domain
                }
                rateLimiter.acquire()
                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dss scan $attempt try started for $domain ")
                last = DSSCommand(domain).run(Config["TLS_TIMEOUT"])
                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]:dss scan $attempt try finished for $domain ")
                last!!
            }.first { it.exitCode == 0 }
        } catch (ex: NoSuchElementException) {
            val logger = LoggerFactory.getLogger(Application::class.java)
            logger.warn("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: dss scan did not finish after $retries retries for $domain")

            return last!!
        }
    }


    fun testDane(mx: String, rateLimiter: RateLimiter): DaneCommandResult {
        rateLimiter.acquire()
        return DaneCommand(mx).run(Config["DANE_TIMEOUT"])
    }

}







