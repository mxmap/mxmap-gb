import Measurement.logger
import Measurement.mutex
import Measurement.semaphore
import Measurement.threadCount
import com.google.common.util.concurrent.RateLimiter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import dataClass.SCAN.ScanDataNotNullable
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

class RoundRobinIPTest {

    val simulatedScanData = listOf(
        // --- Cluster 1: Große Hoster mit vielen IPs hinter einem MX (z. B. Google Workspace) ---
        // gmail.com
        ScanDataNotNullable("gmail.com", "gmail-smtp-in.l.google.com", "142.251.16.27"),
        ScanDataNotNullable("gmail.com", "gmail-smtp-in.l.google.com", "142.251.16.26"),
        ScanDataNotNullable("gmail.com", "gmail-smtp-in.l.google.com", "142.250.113.27"),
        ScanDataNotNullable("gmail.com", "gmail-smtp-in.l.google.com", "142.250.114.27"),
        // github.com (nutzt Google MX)
        ScanDataNotNullable("github.com", "aspmx.l.google.com", "142.251.16.27"),
        ScanDataNotNullable("github.com", "aspmx.l.google.com", "142.251.16.27"),
        ScanDataNotNullable("github.com", "aspmx.l.google.com", "142.251.16.26"),

        // --- Cluster 2: Microsoft 365 / Outlook mit mehreren IPs ---
        // outlook.com
        ScanDataNotNullable("outlook.com", "outlook-com.olc.protection.outlook.com", "142.251.16.27"),
        ScanDataNotNullable("outlook.com", "outlook-com.olc.protection.outlook.com", "17.42.251.11"),
        ScanDataNotNullable("outlook.com", "outlook-com.olc.protection.outlook.com", "104.47.57.33"),
        ScanDataNotNullable("outlook.com", "outlook-com.olc.protection.outlook.com", "104.47.57.34"),
        // firmen-domain.de (nutzt Microsoft 365)
        ScanDataNotNullable("firmen-domain.de", "firmendomain-de.mail.protection.outlook.com", "142.251.16.27"),
        ScanDataNotNullable("firmen-domain.de", "firmendomain-de.mail.protection.outlook.com", "17.42.251.11"),
        ScanDataNotNullable("firmen-domain.de", "firmendomain-de.mail.protection.outlook.com", "104.47.60.38"),

        // --- Cluster 3: Yahoo & iCloud (3-4 IPs) ---
        // yahoo.com
        ScanDataNotNullable("yahoo.com", "mta5.am0.yahoodns.net", "142.251.16.27"),
        ScanDataNotNullable("yahoo.com", "mta5.am0.yahoodns.net", "17.42.251.11"),
        ScanDataNotNullable("yahoo.com", "mta5.am0.yahoodns.net", "98.136.216.25"),
        ScanDataNotNullable("yahoo.com", "mta5.am0.yahoodns.net", "98.136.216.26"),
        // icloud.com
        ScanDataNotNullable("icloud.com", "mx01.mail.icloud.com", "142.251.16.27"),
        ScanDataNotNullable("icloud.com", "mx01.mail.icloud.com", "17.42.251.11"),
        ScanDataNotNullable("icloud.com", "mx01.mail.icloud.com", "17.42.251.12"),

        // --- Cluster 4: Mittelgroße Provider mit 2-3 IPs (Loadbalancer) ---
        // gmx.de
        ScanDataNotNullable("gmx.de", "mx00.eml.gmx.net", "142.251.16.27"),
        ScanDataNotNullable("gmx.de", "mx00.eml.gmx.net", "17.42.251.11"),
        ScanDataNotNullable("gmx.de", "mx01.eml.gmx.net", "212.227.17.4"),
        ScanDataNotNullable("gmx.de", "mx01.eml.gmx.net", "212.227.17.5"),
        // web.de
        ScanDataNotNullable("web.de", "mx-ha02.web.de", "142.251.16.27"),
        ScanDataNotNullable("web.de", "mx-ha02.web.de", "17.42.251.11"),
        // t-online.de
        ScanDataNotNullable("t-online.de", "mx03.t-online.de", "142.251.16.27"),
        ScanDataNotNullable("t-online.de", "mx03.t-online.de", "194.25.134.73"),
        // amazon.de
        ScanDataNotNullable("amazon.de", "amazon-smtp.amazon.com", "142.251.16.27"),
        ScanDataNotNullable("amazon.de", "amazon-smtp.amazon.com", "52.94.124.51"),
        ScanDataNotNullable("amazon.de", "amazon-smtp.amazon.com", "52.94.124.52"),

        // --- Cluster 5: Kleinere Provider mit exakt 2 IPs (Oft IPv4 Failover) ---
        // mailbox.org
        ScanDataNotNullable("mailbox.org", "mx1.mailbox.org", "80.241.60.212"),
        ScanDataNotNullable("mailbox.org", "mx1.mailbox.org", "80.241.60.213"),
        // bund.de
        ScanDataNotNullable("bund.de", "mx1.bund.de", "141.66.11.192"),
        ScanDataNotNullable("bund.de", "mx1.bund.de", "141.66.11.193"),
        // example.com
        ScanDataNotNullable("example.com", "mx1.example.com", "93.184.216.34"),
        ScanDataNotNullable("example.com", "mx1.example.com", "93.184.216.35"),

        // --- Cluster 6: Dedizierte Mailserver mit exakt 1 IP ---
        ScanDataNotNullable("posteo.de", "mx01.posteo.de", "89.146.220.134"),
        ScanDataNotNullable("company.com", "mx.company.com", "198.51.100.50"),
        ScanDataNotNullable("klein-unternehmen.de", "mail.klein-unternehmen.de", "203.0.113.15"),
        ScanDataNotNullable("blog.net", "mx1.blog.net", "104.21.4.15"),
        ScanDataNotNullable("verein.org", "mail.verein.org", "81.169.145.100"),
        ScanDataNotNullable("startup.io", "mx.startup.io", "172.217.16.19"),
        ScanDataNotNullable("shop-lokal.de", "mail.shop-lokal.de", "85.214.23.111"),
        ScanDataNotNullable("kanzlei.de", "mail.kanzlei.de", "192.168.1.100"), // Simuliert
        ScanDataNotNullable("arztpraxis.net", "mx.arztpraxis.net", "10.0.0.45"), // Simuliert

        // --- Cluster 7: Weitere Einzel-IPs (Fallback MX Records mit niedrigerer Prio) ---
        // Meistens hat ein zweiter MX-Eintrag (Prio 20) ebenfalls nur eine IP
        ScanDataNotNullable("company.com", "mx2.company.com", "198.51.100.51"),
        ScanDataNotNullable("example.com", "mx2.example.com", "93.184.216.36"),
        ScanDataNotNullable("posteo.de", "mx02.posteo.de", "89.146.220.135")
    )



    @Test
    public fun roundRobinSimulatedTest() {

            val grouped = simulatedScanData.groupBy { it.mxRecord }
            val maxIpsForAnyMx = grouped.values.maxOfOrNull { it.size } ?: 0

            val interleavedScanList = mutableListOf<Pair<Int,ScanDataNotNullable>>()

            // Für Jede IP-Adressen-Prio
            for (i in 0 until maxIpsForAnyMx) {

                // Jeden Mailserver abfragen
                for (mxList in grouped.values) {

                    // Ob dieser für die Prio eine IP-Adresse besitzt
                    if (i < mxList.size) {
                        interleavedScanList.add(Pair(i,mxList[i]))
                    }
                }
            }

            val rateLimiter = RateLimiter.create(2.0)

            logger.info("starting to measure tls and cert data from domains")
            logger.info("using $threadCount threads for resolving MX records")
            logger.info("using a rate limit of ${rateLimiter.rate.toInt()} queries per second")

            val starttime = System.currentTimeMillis()


            runBlocking {
                var finishCounter = 0
                var startCounter = 0

                logger.info("starting tls cert scan")

                interleavedScanList.forEach { (ipIndex,mxAndIP) ->
                    launch(Dispatchers.IO) {

                        val delayIndex = ipIndex * 3
                        delay(delayIndex.seconds)

                        semaphore.withPermit {


                            // Teste mit einem Retry
                            rateLimiter.acquire()
                            mutex.withLock {
                                startCounter += 1

                            }
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s] started for ${mxAndIP.ipAddress} ${mxAndIP.mxRecord}($startCounter from ${simulatedScanData.size})")
                            test()
                            mutex.withLock {
                                finishCounter += 1
                                //logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s] finished for ${mxAndIP.ipAddress} ${mxAndIP.mxRecord} ($finishCounter from ${simulatedScanData.size})")
                            }


                        }
                    }
                }
            }
            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: finished tls cert scan")




    }



    @Test
    fun roundRobinSimulatedTest2() {
        val grouped = simulatedScanData.groupBy { it.mxRecord }
        val maxIpsForAnyMx = grouped.values.maxOfOrNull { it.size } ?: 0

        val interleavedScanList = mutableListOf<ScanDataNotNullable>()

        // Das Round-Robin-Interleaving behalten wir, weil es dafür sorgt,
        // dass wir nicht am Anfang unnötig warten müssen, sondern direkt
        // andere Hosts abarbeiten können. (Den ipIndex brauchen wir aber nicht mehr).
        for (i in 0 until maxIpsForAnyMx) {
            for (mxList in grouped.values) {
                if (i < mxList.size) {
                    interleavedScanList.add(mxList[i])
                }
            }
        }

        val rateLimiter = RateLimiter.create(0.25)

        // NEU: Ein Mutex und ein Zeitstempel für jeden MX-Host
        val mxMutexes = java.util.concurrent.ConcurrentHashMap<String, kotlinx.coroutines.sync.Mutex>()
        val lastScannedMx = java.util.concurrent.ConcurrentHashMap<String, Long>()
        val MIN_DELAY_MS = 5000 // 5 Sekunden mindestabstand

        logger.info("starting to measure tls and cert data from domains")
        logger.info("using $threadCount threads for resolving MX records")
        logger.info("using a rate limit of ${rateLimiter.rate.toInt()} queries per second")

        val starttime = System.currentTimeMillis()

        runBlocking {
            var finishCounter = 0
            var startCounter = 0

            logger.info("starting tls cert scan")

            interleavedScanList.forEach { mxAndIP ->
                launch(Dispatchers.IO) {


                    // Füge Wert hinzu bzw. entferne diesen (Mutex anlegen und entfernen)
                    val mxMutex = mxMutexes.getOrPut(mxAndIP.mxRecord) { kotlinx.coroutines.sync.Mutex() }

                    // 1. MX-Level: IPs desselben Hosts laufen hier strikt nacheinander durch
                    mxMutex.withLock {

                        // Wichtig: berechne den Zeitabstand seitdem die letzte Ausführung FERTIG geworden ist!!
                        val lastTime = lastScannedMx[mxAndIP.mxRecord] ?: 0L
                        val now = System.currentTimeMillis()
                        val timeSinceLast = now - lastTime

                        // Wenn der Host schon mal dran war und die Zeit noch nicht abgelaufen ist: Warten!
                        if (lastTime != 0L && timeSinceLast < MIN_DELAY_MS) {
                            val waitTime = MIN_DELAY_MS - timeSinceLast
                            // delay() blockiert keinen Thread! Es pausiert nur diese Coroutine.
                            delay(waitTime)
                        }

                        // 2. Global-Level: Jetzt reihen wir uns in die globale RateLimiter-Warteschlange ein
                        semaphore.withPermit {
                            rateLimiter.acquire()

                            mutex.withLock { startCounter += 1 }
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s] started for ${mxAndIP.ipAddress} ${mxAndIP.mxRecord} ($startCounter from ${simulatedScanData.size})")
                            test()
                            logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s] finished for ${mxAndIP.ipAddress} ${mxAndIP.mxRecord} ($startCounter from ${simulatedScanData.size})")
                            // 3. WICHTIG: Zeitstempel aktualisieren, BEVOR wir das mxMutex freigeben.
                            // So weiß die nächste IP dieses Hosts exakt, ab wann die 10 Sekunden gelten.
                            lastScannedMx[mxAndIP.mxRecord] = System.currentTimeMillis()

                            mutex.withLock { finishCounter += 1 }
                        }
                    }
                }
            }
        }
        logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: finished tls cert scan")
    }

    @Test
    fun rrTest3() {

        // Key Mailserver -> Value: (Menge an zugehörigen IPs)
        val grouped = simulatedScanData.groupBy { it.mxRecord }
        val maxIpsForAnyMx = grouped.values.maxOfOrNull { it.size } ?: 0

        val interleavedScanList = mutableListOf<ScanDataNotNullable>()
        val starttime = System.currentTimeMillis()
        // Round-Robin  -> Verteile die MX-Hosts: nimm im ersten durchlauf jeweils die erste IP von jedem Mailserver
        // Im zweiten Durchlauf die zweite IP von jedem Mailserver usw.
        for (i in 0 until maxIpsForAnyMx) {
            for (mxList in grouped.values) {
                if (i < mxList.size) {
                    interleavedScanList.add(mxList[i])
                }
            }
        }

        // Nutze Collections

        // Globale Maps für MX bzw. IP-Spezfifischer-Mutex
        val mxMutexes = ConcurrentHashMap<String, Mutex>()
        val ipMutexes = ConcurrentHashMap<String, Mutex>()


        // Messe für jeden MX bzw. IP das Ende der letzten Nutzung
        val lastScannedMx = ConcurrentHashMap<String, Long>()
        val lastScannedIp = ConcurrentHashMap<String, Long>()


        // Mindestabstand (in Sekunden) zwischen zwei Anfragen an den gleichen Mailhost bzw. IP
        val minDelayMX = 4
        val minDelayIP = 4

        val rateLimiter = RateLimiter.create(0.25) // Nur alle 4 Sekunden wird eine Anfrage gestartet
        val semaphore = Semaphore(4) //lasse maximal 4 Threads zu
        runBlocking {
            interleavedScanList.forEach { mxAndIP ->
                launch(Dispatchers.IO) {

                    // Anlegen bzw. erlangen des Mutexes je Mailserver bzw. IpAdresse
                    val mxMutex = mxMutexes.getOrPut(mxAndIP.mxRecord) { Mutex() }
                    val ipMutex = ipMutexes.getOrPut(mxAndIP.ipAddress) { Mutex() }

                    // erst MX dann IP sperren. Deadlocks möglichst vermeiden
                    mxMutex.withLock {
                        ipMutex.withLock {

                            val now = System.currentTimeMillis()
                            val lastMxTime = lastScannedMx[mxAndIP.mxRecord] ?: 0L
                            val lastIpTime = lastScannedIp[mxAndIP.ipAddress] ?: 0L

                            val timeSinceLastMx = now - lastMxTime
                            val timeSinceLastIp = now - lastIpTime

                            // Berechne die nötige Wartezeit für MX und IP
                            val delayMx = if (lastMxTime != 0L && timeSinceLastMx < minDelayMX){
                                minDelayMX - timeSinceLastMx
                            } else {
                                0L
                            }

                            val delayIp = if (lastIpTime != 0L && timeSinceLastIp  < minDelayIP) {
                                minDelayIP - timeSinceLastIp
                            } else {
                                0L
                            }

                            // Größtmögliche Wartezeit (je Nachdem, ob Mx oder Ip als letztes verwendet wurde) -> (1 Sekunde mindestens!)
                            val waitTime = maxOf(delayMx, delayIp,1L)

                            // Verzögere (prüfe nur zur sicherheit auf pos. Wert)
                            if (waitTime  > 0) {
                                delay(waitTime.seconds)
                            }

                            // Semaphor dennoch nötig: Der Codeabschnitt könnte von mehreren Coroutines gleichtzeitig ausgeführt werden
                            semaphore.withPermit {
                                rateLimiter.acquire()

                                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s] started for ${mxAndIP.ipAddress} ${mxAndIP.mxRecord}")


                                //testTls(mxAndIP.mxRecord, mxAndIP.ipAddress, rateLimiterTls , 2, starttime)

                                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s] ended for ${mxAndIP.ipAddress} ${mxAndIP.mxRecord}")
                                // Zeitstempel wann TLS Versions-Scan beendet wurde aktualisieren
                                val completionTime = System.currentTimeMillis()
                                lastScannedMx[mxAndIP.mxRecord] = completionTime
                                lastScannedIp[mxAndIP.ipAddress] = completionTime
                            }
                        }
                    }
                }
            }
        }


    }

    fun test() {
        val random = Random.nextLong(10000,20000)
        Thread.sleep(random)

    }


    /*
    suspend fun testTls(mxrecord: String, ipaddress: String, rateLimiter: RateLimiter, retries: Int, starttime : Long): TlsCommandResult {
        var last: TlsCommandResult? = null
        return try {
            (0 until retries).asFlow().map {attempt ->
                if (attempt > 0) {
                    delay(3.seconds) // 2 Sekunden warten vor neuem Versuch auf dieselbe IP und Mailserver
                }
                rateLimiter.acquire()
                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: $ipaddress $mxrecord try $attempt tls version range scan started")

                val random = Random.nextLong(10000,20000)
                Thread.sleep(random)
                logger.info("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: $ipaddress $mxrecord try $attempt version range scan finished")


            }.first { it.exitCode == 0 }
        } catch (ex: NoSuchElementException) {
            val logger = LoggerFactory.getLogger(Application::class.java)
            logger.warn("[${"%.2f".format((System.currentTimeMillis() - starttime) / 1000.0)}s]: $ipaddress $mxrecord tls version range scan did not finish after $retries retries ")

            return last!!
        }
    }
   */

}