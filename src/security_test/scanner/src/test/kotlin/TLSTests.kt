
import commands.TlsHttpCertCheck
import commands.TlsSmtpCertCheck
import commands.TrustManagerCertData
import commands.TrustManagerDecorator
import dataClass.TLS.tlsRequirements
import enums.PubKeyAlgorithm
import models.enums.TlsCertError
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider
import org.junit.Assert.*
import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import java.lang.Thread.sleep
import java.security.KeyStore
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.collections.set

@RunWith(Parameterized::class)
class TLSTests(private val domain: String) {

    companion object {
        // 3. Diese Methode liefert die Testdaten
        @JvmStatic
        @Parameterized.Parameters(name = "{index}: Teste Server {0}")
        fun data(): Collection<Array<String>> {
            return listOf(
                //arrayOf("prefilter.emailsecurity.trendmicro.eu"),
                //arrayOf("mail.bolsover.gov.uk"),
                //arrayOf("mailgate.derbyshiredales.gov.uk"),

                //arrayOf("uk.mx1.mailanyone.net"), // G
                //arrayOf("uk.mx3.mailanyone.net"), // G

                //arrayOf("mailgate.ne-derbyshire.gov.uk"),

               // arrayOf("uk.mx2.mx25.net"), // G

               // arrayOf("pop3.positive-internet.com"), // G UG


                //arrayOf("mail.charnwood.gov.uk"),
                //arrayOf("mail3.redditchbc.gov.uk"),
                //arrayOf("smtp-ma.kcn.org.uk"),

                //arrayOf("mx3.westlothian.gov.uk") ,// G
                arrayOf("cityoflondon-gov-uk.mail.protection.outlook.com")
                // Hier kannst du beliebig viele weitere Domains als arrayOf("...") hinzufügen
            )
        }
    }

    // 4. Dein eigentlicher Testfall
    @Test
    fun checkTLSSmtpTestResoladed() {
        sleep(1)
        val smtpCheck = TlsSmtpCertCheck(domain)
        val ret = smtpCheck.testSmtpTlsHandshake()

        println("Ergebnis für $domain: ${ret?.errorType}")

        // Achtung: In JUnit 4 steht die Custom-Fehlermeldung ganz VORNE!
        assertEquals("Fehler bei der Domain $domain: ${ret?.errorType}", null, ret?.errorType)
    }



    @Test
    fun checkHttpTLSVersion() {
        val httpCheck = TlsHttpCertCheck("badssl.com", "104.154.89.105")
        val ret = httpCheck.testHttpsTlsHandshake()
        assertEquals("TLSv1.2", ret?.tlsVersion)
    }


    @Test
    fun checkHttpExpiredCertificate() {
        val httpCheck = TlsHttpCertCheck("expired.badssl.com","104.154.89.105")
        val ret = httpCheck.testHttpsTlsHandshake()
        assertEquals(TlsCertError.ExpiredCertificate.stringText,ret?.errorType)
    }

    @Test
    fun checkTLSSmtpTest() {
        val smtpCheck = TlsSmtpCertCheck("gmail-smtp-in.l.google.com")
        val ret = smtpCheck.testSmtpTlsHandshake()
        println(ret?.errorType)
        assertEquals(null, ret?.errorType)
    }




    @Test
    fun testuntrustedRoot() {
        val httpsCheck = TlsHttpCertCheck("untrusted-root.badssl.com")
        val ret = httpsCheck.testHttpsTlsHandshake()
        assertEquals(TlsCertError.RootCAUntrusted.stringText, ret?.errorType)
        println(TlsCertError.RootCAUntrusted.stringText)
    }

    @Test
    fun noConnectionRoot() {
        val httpsCheck = TlsHttpCertCheck("localhost")
        val ret = httpsCheck.testHttpsTlsHandshake()
        assertEquals(TlsCertError.SocketVerbindungsfehler.stringText.startsWith(TlsCertError.SocketVerbindungsfehler.stringText), ret?.errorType?.startsWith(TlsCertError.SocketVerbindungsfehler.stringText))
    }

    @Test
    fun selfSigned() {
        val httpsCheck = TlsHttpCertCheck("self-signed.badssl.com")
        val ret = httpsCheck.testHttpsTlsHandshake()
        assertEquals(TlsCertError.RootCAUntrusted.stringText, ret?.errorType)
    }

    @Test
    fun incompleteChain() {
        val httpsCheck = TlsHttpCertCheck("incomplete-chain.badssl.com")
        val ret = httpsCheck.testHttpsTlsHandshake()
        assertEquals(TlsCertError.RootCAUntrusted.stringText, ret?.errorType)
    }

    @Test
    fun mismatchHost() {
        val httpsCheck = TlsHttpCertCheck("wrong.host.badssl.com")
        val ret = httpsCheck.testHttpsTlsHandshake()
        assertEquals(TlsCertError.SANMismatch.stringText, ret?.errorType)
    }


    @Test
    fun testTLS() {
        //tmf.init(null as KeyStore?) // Standard KeyStore


        val tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm() // Standardalgorithmus: idR PKIX
        )
        //tmf.init(null as KeyStore?) // Standard KeyStore
        // Mehrdeutigkeit, da mehrere init-Methoden mit einem Parameter vorhanden sind
        val defaultKeyStore: KeyStore? = null
        tmf.init(defaultKeyStore)
        // Festlegung auf Typ KeyStore?
        // Mehrdeutigkeit, da mehrere init-Methoden mit einem Parameter vorhanden sind

        // Erstelle SSLContext mit eigener TrustManager-Implementierung ( notwendig für SSLSocket)


        // Bouncy Castle Provider direkt instanziieren (isoliert)
        val bcCryptoProvider = BouncyCastleProvider()
        val bcJsseProvider = BouncyCastleJsseProvider(bcCryptoProvider)
        val context: SSLContext = SSLContext.getInstance("TLS", bcJsseProvider)

        val defaultTm = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
        //Liste, beim Testen idR aber nur ein Algorithmus

        // TrustManager-Decorator (Äußerer Wrappper: Sammelt Zertifikatsdaten, innen Standard-Trustmanager)
       // val  tmd: TrustManagerDecorator = TrustManagerCertData(defaultTm, tlsdataCollector, hostname)

        context.init(
            null,
            null,
            null
        )

    }


    @Test
    fun tls11Test() {
        // "Compatibility Profile for TLS 1.2" mit CBC Verschlüsselung
        java.security.Security.setProperty(
            "jdk.tls.disabledAlgorithms",
            ""
        )
        val tlsVersion = "TLSv1"
        val tlsReq = tlsRequirements(tlsVersion)

        val httpsCheck = TlsHttpCertCheck("tls-v1-0.badssl.com", port= 1010)
        val ret = httpsCheck.testHttpsTlsHandshake(tlsReq)
        assertEquals(TlsCertError.SANMismatch.stringText, ret?.errorType)
    }

    @Test
    fun tls11Test_SMTP() {
        // "Compatibility Profile for TLS 1.2" mit CBC Verschlüsselung
        java.security.Security.setProperty(
            "jdk.tls.disabledAlgorithms",
            ""
        )
        Thread.sleep(2000)
        val preferIpv4 = System.getProperty("java.net.preferIPv4Stack")
        println(">>> JVM preferIPv4Stack aktiv: $preferIpv4")


        //val mxRec = Measurement.tlsVersionRangeTest(listOf("microsoft-com.mail.protection.outlook.com"))

        //assertEquals(TlsCertError.SANMismatch.stringText, mxRec.first().consoleLog)

        val mxRecRzone = Measurement.tlsVersionRangeTest(listOf("smtpin.rzone.de"))

        assertEquals("PROTOS_OFFERED: tls1:no tls1_1:no tls1_2:yes", mxRecRzone.first().consoleLog)

    }


}