package commands

import dataClass.TLS.tlsRequirements
import dataClass.TLS.TLSDataCollector
import models.enums.TlsCertError
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jsse.BCSSLParameters
import org.bouncycastle.jsse.BCSSLSocket
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.cert.CertificateExpiredException
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

abstract class TLS(protected val port: Int, protected val hostname: String, protected val ip: String? ) {

    // TLS-Handshake durchführen mit Standardkonfiguration (inklusive Zertifikatsprüfung und Sammlung der Zertifikatsdaten)
    protected fun testTLS(socket: Socket, tlsRequirements: tlsRequirements? = null,  ignoreCertValidity:Boolean = false): TLSDataCollector {

        val tlsCollector = TLSDataCollector(hostname, ip)

        try {




            //SSL-Socket erstellen -> Use Block für sicheres schließen
            createSSLSocket(tlsCollector, socket, tlsRequirements, ignoreCertValidity).use {
                sslSocket ->
                sslSocket.startHandshake()
                // Wenn erfolgreich, dann erfasse ausgehandelte TLS-Daten der Session
                tlsCollector.cipherSuite = sslSocket.session.cipherSuite
                tlsCollector.tlsVersion = sslSocket.session.protocol

                runCatching {

                    if(this is TlsSmtpCertCheck) {
                        sslSocket.soTimeout = 6000 // Kurzer Timeout (6sek)

                        val writer = OutputStreamWriter(sslSocket.outputStream, StandardCharsets.US_ASCII)
                        writer.write("QUIT\r\n")
                        writer.flush()


                        val reader = BufferedReader(InputStreamReader(sslSocket.inputStream, StandardCharsets.US_ASCII))
                        reader.readLine()
                    }

                }
            }

        }catch(e:Exception){

            val message = e.message ?: ""
            when {
                // Vereinfachung der Fehlermeldung
                findCause<CertificateExpiredException>(e) ->
                    tlsCollector.errorType = TlsCertError.ExpiredCertificate.stringText

                /*findCause<CertPathValidatorException>(e) ->
                    println("PKIX-Fehler")*/

                // Interne Hostname-Prüfung
                message.contains("No subject alternative") ->
                    tlsCollector.errorType = TlsCertError.SANMismatch.stringText

                // Kategorie für: Zertifikat fehlt in Kette, Selbssigniert, unvertrauenswürdige CA
                message.contains("unable to find valid certification path to requested target") ->
                    tlsCollector.errorType = TlsCertError.RootCAUntrusted.stringText

                message.contains("The server selected protocol version") ->
                    tlsCollector.errorType = TlsCertError.UnsupportedProtocolVersion.stringText


                // Weitere Fehlermeldungen wie Handshake-Failure bei z.B. alten Cipher Suites (z.b. rc4.badssl.com)
                else -> {
                    // Den Namen der Exception-Klasse abfragen
                    val errorType = e::class.simpleName ?: "UnbekannteException"

                    // Einen sinnvollen Fehlertext zusammenbauen
                    tlsCollector.errorType  = if (e.message.isNullOrBlank()) {
                        errorType // Wenn keine Message da ist, nur den Typ ausgeben
                    } else {
                        "$errorType: ${e.message}"
                    }
                }


            }

        }

        return tlsCollector
    }


    // Erstellungsprozess und Konfiguration eines SSL-Sockets
    private fun createSSLSocket(tlsdataCollector: TLSDataCollector, socket: Socket, tlsRequirements: tlsRequirements? = null, ignoreCertValidity:Boolean = false): SSLSocket {

        val targetAdress = ip ?: hostname

        //Erstelle Trustmanager mit vorgegebenen Standardeinstellungen
        val tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm() // Standardalgorithmus: idR PKIX
        )
        //tmf.init(null as KeyStore?) // Standard KeyStore

        // Festlegung auf Typ KeyStore?
        // Mehrdeutigkeit, da mehrere init-Methoden mit einem Parameter vorhanden sind
        val defaultKeyStore: KeyStore? = null
        tmf.init(defaultKeyStore)


        val defaultTm = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
        //Liste, beim Testen idR aber nur ein Algorithmus

        // TrustManager-Decorator (Äußerer Wrappper: Sammelt Zertifikatsdaten, innen Standard-Trustmanager)
        val  tmd: TrustManagerDecorator = TrustManagerCertData(defaultTm, tlsdataCollector, hostname, ignoreCertValidity)

        // Erstelle SSLContext mit eigener TrustManager-Implementierung ( notwendig für SSLSocket)
        val context: SSLContext = if (tlsRequirements != null) {

            // Bouncy Castle Provider direkt instanziieren (isoliert)
            val bcCryptoProvider = BouncyCastleProvider()
            val bcJsseProvider = BouncyCastleJsseProvider(bcCryptoProvider)
            SSLContext.getInstance("TLS", bcJsseProvider)

        } else {
            // Standard-Fall: Nutze das normale Java-Verhalten (SunJSSE)
            SSLContext.getInstance("TLS")
        }

        context.init(
            null,
            arrayOf(tmd),
            null
        )



        val sslSocket = context.socketFactory.createSocket(socket,targetAdress,
            port, true) as SSLSocket

        val params = sslSocket.sslParameters
        // Aktiviere die Hostname-Prüfung (standardmäßig nicht aktiviert)

        if (!ignoreCertValidity) {
            params.endpointIdentificationAlgorithm = "HTTPS"
        } else {
            params.endpointIdentificationAlgorithm = null
        }

        //params.endpointIdentificationAlgorithm = "HTTPS"
        params.serverNames = listOf(SNIHostName(hostname))
        sslSocket.sslParameters = params


        if(tlsRequirements != null) {
            // 1. Bouncy Castle Socket Casten
            if (sslSocket is BCSSLSocket) {

                //  BC-spezifische Parameter holen
                val bcParams: BCSSLParameters = sslSocket.parameters

                // Protokolle und Cipher Suites setzen

                bcParams.protocols = arrayOf(tlsRequirements.version)

                if(tlsRequirements.cipherSuite != null) {
                    bcParams.cipherSuites = arrayOf(tlsRequirements.cipherSuite)
                }

                if(tlsRequirements.curvesData != null) {
                    bcParams.namedGroups = tlsRequirements.curvesData
                }
                // Kurven setzen (supported_groups extension) setzen

                // supported signatures extension setzen
                if(tlsRequirements.signatureAlgorithms != null) {
                    bcParams.signatureSchemes = tlsRequirements.signatureAlgorithms
                }

                sslSocket.parameters = bcParams

            } else {
                throw IllegalStateException("Der Socket ist kein BouncyCastle Socket!")
            }
        }else {
            // Mindestanforderung von MTA-STS
            params.protocols = arrayOf("TLSv1.3", "TLSv1.2")
            sslSocket.sslParameters = params
        }

        return sslSocket

    }

    // Prüfe auf spezifischen Fehlertyp in der Cause-Kette
    inline fun <reified T : Throwable> findCause(currentThrow: Throwable?): Boolean {

        var current: Throwable? = currentThrow

        while (current != null) {

            if (current is T)
                return true

            current = current.cause
        }

        return false
    }



}