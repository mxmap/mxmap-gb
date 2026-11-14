package commands

import kotlinx.datetime.Instant
import kotlinx.datetime.toKotlinInstant
import dataClass.TLS.TLSDataCollector
import dataClass.TLS.TLSServerCertificateInfo
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.interfaces.DHPublicKey
import javax.naming.ldap.LdapName
import javax.net.ssl.X509TrustManager
import kotlin.math.roundToLong
import kotlin.time.DurationUnit

public class TrustManagerCertData(delegate: X509TrustManager, tlsTestData: TLSDataCollector,
                                  private val hostname: String, val ignoreCertValidity : Boolean = false) : TrustManagerDecorator(delegate, tlsTestData) {

    // Wrapperfunktion: Sammle die Zertifikatsdaten aus dem Endnutzerzertifikat
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {

        //Endnutzer-X509Certificate, beim Testen war dies in der Regel das Endnutzerzertifikat
        val serverEndUserCert = chain.first()


        val issuerMetadata =
            LdapName(serverEndUserCert.issuerX500Principal.name)
                .rdns
                .associate { it.type to it.value.toString() }

        val subjectMetadata =
            LdapName(serverEndUserCert.subjectX500Principal.name)
                .rdns
                .associate { it.type to it.value.toString() }

        val sanDNSValues = getSanDnsValues(serverEndUserCert)

        val certInfo = TLSServerCertificateInfo(
            issuerMetadata["CN"],
            issuerMetadata["O"],
            issuerMetadata["C"],

            subjectMetadata["CN"],


            validFrom = serverEndUserCert.notBefore.toInstant().toKotlinInstant(),
            validUntil = serverEndUserCert.notAfter.toInstant().toKotlinInstant(),
            validPeriod = getDayDifference(serverEndUserCert.notBefore.toInstant().toKotlinInstant()
                , serverEndUserCert.notAfter.toInstant().toKotlinInstant()),

            signatureAlgorithm = serverEndUserCert.sigAlgName,
            publicKeyAlgorithm = serverEndUserCert.publicKey.algorithm,
            publicKeyLength = getPubKeyLength(serverEndUserCert.publicKey),

            sanList = sanDNSValues,
            sanDnsMatch = sanDnsCheck(sanDNSValues),
            sanStrictIdentifierMatch = sanStrictIdentifierCheck(sanDNSValues)
        )

        tlsTestData.tlsServerCertificateInfo = certInfo

        // Die eigentliche Zertifikatsprüfung

        if(!ignoreCertValidity) {
            super.checkServerTrusted(chain, authType)
        }


    }


    private fun getSanDnsValues(serverEndUserCert: X509Certificate): List<String> {
        val sans = serverEndUserCert.subjectAlternativeNames
        val sanDNSValues = mutableListOf<String>()
        sans?.forEach {
            if (it[0] == 2) sanDNSValues.add(it[1].toString())
        }
        return sanDNSValues
    }


    //RFC 7818/8461 verlangt einen SAN-DNS-Eintrag
    // Führe eine (vereinfachte) SAN-Prüfung durch
    private fun sanDnsCheck(sanDNSList: List<String>): Boolean {

        if(sanDNSList.isEmpty()) {
           return false
        }

        // Vereinfachte DNS-ID SAN Prüfung: Zur Sicherheit orientiert an RFC 9525, berücksichtigt keine Edge-Cases
        // ReferenceIdentifier sind bekannte Domains aus Domainlisten, berücksichtige deshalb keine Edge-Cases
        for(san in sanDNSList) {

            val lowerHostname = hostname.lowercase()
            val lowerSanDns = san.lowercase()

            if (lowerSanDns.equals(lowerHostname))
                return true

            // Prüfe Wildcard-Fall
            if (!lowerSanDns.startsWith("*."))
                continue
            val sanSuffix = lowerSanDns.removePrefix("*.")
            if(sanSuffix.contains("*"))
                continue

            val regTest = lowerHostname.replace(Regex("^[a-zA-Z0-9]([a-zA-Z0-9\\-]*[a-zA-Z0-9])?\\."),"")
            if(sanSuffix.equals(regTest))
                return true
        }
        return false
    }



    private fun sanStrictIdentifierCheck(sanDNSList: List<String>): Boolean {

        if(sanDNSList.isEmpty()) {
            return false
        }

        // Vereinfachte DNS-ID SAN Prüfung: Zur Sicherheit orientiert an RFC 9525, berücksichtigt keine Edge-Cases
        for(san in sanDNSList) {

            val lowerHostname = hostname.lowercase()
            val lowerSanDns = san.lowercase()

            if (lowerSanDns.equals(lowerHostname))
                return true

        }
        return false
    }



    // Hilfsfunktion: Ermittle Gültigkeitsdauer des Endnutzerzertifikats (gerundet in Tagen)
    fun getDayDifference(validFrom: Instant, validUntil: Instant): Long {
        // 1. Differenz als kotlin.time.Duration berechnen
        val duration = validUntil - validFrom

        // 2. In Tage
        return duration.toDouble(DurationUnit.DAYS).roundToLong()
    }


    // Ermittle die Schlüssellänge des Public Keys
    public fun getPubKeyLength(pubKey: PublicKey): Int? {
        return when (pubKey) {
            is RSAPublicKey -> pubKey.modulus.bitLength()
            is ECPublicKey -> pubKey.params.curve.field.fieldSize
            is DSAPublicKey -> pubKey.params.p.bitLength()
            is DHPublicKey -> pubKey.params.p.bitLength()

            else -> null
        }
    }


}