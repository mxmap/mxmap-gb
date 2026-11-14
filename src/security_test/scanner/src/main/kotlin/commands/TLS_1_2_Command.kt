package commands

import com.google.common.util.concurrent.RateLimiter
import dataClass.TLS.TLS_1_2_AllResult
import dataClass.TLS.TLS_1_2_Result
import dataClass.TLS.tlsRequirements
import enums.PubKeyAlgorithm
import enums.Tls_1_2_Error
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.seconds

class TLS_1_2_Command {

    suspend public fun testTlsBSI(domain: String, rateLimiter: RateLimiter): TLS_1_2_AllResult {

        val duration = 10.seconds
        val results = mutableMapOf<String, TLS_1_2_Result>()
        val groupNameP256 = "secp256r1"
        val tlsVersion = "TLSv1.2"

        // "Recommended Profiles for TLS 1.2"
        rateLimiter.acquire()

        val signatureExtensions = arrayOf(
            // RSA PKCS1 gemäß BSI-Richtlinie nicht mehr unterstützt (-> aber Intermediate Zertifikate!)
            "RSA_PKCS1_SHA256",
            "RSA_PKCS1_SHA384",
            "RSA_PKCS1_SHA512",

            "RSA_PSS_RSAE_SHA256",
            "RSA_PSS_RSAE_SHA384",
            "RSA_PSS_RSAE_SHA512",
            "RSA_PSS_PSS_SHA256",
            "RSA_PSS_PSS_SHA384",
            "RSA_PSS_PSS_SHA512",
            // ECDSA
            "ECDSA_SECP256R1_SHA256",
            "ECDSA_SECP384R1_SHA384",
            "ECDSA_SECP521R1_SHA512",
            // Neue ED
            "ED25519",
            "ED448"
        )

        // "ECDHE using P-256 Curve" -> secp256r1
        val cipherSuiteECDSA = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        val configTLSECDSA = tlsRequirements(tlsVersion, cipherSuiteECDSA,
            arrayOf(groupNameP256), signatureExtensions)
        val resultECDSA = checkTLSConfig(domain, configTLSECDSA, 256, PubKeyAlgorithm.ECDSA, ignoreCAValidity = true)
        results["Recommended_ECDSA_GCM_P-256"] = resultECDSA

        delay(duration)
        rateLimiter.acquire()

        // RSA
        val cipherSuiteRSA = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        val configTLSRSA = tlsRequirements(tlsVersion, cipherSuiteRSA,
            arrayOf(groupNameP256), signatureExtensions)
        val resultRSA = checkTLSConfig(domain,configTLSRSA,3000, PubKeyAlgorithm.RSA, ignoreCAValidity = true)
        results["Recommended_RSA_GCM_P-256"] = resultRSA

        delay(duration)
        rateLimiter.acquire()


        // Prüfe nun auf die Unterstützung der brainpool-Kurve

        val groupBrainpool = "brainpoolP256r1"

        val configBrainpoolECDSA = tlsRequirements(tlsVersion,cipherSuiteECDSA,
            arrayOf(groupBrainpool), signatureExtensions)

        val resultBrainpoolECDSA = checkTLSConfig(domain,configBrainpoolECDSA,256, PubKeyAlgorithm.ECDSA, ignoreCAValidity = true)
        results["Recommended_ECDSA_GCM_Brainpool"] = resultBrainpoolECDSA

        delay(duration)
        rateLimiter.acquire()

        val configBrainpoolRSA = tlsRequirements(tlsVersion,cipherSuiteRSA,
            arrayOf(groupBrainpool), signatureExtensions)

        val resultBrainpoolRSA = checkTLSConfig(domain,configBrainpoolRSA,3000, PubKeyAlgorithm.RSA, ignoreCAValidity = true)
        results["Recommended_RSA_GCM_Brainpool"] = resultBrainpoolRSA

        return TLS_1_2_AllResult(domain, results)

    }


    suspend public fun testTlsNCSC(domain: String, rateLimiter: RateLimiter): TLS_1_2_AllResult {

        val duration = 10.seconds
        val results = mutableMapOf<String, TLS_1_2_Result>()
        val groupNameP256 = "secp256r1"
        val tlsVersion = "TLSv1.2"

        // "Recommended Profiles for TLS 1.2"
        rateLimiter.acquire()

        val signatureExtensions = arrayOf(
            // RSA
            "RSA_PKCS1_SHA256",
            "RSA_PKCS1_SHA384",
            "RSA_PKCS1_SHA512",
            "RSA_PSS_RSAE_SHA256",
            "RSA_PSS_RSAE_SHA384",
            "RSA_PSS_RSAE_SHA512",
            "RSA_PSS_PSS_SHA256",
            "RSA_PSS_PSS_SHA384",
            "RSA_PSS_PSS_SHA512",
            // ECDSA
            "ECDSA_SECP256R1_SHA256",
            "ECDSA_SECP384R1_SHA384",
            "ECDSA_SECP521R1_SHA512",
            // Neue ED
            "ED25519",
            "ED448"
        )

        // "ECDHE using P-256 Curve" -> secp256r1
        val cipherSuiteECDSA = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        val configTLSECDSA = tlsRequirements(tlsVersion, cipherSuiteECDSA,
            arrayOf(groupNameP256), signatureExtensions)
        val resultECDSA = checkTLSConfig(domain, configTLSECDSA, 256, PubKeyAlgorithm.ECDSA)
        results["Recommended_ECDSA_GCM_P-256"] = resultECDSA

        delay(duration)
        rateLimiter.acquire()

        // RSA Authentifikation
        val cipherSuiteRSA = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        val configTLSRSA = tlsRequirements(tlsVersion, cipherSuiteRSA,
            arrayOf(groupNameP256), signatureExtensions)
        val resultRSA = checkTLSConfig(domain,configTLSRSA,2048, PubKeyAlgorithm.RSA)
        results["Recommended_RSA_GCM_P-256"] = resultRSA

        delay(duration)
        rateLimiter.acquire()


        // "Compatibility Profile for TLS 1.2" mit CBC Verschlüsselung
        val cipherSuiteRSA_CBC = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
        val configTLSRSA_CBC = tlsRequirements(tlsVersion, cipherSuiteRSA_CBC, arrayOf(groupNameP256),
            signatureExtensions)
        val resultRSA_CBC = checkTLSConfig(domain,configTLSRSA_CBC,2048, PubKeyAlgorithm.RSA)
        results["Compatibility_RSA_CBC_P-256"] = resultRSA_CBC


        return TLS_1_2_AllResult(domain, results)

    }




    public fun checkTLSConfig(domain: String, tlsRequirements: tlsRequirements, pubKeyLength: Int, pubKeyAlgorithm: PubKeyAlgorithm, ignoreCAValidity: Boolean = false): TLS_1_2_Result {


        var firstHandshake = TlsSmtpCertCheck(domain).testSmtpTlsHandshake(tlsRequirements,ignoreCAValidity)
        val resultHandshake = if(firstHandshake?.errorType == null) { firstHandshake  } else { Thread.sleep(1000); TlsSmtpCertCheck(domain).testSmtpTlsHandshake(tlsRequirements,ignoreCAValidity)}


        // Wesentliche Fehlerfälle prüfen
        if (resultHandshake == null || resultHandshake.errorType != null || resultHandshake.cipherSuite != tlsRequirements.cipherSuite) {

            return TLS_1_2_Result(
                domain,
                tlsRequirements.cipherSuite!!,
                tlsRequirements.curvesData!!.joinToString(","),
                false,
                resultHandshake?.errorType,
                tlsData = resultHandshake
            )

        }


        val certInfo = resultHandshake.tlsServerCertificateInfo
        val algorithm = certInfo?.publicKeyAlgorithm
        val signature = certInfo?.signatureAlgorithm
        val certKeyLength = certInfo?.publicKeyLength

       // Beispiel RSA: Neben "RSA", "RSA-PSS" wäre noch denkbar
        if(algorithm != null && !algorithm.contains(pubKeyAlgorithm.stringText)) {


            return TLS_1_2_Result(
                domain,
                tlsRequirements.cipherSuite!!,
                tlsRequirements.curvesData!!.joinToString(","),
                false,
                Tls_1_2_Error.WrongCertPubKey.stringText,
                algorithm,
                certKeyLength,
                signature,
                resultHandshake
            )

        }


        // Public Key Längenprüfung, je Nach Public-Key-Algorithmus
        when (pubKeyAlgorithm) {

            PubKeyAlgorithm.RSA -> {
                if(certKeyLength != null && certKeyLength < pubKeyLength) {

                    return TLS_1_2_Result(
                        domain,
                        tlsRequirements.cipherSuite!!,
                        tlsRequirements.curvesData!!.joinToString(","),
                        false,
                        Tls_1_2_Error.TooShortRSAKey.stringText,
                        algorithm,
                        certKeyLength,
                        signature,
                        resultHandshake
                    )

                }
            }


            PubKeyAlgorithm.ECDSA -> {
                if(certKeyLength != null && certKeyLength != pubKeyLength) {

                    return TLS_1_2_Result(
                        domain,
                        tlsRequirements.cipherSuite!!,
                        tlsRequirements.curvesData!!.joinToString(","),
                        false,
                        Tls_1_2_Error.ECFieldLength.stringText,
                        algorithm,
                        certKeyLength,
                        signature,
                        resultHandshake
                    )

                }
            }
        }



        // Erfolgsfall: Keiner der Fehlerfälle trifft zu
        return TLS_1_2_Result(
            domain,
            tlsRequirements.cipherSuite!!,
            tlsRequirements.curvesData!!.joinToString(","),
            true,
            null,
            algorithm,
            certKeyLength,
            signature,
            resultHandshake

        )



    }

}