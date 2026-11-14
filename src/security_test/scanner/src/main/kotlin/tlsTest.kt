import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.SSLContext

class tlsTest {
    fun testTLSConfig() {



            // Eine Liste bekannter Kurven, die wir testen wollen
            val curvesToTest = listOf(
                "secp256r1", "secp384r1", "secp521r1", // NIST Kurven (Standard für TLS)
                "prime256v1",                          // Anderer Name für secp256r1
                "secp256k1",                           // Bitcoin-Kurve
                "brainpoolP256r1", "brainpoolP384r1",  // Brainpool (oft in DE/Behörden gefordert)
                "X25519", "X448"                       // Moderne Kurven
            )

            println("=== Teste spezifische Elliptische Kurven ===")

            val ecKpg = KeyPairGenerator.getInstance("EC")
            println("=== 1. Unterstützte TLS-Protokolle & Cipher-Suites ===")
            val context = SSLContext.getDefault()
            val params = context.supportedSSLParameters
            //context.defaultSSLParameters
            println("Protokolle:")
            params.protocols.forEach { println(" - $it") }

            println("\nCipher Suites (unterstützt, aber ggf. nicht alle standardmäßig aktiv):")
            params.cipherSuites.forEach { println(" - $it") }
            for (curve in curvesToTest) {
                try {
                    // Versuch 1: Ist es ein Parameter für den allgemeinen "EC" Algorithmus?
                    ecKpg.initialize(ECGenParameterSpec(curve))
                    println("✅ Unterstützt: $curve")
                } catch (e: Exception) {
                    // Versuch 2: Ist es ein eigenständiger Algorithmus (wie X25519)?
                    try {
                        KeyPairGenerator.getInstance(curve)
                        println("✅ Unterstützt (als eigener Alg.: $curve)")
                    } catch (e2: Exception) {
                        println("❌ NICHT unterstützt: $curve")
                    }
                }
            }
        }
    }

