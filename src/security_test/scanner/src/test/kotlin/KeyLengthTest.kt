import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.EdECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.interfaces.XECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.interfaces.DHPublicKey

class PubKeyLengthTest {

    // Experimentell
    public fun getPubKeyLength(pubKey: PublicKey): Int? {
        return when (pubKey) {
            is RSAPublicKey -> pubKey.modulus.bitLength()
            is ECPublicKey -> pubKey.params.curve.field.fieldSize
            is DSAPublicKey -> pubKey.params.p.bitLength()
            is DHPublicKey -> pubKey.params.p.bitLength()
            // Java 15+: Moderne Elliptische Kurven (Ed25519, Ed448) für Signaturen
            is EdECPublicKey -> getNamedCurveLength(pubKey.params.name)

            // Java 11+: Moderne Elliptische Kurven (X25519, X448) für Key Agreement
            is XECPublicKey -> getNamedCurveLength(pubKey.algorithm)

            // Fallback: Manche Provider (wie ältere BouncyCastle Versionen) implementieren
            // evtl. nicht die neuesten Java-Interfaces. Dann prüfen wir den Algorithmus-Namen.
            else -> getNamedCurveLength(pubKey.algorithm)
        }
    }

    private fun getNamedCurveLength(name: String?): Int? {
        return when (name?.uppercase()) {
            "ED25519" -> 256
            "X25519" -> 255  // X25519 operiert technisch auf 255 Bit
            "ED448", "X448" -> 448
            else -> null
        }
    }

    /*
    @Nested
    @DisplayName("Klassische Algorithmen (RSA, DSA, DH)")
    inner class ClassicalAlgorithms {

        @Test
        fun `test RSA key length`() {
            val kpg = KeyPairGenerator.getInstance("RSA")
            kpg.initialize(2048)
            val pubKey = kpg.generateKeyPair().public

            assertEquals(2048, getPubKeyLength(pubKey))
        }

        @Test
        fun `test DSA key length`() {
            val kpg = KeyPairGenerator.getInstance("DSA")
            kpg.initialize(2048)
            val pubKey = kpg.generateKeyPair().public

            assertEquals(2048, getPubKeyLength(pubKey))
        }

        @Test
        fun `test Diffie-Hellman (DH) key length`() {
            val kpg = KeyPairGenerator.getInstance("DiffieHellman")
            kpg.initialize(2048)
            val pubKey = kpg.generateKeyPair().public

            assertEquals(2048, getPubKeyLength(pubKey))
        }
    }

    @Nested
    @DisplayName("Elliptische Kurven (ECDSA)")
    inner class EllipticCurves {

        @Test
        fun `test EC P-256 (secp256r1)`() {
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            val pubKey = kpg.generateKeyPair().public

            assertEquals(256, getPubKeyLength(pubKey))
        }

        @Test
        fun `test EC P-384 (secp384r1)`() {
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp384r1"))
            val pubKey = kpg.generateKeyPair().public

            assertEquals(384, getPubKeyLength(pubKey))
        }
    }

    @Nested
    @DisplayName("Moderne Edwards Kurven (EdDSA & XDH)")
    inner class ModernCurves {

        // HINWEIS: Diese Tests benötigen mindestens Java 15 (für Ed25519) bzw. Java 11 (für X25519)

        @Test
        fun `test Ed25519 key length`() {
            val kpg = KeyPairGenerator.getInstance("Ed25519")
            val pubKey = kpg.generateKeyPair().public

            assertEquals(256, getPubKeyLength(pubKey))
        }

        @Test
        fun `test Ed448 key length`() {
            val kpg = KeyPairGenerator.getInstance("Ed448")
            val pubKey = kpg.generateKeyPair().public

            assertEquals(448, getPubKeyLength(pubKey))
        }

        @Test
        fun `test X25519 key length`() {
            val kpg = KeyPairGenerator.getInstance("X25519")
            val pubKey = kpg.generateKeyPair().public

            assertEquals(255, getPubKeyLength(pubKey))
        }

        @Test
        fun `test X448 key length`() {
            val kpg = KeyPairGenerator.getInstance("X448")
            val pubKey = kpg.generateKeyPair().public

            assertEquals(448, getPubKeyLength(pubKey))
        }
    }

     */
}