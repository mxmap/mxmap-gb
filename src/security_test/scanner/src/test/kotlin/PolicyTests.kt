import commands.MtaStsPolicyCommand
import commands.TlsHttpCertCheck
import commands.TlsSmtpCertCheck

import org.junit.Assert.*
import org.junit.Test

class PolicyTests {


    @Test
    fun test() {
        val policy = MtaStsPolicyCommand("gmail.com")
        //policy.getPolicy()
    }

    @Test
    fun testWithTruststore() {
/*
        val tls = TLS("104.154.89.105","untrusted-root.badssl.com")
        val tlsCollection = tls.testTLS()
        assertEquals("Root-CA-Untrusted", tlsCollection.failure)
*/
        //val tlsRSA = TLS("104.154.89.105", "static-rsa.badssl.com")
        //val tlsCollection2 = tlsRSA.testTLS()
        //assertEquals("TLS_RSA_WITH_AES_256_GCM_SHA384", tlsCollection2.cipherSuite)


        val tls = TlsHttpCertCheck( "badssl.com","104.154.89.105")
        val tlsCollection3 = tls.testHttpsTlsHandshake()


        //val smtpTLS = TlsSmtpCertCheck("142.251.127.26","gmail-smtp-in.l.google.com")
        val smtpTLS = TlsSmtpCertCheck("192.168.255.255", "localhost")
        val smtp = smtpTLS.testSmtpTlsHandshake()


    }

    @Test
    fun tesPolicyRetrieval() {
        val mtaStsPolicyInstance = MtaStsPolicyCommand("gmail.com")
        val policy = mtaStsPolicyInstance.retrievePolicy()
        println(policy.hasPolicy)
        println(policy.rawPolicy)
        //println(policy.errorType)
        //println(policy.errorMessage)


        //val validator = mtaStsPolicyInstance.validatePolicy(policy.rawPolicy)
        //assertEquals(null,policy.rawPolicy,)

    }


    @Test
    fun testStringSplit() {
        val new = ""
        val split = new.split(":")
        println(split.size )
    }


    @Test
    fun testStringSplit2() {
        val new = "gsgs\r\ngsgsgsg"

        // Zeilenweise spalten (CRLF oder LF gemäß Grammatik!) -> Hier auch CR
        val linesRaw = new.lines()

        // Grammatik erlaubt ein CRLF/ LF am Ende einer letzten Zeile -> Das sorgt für ein leeres letztes Zeilenelement
        val lines =  if (linesRaw.isNotEmpty() && linesRaw.last().isEmpty()) {
            linesRaw.dropLast(1)
        } else {
            linesRaw
        }
        println(lines.size )
    }
}