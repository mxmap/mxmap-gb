import commands.TlsRptDnsRecordCommand
import dataClass.TLS.TlsRptAdress
import models.enums.TlsRptDnsRecordError
import org.junit.Assert.*
import org.junit.Test

class TlsRptDnsRecordParserTest {

     // Name ggf. anpassen
    private val testDomain = "example.com"
    private var parser = TlsRptDnsRecordCommand(testDomain)
        // Hier wird die Klasse instanziiert, der die parseDnsRecord-Methode angehört.



    // ==========================================
    // Generelle Testfälle
    // ==========================================

    @Test
    fun `Gültig - Standard DNS-Record`() {
        val record = "v=TLSRPTv1;rua=mailto:sts-reports@google.com"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertNull(result.errorType)
        assertEquals(1, result.adressList?.size)
        assertEquals(true, result.adressList?.get(0)?.schemeMailto)
        assertEquals("google.com", result.adressList?.get(0)?.hostname)
    }

    @Test
    fun `Leerer DNS-Record (nur Whitespace)`() {
        val record = "   "
        val result = parser.parseDnsRecord(record)

        assertFalse(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.EmptyDnsRecord, result.errorType)
    }

    @Test
    fun `Rua-Feld mit nur key rua (kein = Zeichen und kein Wert)`() {
        val record = "v=TLSRPTv1;rua"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.NoKeyValueFormat, result.errorType)
    }

    @Test
    fun `Gültig - Semikolon am Ende des DNS-Records`() {
        val record = "v=TLSRPTv1;rua=mailto:sts-reports@google.com;"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertNull(result.errorType)
        assertEquals(1, result.adressList?.size)
    }

    @Test
    fun `Gültig - Zwischen Semikolon und rua-Key beliebig Whitespace`() {
        val record = "v=TLSRPTv1;   rua=mailto:sts-reports@google.com"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertNull(result.errorType)
    }

    // ==========================================
    // Versionsfeld
    // ==========================================

    @Test
    fun `Kein gültiges Versionsfeld (Falscher Wert)`() {
        val record = "v=TLSRPTv2;rua=mailto:sts-reports@google.com"
        val result = parser.parseDnsRecord(record)

        assertFalse(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.NoVersionField, result.errorType)
    }

    @Test
    fun `Kein gültiges Versionsfeld (Case - falsche Groß- und Kleinschreibung)`() {
        val record = "v=tlsrptv1;rua=mailto:sts-reports@google.com"
        val result = parser.parseDnsRecord(record)

        assertFalse(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.NoVersionField, result.errorType)
    }

    @Test
    fun `Versionsfeld mit beliebig Whitespace nach Versionswert`() {
        // Matches Regex, but fails startsWith("v=TLSRPTv1;")
        val record = "v=TLSRPTv1   ;rua=mailto:sts-reports@google.com"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.VersionValueMatchesABNFOnly, result.errorType)
    }

    // ==========================================
    // Rua-Syntax
    // ==========================================

    @Test
    fun `Leerer rua-Wert (nur Whitespace)`() {
        val record = "v=TLSRPTv1;rua=   "
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.EmptyRuaValue, result.errorType)
    }

    @Test
    fun `Rua Feld mit Leerzeichen vor dem Inhalt`() {
        val record = "v=TLSRPTv1;rua= mailto:sts-reports@google.com"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.InvalidRuaValue, result.errorType)
    }

    // ==========================================
    // URI-Syntax
    // ==========================================

    @Test
    fun `Rua Feld mit Inhalt abc`() {
        val record = "v=TLSRPTv1;rua=abc"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        // Scheme is missing or unknown
        assertEquals(TlsRptDnsRecordError.InvalidUriScheme, result.errorType)
    }

    @Test
    fun `URI Feld mit ungültigem Schema (mail ohne mailto)`() {
        val record = "v=TLSRPTv1;rua=abc@google.com"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.InvalidUriScheme, result.errorType)
    }


    @Test
    fun `URI Feld mit ungültigem URI-Zeichen-Unkodiertes Komma`() {
        val record = "v=TLSRPTv1;rua=mailto:abc@goo,gle.com"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.InvalidReportUri, result.errorType)
    }


    @Test
    fun `URI Feld mit ungültigem Domainanfang`() {
        val record = "v=TLSRPTv1;rua=mailto:abc@-google.com"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.InvalidReportUri, result.errorType)
    }



    // Limitation: Kein unkodiertes ; in URL kann hier erkannt werden -> Syntax-Error other field
    @Test
    fun `URI Feld mit ungültigem URI-Zeichen-Unkodiertes Semikolon im Hostnamen`() {
        val record = "v=TLSRPTv1;rua=https://abcgoo;gle.com?key=value"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.SyntaxErrorOtherField, result.errorType)
    }

    // Limitation: Kein unkodiertes ; in URL kann hier erkannt werden. Das Programm behandelt den Inhalt nach dem Semikolon als
    // Weiteres Feld
    @Test
    fun `URI Feld mit ungültigem URI-Zeichen-Unkodiertes Semikolon im Query String`() {
        val record = "v=TLSRPTv1;rua=https://abcgoogle.com?key=va;lue=e"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.InvalidReportUri, result.errorType)
    }


    // ggf. überarbeiten
    @Test
    fun `URI Feld mit ungültiger HTTPS-URL (kein Host)`() {
        val record = "v=TLSRPTv1;rua=https://"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        // Da parsedUri.host null ist, schlägt der https-Check fehl
        assertEquals(TlsRptDnsRecordError.InvalidReportUri, result.errorType)
    }

    @Test
    fun `URI Feld mit ungültiger E-Mail-Syntax`() {
        // Angenommen, der EmailValidator schlägt hier fehl
        val record = "v=TLSRPTv1;rua=mailto:ungueltige_email_ohne_at_zeichen"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.InvalidReportUri, result.errorType)
    }


    @Test
    fun `Mehrere Reporting URIs, darunter einer mit leerem URI-Feld`() {
        val record = "v=TLSRPTv1;rua=mailto:test@google.com,   ,https://google.com"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.EmptyReportUri, result.errorType)
    }


    @Test
    fun `Gültig - Mehrere Reporting URIs mit mehreren Schemes`() {
        val record = "v=TLSRPTv1;rua=mailto:test@google.com, https://google.com, mailto:test@google.com, mailto:test2@google2.com"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertNull(result.errorType)
        assertEquals(2,result.adressList?.size)
        assertTrue(result.adressList?.get(0)?.schemeMailto == true)
        assertTrue(result.adressList?.get(0)?.schemeHttps == true)

        assertEquals("google2.com", result.adressList?.get(1)?.hostname)
        assertTrue(result.adressList?.get(1)?.schemeMailto == true)
        assertTrue(result.adressList?.get(1)?.schemeHttps == false)
    }

    @Test
    fun `Gültig - Mehrere Reporting URIs mit mehreren Schemes und rua Felder`() {
        val record = "v=TLSRPTv1;rua=mailto:test@google.com,https://google.com;rua=mailto:test@google.com;rua=mailto:test2@google2.com"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertNull(result.errorType)
        assertEquals(2,result.adressList?.size)
        assertTrue(result.adressList?.get(0)?.schemeMailto == true)
        assertTrue(result.adressList?.get(0)?.schemeHttps == true)

        assertEquals("google2.com", result.adressList?.get(1)?.hostname)
        assertTrue(result.adressList?.get(1)?.schemeMailto == true)
        assertTrue(result.adressList?.get(1)?.schemeHttps == false)
    }


    @Test
    fun `Mehrere Reporting URIs mit Komma am Ende (Keine URI folgt daraufhin)`() {
        val record = "v=TLSRPTv1;rua=mailto:test@google.com,"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.EmptyReportUri, result.errorType)
    }

    // ==========================================
    // Rua
    // ==========================================

    @Test
    fun `Rua-Feld fehlt vollständig`() {
        val record = "v=TLSRPTv1;ext=123"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.MissingRua, result.errorType)
    }

    // ==========================================
    // Syntax von weiterem (key_value)-Feld
    // ==========================================

    @Test
    fun `Gültig - Weiteres syntaktisch korrektes Feld`() {
        val record = "v=TLSRPTv1;rua=mailto:sts-reports@google.com;custom=12345"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertNull(result.errorType)
    }

    @Test
    fun `Weiteres Feld mit syntaktisch inkorrektem Key`() {
        // Key darf nicht mit Sonderzeichen beginnen (siehe Regex ^[a-zA-Z0-9]{1}...)
        val record = "v=TLSRPTv1;rua=mailto:sts-reports@google.com;_invalidKey=123"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.SyntaxErrorOtherField, result.errorType)
    }

    @Test
    fun `Weiteres Feld mit syntaktisch inkorrektem Value`() {
        // Value erlaubt laut Regex keine Nicht-ASCII oder bestimmte Sonderzeichen (z.B. Leerzeichen)
        val record = "v=TLSRPTv1;rua=mailto:sts-reports@google.com;custom=wert mit leerzeichen"
        val result = parser.parseDnsRecord(record)

        assertTrue(result.hasDnsRecord)
        assertEquals(TlsRptDnsRecordError.SyntaxErrorOtherField, result.errorType)
    }



    @Test
    fun test1() {
        val record = "v=TLSRPTv1; rua=mailto:postmaster@domain2.de, mailto:postmaster@subdomain.domain2.de, https://domain2.de/test?key=value, https://domain2.de, https://subdomain2.domain2.de, https://subdomain3.domain2.de, mailto:postmaster@externeDomain.de; rua=mailto:postmaster@externeDomain2.de, https://externeDomain2.de, https://externeDomain3.de"
        val result = parser.parseDnsRecord(record)
        assertNull(result.errorType)
    }

    @Test
    fun test() {
        val result = parser.parseDnsRecord("v=TLSRPTv1; rua=mailto:postmaster@hooge.de")
        print(result)
    }
}