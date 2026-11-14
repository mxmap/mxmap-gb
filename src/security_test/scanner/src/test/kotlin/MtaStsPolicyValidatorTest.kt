import commands.MtaStsPolicyCommand
import models.enums.MtaStsPolicyError
import org.junit.Assert.*
import org.junit.Test

class MtaStsPolicyValidatorTest {

    // Die Basis-Policy, die in den meisten Tests mutiert wird
    private val validBasePolicy = "version: STSv1\r\n" +
            "mode: enforce\r\n" +
            "mx: smtp.google.com\r\n" +
            "mx: gmail-smtp-in.l.google.com\r\n" +
            "mx: *.gmail-smtp-in.l.google.com\r\n" +
            "max_age: 86400\r\n"

    // --- Generelle Fehlerfälle ---

    @Test
    fun `Komplett leere Policy`() {
        val command = MtaStsPolicyCommand("example.com")
        val resultNull = command.validatePolicy(null)
        val resultEmpty = command.validatePolicy("")
        val resultEmptyWithLinebreak = command.validatePolicy("\r\n")


        assertEquals(MtaStsPolicyError.EmptyPolicy, resultNull.errorType)
        assertEquals(MtaStsPolicyError.EmptyPolicy, resultEmpty.errorType)
        assertEquals(MtaStsPolicyError.SyntaxErrorKeyValueFormat, resultEmptyWithLinebreak.errorType)
    }

    @Test
    fun `Leerzeichen vor einem Key`() {
        val command = MtaStsPolicyCommand("example.com")
        // " version: STSv1..." -> Key wird als " version" geparst und fällt durch die OtherFields-Regex
        val policy = validBasePolicy.replace("version:", " version:")
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorOtherFields, result.errorType)
    }

    @Test
    fun `Mehrere Leerzeichen direkt nach einem Key`() {
        val command = MtaStsPolicyCommand("example.com")
        // "version  : STSv1..." -> Key wird als "version  " geparst und fällt durch OtherFields-Regex
        val policy = validBasePolicy.replace("version:", "version  :")
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorOtherFields, result.errorType)
    }


    @Test
    fun `Nur Key`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = "version:\r\nmode: enforce\r\nmax_age: 86400\r\nmx"
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorKeyValueFormat, result.errorType)
    }

    @Test
    fun `Leeres Feld nach Doppelpunkt (kein Value)`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = "version:\r\nmode: enforce\r\nmax_age: 86400\r\nmx: m-x.de"
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorKeyValueFormat, result.errorType)
    }

    @Test
    fun `Gültig - Zeilenumbruch am Ende der letzten Zeile`() {
        val command = MtaStsPolicyCommand("example.com")
        val result = command.validatePolicy(validBasePolicy)

        assertNull(result.errorType)

        // Prüfe auch Inhalt vom Datenobjekt
        assertEquals("enforce", result.policyData?.mode)
        assertEquals(3, result.policyData?.mx_list?.size)
        assertEquals("smtp.google.com", result.policyData?.mx_list?.first())
        assertEquals("86400", result.policyData?.max_age)
    }

    @Test
    fun `Gültig - Völlig vertauschte Reihenfolge der Kernfelder`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = "max_age: 86400\r\nmx: smtp.google.com\r\nmode: enforce\r\nversion: STSv1"
        val result = command.validatePolicy(policy)

        assertNull(result.errorType)
    }

    // --- Kernfelder-Validierung ---

    @Test
    fun `Version - Falscher Versionswert (Case Falsch)`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy.replace("STSv1", "stSV1")
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorInvalidVersion, result.errorType)
    }

    @Test
    fun `Mode - Falscher Mode`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy.replace("enforce", "testng")
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorInvalidMode, result.errorType)
    }

    @Test
    fun `Max_age - Unpassende Zeichen`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy.replace("86400", "86:400")
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorInvalidMaxAge, result.errorType)
    }

    @Test
    fun `Max_age - Zu große Zahl (11 Ziffern)`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy.replace("86400", "12345678901")
        val result = command.validatePolicy(policy)
        // Regex ^[0-9]{1,10}$ schlägt hier fehl
        assertEquals(MtaStsPolicyError.SyntaxErrorInvalidMaxAge, result.errorType)
    }

    @Test
    fun `Max_age - Zu großer Zahlenwert (groeßer 31557600)`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy.replace("86400", "31557601")
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorTooLongMaxAge, result.errorType)
    }

    @Test
    fun `Gültig- Max_age - Maximalwert(31557600)`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy.replace("86400", "31557600")
        val result = command.validatePolicy(policy)

        assertNull(result.errorType)
    }

    @Test
    fun `Max_age zu kleiner Wert (negativ) -1`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy.replace("86400", "-1")
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorInvalidMaxAge, result.errorType)
    }

    @Test
    fun `Gültig - Max_age Minimalwert 0`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy.replace("86400", "0")
        val result = command.validatePolicy(policy)

        assertNull(result.errorType)
    }


    // --- Sonstige Felder ---

    @Test
    fun `Gültig - Mehrere Versions-Felder, zweites mit Doppelpunkt im Wert`() {
        val command = MtaStsPolicyCommand("example.com")
        // Das erste version-Feld wird geparst, das zweite rutscht in "validatePolicyOtherFields"
        val policy = validBasePolicy + "version: STSv1:Zusatz\r\n"
        val result = command.validatePolicy(policy)

        assertNull(result.errorType)
    }

    @Test
    fun `Ungültiger Keywert (#key)`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy + "#key: value\r\n"
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorOtherFields, result.errorType)
    }

    @Test
    fun `Gültig - Sonstiges Feld mit gültigem Key und Leerzeichen in der Mitte des Wertes`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy + "custom_field: val ue\r\n"
        val result = command.validatePolicy(policy)

        assertNull(result.errorType)
    }

    // --- Mx-Feld ---

    @Test
    fun `Mx-Feld - Ungültige Subdomain 1 (m colon x)`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy + "mx: m:x.google.de\r\n"
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorInvalidMxPattern, result.errorType)
    }

    @Test
    fun `Mx-Feld - Ungültige Subdomain 2 (zwei Sterne)`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy + "mx: *.*.mx.google.de\r\n"
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorInvalidMxPattern, result.errorType)
    }

    @Test
    fun `Mx-Feld - Ungültige Subdomain 3 (doppelter Punkt)`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy + "mx: mx..google.de\r\n"
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorInvalidMxPattern, result.errorType)
    }

    @Test
    fun `Mx-Feld - Ungültige Subdomain 4 (Punkt am Ende)`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy + "mx: mx.google.de.\r\n"
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorInvalidMxPattern, result.errorType)
    }

    // --- Mode ---

    @Test
    fun `Mode - Nicht none und kein MX-Feld`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = "version: STSv1\r\nmode: enforce\r\nmax_age: 86400\r\n"
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorNoMxPattern, result.errorType)
    }

    @Test
    fun `Mode - Mehrere MX-Felder (eines ungültig)`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy + "mx: mx..google.de\r\n"
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorInvalidMxPattern, result.errorType)
    }

    @Test
    fun `Mode - Gültige Subdomain mit Bindestrich`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = "version: STSv1\r\nmode: enforce\r\nmax_age: 86400\r\nmx: m-x.de\r\n"
        val result = command.validatePolicy(policy)

        assertNull(result.errorType)
    }

    @Test
    fun `Mode - Sonderfall mit 'none' und kein mx-Feld`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = "version: STSv1\r\nmode: none\r\nmax_age: 86400\r\n"
        val result = command.validatePolicy(policy)

        assertNull(result.errorType)
    }

    @Test
    fun `Mode - Mehrere Mx-Felder (alle Gültig)`() {
        val command = MtaStsPolicyCommand("example.com")
        // Die basePolicy enthält bereits 3 gültige MX-Einträge
        val result = command.validatePolicy(validBasePolicy)

        assertNull(result.errorType)
    }

    // --- Vorhandensein von Key-Value-Paaren ---

    @Test
    fun `Gültig - Mehrere Max-Age Felder (nimmt nur das erste)`() {
        val command = MtaStsPolicyCommand("example.com")
        // Füge ein zweites max_age-Feld am Ende an. Da es ignoriert und als OtherField validiert wird,
        // sollte es zu keinem Fehler kommen.
        val policy = validBasePolicy + "max_age: 12345\r\n"
        val result = command.validatePolicy(policy)

        assertNull(result.errorType)
        assertEquals("86400", result.policyData?.max_age)
    }

    @Test
    fun `Typo in versions-Key (vrsion) - Nicht gefunden`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = validBasePolicy.replace("version:", "vrsion:")
        val result = command.validatePolicy(policy)
        // "vrsion" ist ein valides custom_field, aber die verpflichtende "version" fehlt
        assertEquals(MtaStsPolicyError.SyntaxErrorNoVersion, result.errorType)
    }

    @Test
    fun `Kein mode-Feld`() {
        val command = MtaStsPolicyCommand("example.com")
        val policy = "version: STSv1\r\nmx: smtp.google.com\r\nmax_age: 86400\r\n"
        val result = command.validatePolicy(policy)

        assertEquals(MtaStsPolicyError.SyntaxErrorNoMode, result.errorType)
    }
}