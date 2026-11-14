import commands.MtaStsDnsRecordCommand
import models.enums.MtaStsDnsRecordError
import org.junit.Assert.*
import org.junit.Test

class MtaStsDnsRecordCommandTest {

    private val domain = "example.com"
    private val command = MtaStsDnsRecordCommand(domain)

    // 1. Gültig: Valider STS-Record
    @Test
    fun `Gueltig - Valider STS-Record`() {
        val record = "v=STSv1; id=20190429T010101;"
        val result = command.parseDnsRecord(record)

        assertNull(result.errorType)
        assertTrue(result.hasRecord)
        assertEquals(record, result.rawRecord)
    }

    // 2. Leerer DNS-Record
    @Test
    fun `Ungueltig - Leerer DNS-Record`() {
        val record = "   "
        val result = command.parseDnsRecord(record)

        assertEquals(MtaStsDnsRecordError.EmptyDnsRecord, result.errorType)
        assertFalse(result.hasRecord)
    }

    // 3. Falsches Versionsfeld (v=stsv1; -> Falscher Case)
    @Test
    fun `Ungueltig - Falsches Versionsfeld (Case)`() {
        val record = "v=stsv1; id=20190429T010101;"
        val result = command.parseDnsRecord(record)

        assertEquals(MtaStsDnsRecordError.NoVersionField, result.errorType)
    }

    // 4. Leerzeichen nach Versionsfeld-Wert  (v=STSv1   ;)
    @Test
    fun `Ungueltig - Leerzeichen nach Versionsfeld-Wert`() {
        val record = "v=STSv1  ; id=20190429T010101;"
        val result = command.parseDnsRecord(record)

        // Entspricht der Regex, schlägt aber bei .startsWith("v=STSv1;") fehl
        assertEquals(MtaStsDnsRecordError.VersionValueMatchesABNFOnly, result.errorType)
        assertTrue(result.hasRecord)
    }

    // 5. Nur Leerzeichen zwischen Semikolons
    @Test
    fun `Ungueltig - Nur Leerzeichen zwischen Semikolons`() {
        val record = "v=STSv1;   ; id=20190429T010101;"
        val result = command.parseDnsRecord(record)

        // keyValue.size ist < 2, da der Split bei einem reinen Leerzeichen-String ("") kein "=" findet
        assertEquals(MtaStsDnsRecordError.NoKeyValueFormat, result.errorType)
    }

    // 6. Nur id (ohne =-Zeichen und Wert)
    @Test
    fun `Ungueltig - Nur id ohne Gleichheitszeichen und Wert`() {
        val record = "v=STSv1; id;"
        val result = command.parseDnsRecord(record)

        assertEquals(MtaStsDnsRecordError.NoKeyValueFormat, result.errorType)
    }

    // 7. Id-Feld fehlt vollständig
    @Test
    fun `Ungueltig - Id-Feld fehlt vollstaendig`() {
        val record = "v=STSv1;"
        val result = command.parseDnsRecord(record)

        assertEquals(MtaStsDnsRecordError.NoIDField, result.errorType)
    }

    // 8. ID-Feld hat keinen Wert (besitzt aber key und =-Zeichen)
    @Test
    fun `Ungueltig - ID-Feld hat keinen Wert`() {
        val record = "v=STSv1; id=;"
        val result = command.parseDnsRecord(record)

        assertEquals(MtaStsDnsRecordError.InvalidIDField, result.errorType)
    }

    // 9. Ungültiger Wert beim ID-Feld
    @Test
    fun `Ungueltig - Ungueltiger Wert beim ID-Feld`() {
        // Enthält ungültiges Sonderzeichen (Bindestrich)
        val record = "v=STSv1; id=20190429-010101;"
        val result = command.parseDnsRecord(record)

        assertEquals(MtaStsDnsRecordError.InvalidIDField, result.errorType)
    }

    // 10. Zu langer ID-Wert beim ID-Feld
    @Test
    fun `Ungueltig - Zu langer ID-Wert beim ID-Feld`() {
        // 33 Zeichen (erlaubt sind laut parseIDValue max 32)
        val record = "v=STSv1; id=123456789012345678901234567890123;"
        val result = command.parseDnsRecord(record)

        assertEquals(MtaStsDnsRecordError.InvalidIDField, result.errorType)
    }

    // 11. Gültig: Gültiges weiteres Feld im DNS-Record
    @Test
    fun `Gueltig - Gueltiges weiteres Feld im DNS-Record`() {
        val record = "v=STSv1; id=20190429T010101; ext=valid_value;"
        val result = command.parseDnsRecord(record)

        assertNull(result.errorType)
        assertTrue(result.hasRecord)
    }

    // 12. Weiteres Feld mit ungültigem Key
    @Test
    fun `Ungueltig - Weiteres Feld mit ungueltigem Key`() {
        // "@" ist im Key laut checkDnsExtensionFields nicht erlaubt
        val record = "v=STSv1; id=20190429T010101; e@xt=valid_value;"
        val result = command.parseDnsRecord(record)

        assertEquals(MtaStsDnsRecordError.SyntaxErrorOtherField, result.errorType)
    }

    // 13. Weiteres Feld mit ungültigem Value
    @Test
    fun `Ungueltig - Weiteres Feld mit ungueltigem Value`() {
        // Leerzeichen (\x20) sind laut checkDnsExtensionFields im Value nicht erlaubt
        val record = "v=STSv1; id=20190429T010101; ext=invalid value;"
        val result = command.parseDnsRecord(record)

        assertEquals(MtaStsDnsRecordError.SyntaxErrorOtherField, result.errorType)
    }
}