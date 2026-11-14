package emailtest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals


class SpfMXAParsingTest {

    fun extractSpfA_MxAddresses(spfRecord: String, mechanismType: String): List<String> {
        // Regex sucht nach SPF-Mechanismen der Form a:<MX-Domain> oder mx:<Domain>

        val safeMechanism = Regex.escape(mechanismType)

        val regex = Regex("(?i)(?:^|\\s)[+\\-~?]?$safeMechanism:([^\\s]+)")

        return regex.findAll(spfRecord)
            .map { it.groupValues[1] } // Die erste Capture-Group enthält die Adresse
            .toList()


    }
    
    
    
    @Test
    fun `extracts standard A and MX records`() {
        val spf = "v=spf1 a:example.com mx:mail.example.org -all"

        assertEquals(listOf("example.com"), extractSpfA_MxAddresses(spf, "a"))
        assertEquals(listOf("mail.example.org"), extractSpfA_MxAddresses(spf, "mx"))
    }

    @Test
    fun `handles SPF qualifiers correctly`() {
        // Testet +, -, ~ und ? direkt vor dem Mechanismus
        val spf = "v=spf1 +a:plus.com -a:minus.com ~mx:soft.com ?mx:neutral.com -all"

        assertEquals(listOf("plus.com", "minus.com"), extractSpfA_MxAddresses(spf, "a"))
        assertEquals(listOf("soft.com", "neutral.com"), extractSpfA_MxAddresses(spf, "mx"))
    }

    @Test
    fun `is case insensitive`() {
        // Testet Großschreibung bei Mechanismus und Qualifier und mehrere Leerzeichen
        val spf = "v=spf1 A:upper.com      mX:mixed.com -ALL"

        assertEquals(listOf("upper.com"), extractSpfA_MxAddresses(spf, "a"))
        assertEquals(listOf("mixed.com"), extractSpfA_MxAddresses(spf, "mx"))
    }

    @Test
    fun `ignores naked mechanisms without colon`() {
        // Ein "a" oder "mx" ohne Doppelpunkt und Adresse soll ignoriert werden
        val spf = "v=spf1 a mx a:valid.com mx:valid-mx.com -all"

        assertEquals(listOf("valid.com"), extractSpfA_MxAddresses(spf, "a"))
        assertEquals(listOf("valid-mx.com"), extractSpfA_MxAddresses(spf, "mx"))
    }

    @Test
    fun `returns empty list if mechanism is not present`() {
        val spf = "v=spf1 include:_spf.google.com -all"

        assertEquals(emptyList<String>(), extractSpfA_MxAddresses(spf, "a"))
        assertEquals(emptyList<String>(), extractSpfA_MxAddresses(spf, "ptr"))
    }

    @Test
    fun `handles include mechanisms`() {
        val spf = "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all"

        assertEquals(
            listOf("spf.protection.outlook.com", "_spf.google.com"),
            extractSpfA_MxAddresses(spf, "include")
        )
    }
}
