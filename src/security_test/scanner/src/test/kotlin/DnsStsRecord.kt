
import Dig.parseDigOutput
import models.dataClass.DigCmdResult
import commands.MtaStsPolicyCommand
import models.enums.MtaStsDnsRecordError

import java.io.File
import org.junit.Assert.*
import org.junit.Test

class DnsStsRecord {
/*
    private fun loadAndParseTestFile(fileName: String): MtaStsDnsRecordError {
        val mtaStSRecordOutput = File("C:\\Users\\jorel\\Desktop\\8. Sem BA\\Codes\\UnitTestDigTestfiles\\TestcasesDigMtaStsTxtRec\\$fileName").readText(Charsets.UTF_8)

        // Simuliere den Parse-Ablauf deines Scanners
        val res = parseDigOutput(DigCmdResult(mtaStSRecordOutput, 0), "_mta-sts.cheshireeast.gov.uk", "TXT")
        val parsing = MtaStsPolicyCommand("_mta-sts.cheshireeast.gov.uk")

        return parsing.stsDnsRecordParsing(res.answer.first())
    }

    @Test
    fun `Test valid record`() {
        assertEquals(MtaStsDnsRecordError.None, loadAndParseTestFile("DigMtaStsPolicyWithMultipleStrings"))
    }

    @Test
    fun `Test wrong case for STSv1`() {
        assertEquals(MtaStsDnsRecordError.SyntaxErrorCaseStsVersion, loadAndParseTestFile("wrongCaseVersion"))
    }

    @Test
    fun `Test double semicolon`() {
        assertEquals(MtaStsDnsRecordError.SyntaxErrorBetweenFields, loadAndParseTestFile("doubleSemicolon"))
    }

    @Test
    fun `Test missing ID field`() {
        assertEquals(MtaStsDnsRecordError.SyntaxErrorNoIDField, loadAndParseTestFile("noIDAvailable"))
    }

    @Test
    fun `Test invalid characters in ID`() {
        assertEquals(MtaStsDnsRecordError.SyntaxErrorInvalidIDField, loadAndParseTestFile("invalidIDValChars"))
    }

    @Test
    fun `Test invalid ABNF in extension field`() {
        assertEquals(MtaStsDnsRecordError.SyntaxErrorField, loadAndParseTestFile("wrongExtensionfieldChar"))
    }

    @Test
    fun `Test valid Space between fields`() {
        assertEquals(MtaStsDnsRecordError.None, loadAndParseTestFile("Spacebetween"))
    }

    @Test
    fun `Test valid end semicolon`() {
        assertEquals(MtaStsDnsRecordError.None, loadAndParseTestFile("EndSemicolon"))
    }

    @Test
    fun `Test id with invalid field1`() {
        assertEquals(MtaStsDnsRecordError.SyntaxErrorField, loadAndParseTestFile("invalidField1"))
    }

    @Test
    fun `Test id with invalid field2`() {
        assertEquals(MtaStsDnsRecordError.SyntaxErrorField, loadAndParseTestFile("invalidField2"))
    }



    @Test
    fun `Test id with too long value`() {
        assertEquals(MtaStsDnsRecordError.SyntaxErrorInvalidIDField, loadAndParseTestFile("tooLongId"))
    }





    @Test
    fun txtRecord() {
        val mtaStSRecordOutput = File("C:\\Users\\jorel\\Desktop\\8. Sem BA\\Codes\\UnitTestDigTestfiles\\test.txt").readText(Charsets.UTF_8)
        val res = parseDigOutput(DigCmdResult(mtaStSRecordOutput, 0), "_mta-sts.cheshireeast.gov.uk", "TXT")
        val parsing = MtaStsPolicyCommand("_mta-sts.cheshireeast.gov.uk")

        val parsingResult = parsing.stsDnsRecordParsing(res.answer.first())
        assertEquals(MtaStsDnsRecordError.None, parsingResult)

    }
*/
}