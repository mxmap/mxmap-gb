import Dig.parseDigOutput
import models.dataClass.DigCmdResult
import org.junit.Assert.*
import org.junit.Test
import java.io.File


class DigTest {

    @Test
    fun txtRecord () {
        val mtaStSRecordOutput = File("C:\\Users\\jorel\\Desktop\\8. Sem BA\\Codes\\UnitTestDigTestfiles\\test.txt").readText(Charsets.UTF_8)
        /*val mtaStSRecordOutput = """
        ; <<>> DiG 9.18.30-0ubuntu0.20.04.2-Ubuntu <<>> TXT _mta-sts.cheshireeast.gov.uk
        ;; global options: +cmd
        ;; Got answer:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3432
        ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

        ;; OPT PSEUDOSECTION:
        ; EDNS: version: 0, flags:; udp: 512
        ;; QUESTION SECTION:
        ;_mta-sts.cheshireeast.gov.uk.  IN      TXT

        ;; ANSWER SECTION:
        _mta-sts.cheshireeast.gov.uk. 3276 IN   TXT     "v=STSv1;id=202201191147"

        ;; Query time: 63 msec
        ;; SERVER: 10.255.255.254#53(10.255.255.254) (UDP)
        ;; WHEN: Mon Jun 29 16:27:37 CEST 2026
        ;; MSG SIZE  rcvd: 93

        """
        */

        val res = parseDigOutput(DigCmdResult(mtaStSRecordOutput, 0), "_mta-sts.cheshireeast.gov.uk", "TXT")
        assertEquals(1, res.answer.size)
        assertEquals("\"v=STSv1;id=202201191147\"", res.answer.first())
        assertEquals(res.cnameChain.size,0)
        assertEquals(res.lastCname, null)
        assertFalse(res.adFlag)
    }

    @Test
    fun testCNAMERecord () {
        val mtaStSRecordOutput = File("C:\\Users\\jorel\\Desktop\\8. Sem BA\\Codes\\UnitTestDigTestfiles\\cName").readText(Charsets.UTF_8)

        val res = parseDigOutput(DigCmdResult(mtaStSRecordOutput, 0), "mta-sts.cheshireeast.gov.uk", "A")
        assertEquals(1, res.answer.size)
        assertEquals("150.171.109.101", res.answer.first())
        assertEquals(res.cnameChain.size,3)
        assertEquals(res.lastCname, "mr-afd-azuredge.tm-azurefd.net")
        assertFalse(res.adFlag)
    }


    //CNAME + Aufgeteilter TXT-Record -> Bestanden
    @Test
    fun testTXTRecordMultipleStrings () {
        val mtaStSRecordOutput = File("C:\\Users\\jorel\\Desktop\\8. Sem BA\\Codes\\UnitTestDigTestfiles\\multiTXTStrings").readText(Charsets.UTF_8)

        val res = parseDigOutput(DigCmdResult(mtaStSRecordOutput, 0), "k2._domainkey.github.com", "TXT")
        assertEquals(1, res.answer.size)
        assertEquals("\"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2aC2KjGKLOwTweBY5A9RpjsxaBXR9r7OAU6U8/zn92ivImI75naUujWbItRI/QmL1jy5PWGqLwoUA0b90ObWaLDc+i9MtTNmGeWO009hr20fIxhGg6XBT2kjZ1DTThopSe1nAndsupmcBwlQ5Q6LJ+ZAxLcujnPIxM0ZBLmgpkv8u6RfY4eFP8OLvdAW3oSuB0DyLDigQX4Sj8wBO4YIdQH6AAmBeOsidsKAFNFUCpc3vCxtBDR12U+cBg724l3sBkMQ8evnz6idnqxq9QAVYh8k4kJ+RP+6cqTdy7LjIm8xY/bQNpQIpGUAuDo2DjLcCDun9DAI4Q/3z+Q0o9QuQIDAQAB;\"", res.answer.first())
        assertEquals(res.cnameChain.size,1)
        assertEquals(res.lastCname, "dkim2.mcsv.net")
        assertFalse(res.adFlag)
    }


    //CNAME + Aufgeteilter TXT-Record -> Bestanden
    @Test
    fun testTXTRecordsMultiple () {
        val mtaStSRecordOutput = File("C:\\Users\\jorel\\Desktop\\8. Sem BA\\Codes\\UnitTestDigTestfiles\\multiTXTRecords").readText(Charsets.UTF_8)

        val res = parseDigOutput(DigCmdResult(mtaStSRecordOutput, 0), "_dmarc.nuremberg.gov.uk", "TXT")
        assertEquals(2, res.answer.size)
        assertEquals("\"v=spf1 ?all\"", res.answer.first())
        assertEquals("\"v=DMARC1;p=reject;rua=mailto:govuk-rua@dmarc.service.gov.uk\"", res.answer.last())
        assertEquals(0,res.cnameChain.size)
        assertEquals(null, res.lastCname)
    }

}