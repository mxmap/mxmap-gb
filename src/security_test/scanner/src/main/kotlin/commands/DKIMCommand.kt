package commands

import com.google.common.util.concurrent.RateLimiter
import dataClass.DKIM.DKIMResult
import enums.DKIMClassification
import enums.DigAnswerStatus

class DKIMCommand (private val domain: String ) {



    public fun testDKIM(rateLimiter: RateLimiter): DKIMResult {
        rateLimiter.acquire()

        // DNS-Abfrage an _domainkey-Subdomain
        val resultDomainkey = Dig.digAnswer("_domainkey.$domain")


        // Kein DKIM erkannt
        if (resultDomainkey == DigAnswerStatus.NXDOMAIN.stringText) {

            return DKIMResult(domain, DKIMClassification.NoDKIM.stringText, resultDomainkey, null)
        }

        // Sonstiger Fehler
        if(resultDomainkey != DigAnswerStatus.NOERROR.stringText && resultDomainkey != DigAnswerStatus.NOERRORandADFlag.stringText) {
            return DKIMResult(domain, DKIMClassification.OtherError.stringText, resultDomainkey, null)
        }

        rateLimiter.acquire()


        //Prüfe zur Kontrolle den RCODE einer weiteren Subdomain
        val resultOther = Dig.digAnswer("nxdomain-test-domainkkey.$domain")

        // Entscheide nun ob die erste Antwort aussagekräfig ist oder nicht
        if(resultOther == DigAnswerStatus.NOERROR.stringText || resultOther == DigAnswerStatus.NOERRORandADFlag.stringText) {

            return DKIMResult(domain, DKIMClassification.Wildcard.stringText, resultDomainkey, resultOther)

        }else if ( resultOther == DigAnswerStatus.NXDOMAIN.stringText) {

            return DKIMResult(domain, DKIMClassification.PossibleDKIM.stringText, resultDomainkey, resultOther)

        }

        return DKIMResult(domain, DKIMClassification.OtherError.stringText, resultDomainkey, resultOther)

    }

}