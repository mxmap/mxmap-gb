package commands

import com.google.common.util.concurrent.RateLimiter
import dataClass.DNSSEC.DNSSECResult
import enums.DigAnswerStatus

class DNSSECCommand(val domain: String, val adFlagOtherResolver: Boolean) {

    suspend fun testDNSSEC(rateLimiter: RateLimiter,type : String, resolver: String) : DNSSECResult {

        rateLimiter.acquire(1)
        val result = Dig.digAnswer(domain, type,resolver)

        when(result) {
            DigAnswerStatus.NOERRORandADFlag.stringText -> {
                return DNSSECResult(domain,resolver, type,true,true,adFlagOtherResolver,result,null)
            }

            DigAnswerStatus.NOERROR.stringText -> {
                return DNSSECResult(domain,resolver,type,true,false, adFlagOtherResolver,result,null)
            }

            DigAnswerStatus.SERVFAIL.stringText -> {

                //SERVFAIL könnte ein Indikator für einen DNSSEC-Fehler sein -> Prüfe mit delv-Ausgabe
                rateLimiter.acquire(1)
                val resultDelv = Delv.delv(domain,type,resolver)
                return DNSSECResult(domain,resolver,type,false,false, adFlagOtherResolver, result,resultDelv)
            }

            else -> {
                return DNSSECResult(domain,resolver,type,false,false, adFlagOtherResolver, result,null)
            }

        }




    }


}