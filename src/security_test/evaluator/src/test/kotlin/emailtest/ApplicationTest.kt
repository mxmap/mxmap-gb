package emailtest

import com.google.common.net.InternetDomainName
import org.junit.Test

class ApplicationTest {

    @Test
    fun test() {
        println("ApplicationTest")
    }
    // Organizational Domain mit PublicSuffix ermitteln <letztes Label vor Public-Suffix>.<Public-Suffix>
    fun determineOrganizationalDomain(targetDomain: String): String {
        var orgDomainOld : String = ""
        val domainName = InternetDomainName.from(targetDomain.lowercase())
        val publicSuffix = domainName.publicSuffix()

        if(publicSuffix != null) {
            val labelList = domainName.parts()
            val domainLabelCount = labelList.size
            val publicSuffixCount = publicSuffix.parts().size
            // Nur das erste Domainlabel vor dem public Suffix berücksichtigen und vorne anhängen
            if(domainLabelCount > publicSuffixCount) {
                orgDomainOld = labelList.drop(domainLabelCount - publicSuffixCount - 1).joinToString(".")
            }
        }

        return orgDomainOld.lowercase()
    }

    @Test
    fun test2() {

        println(determineOrganizationalDomain("spf.mailjet.com"))
        println(determineOrganizationalDomain("dllee.cc"))
    }
}