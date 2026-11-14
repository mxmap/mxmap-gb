package commands

import dataClass.TLS.TLSDataCollector
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

abstract class TrustManagerDecorator(protected val delegate: X509TrustManager, protected val tlsTestData: TLSDataCollector) :
    X509TrustManager {



    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            // Führe nun die eigentliche Zertifikatsprüfung aus
        delegate.checkServerTrusted(chain, authType)

    }


    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String
    ) {
        delegate.checkClientTrusted(chain, authType)
    }

    override fun getAcceptedIssuers() =
        delegate.acceptedIssuers

}