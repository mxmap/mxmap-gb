package emailtest.dataClassEvaluator.forJSON

import emailtest.dataClassEvaluator.forJSON.DataTransport.aggregatedCertificateData
import kotlinx.serialization.Serializable

@Serializable
data class aggregatedTlsCertData(

    var certData: aggregatedCertificateData? = null,
    var tlsVersion: String? = null,
    var cipherSuite: String? = null,
    var errorType: String? = null
)