package emailtest.dataClassScanData.TLS

import kotlinx.serialization.Serializable

@Serializable
data class TLSDataCollector(
    var domain: String,
    var ip: String? = null,
    var tlsServerCertificateInfo: emailtest.dataClassScanData.TLS.TLSServerCertificateInfo? = null,
    var tlsVersion: String? = null,
    var cipherSuite: String? = null,
    var errorType: String? = null
)