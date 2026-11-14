package emailtest.dataClassEvaluator.forJSON.DataTransport

import kotlinx.serialization.Serializable

@Serializable
data class aggDomainDataTransport(
    val domain: String,
    val aggDataTransportMetadata: aggDataTransportMetadata,
    val tlsCertData: aggTlsCertData? = null,
    val tlsVersionData: aggTLSVersionData? = null,
    val tls12Result: aggTls12Result? = null,
    val mtaStsData: MtaStsData? = null,
    val tlsRptData: TlsRptData? = null,
    val dnssecResult: aggDNSSECResultDataTransport? = null,
    val daneResult: aggDaneResult? = null
)