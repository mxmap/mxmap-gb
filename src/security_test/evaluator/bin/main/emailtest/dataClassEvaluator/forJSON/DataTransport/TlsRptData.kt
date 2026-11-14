package emailtest.dataClassEvaluator.forJSON.DataTransport

import kotlinx.serialization.Serializable

@Serializable
data class TlsRptData(val hasTlsrptDnsRecord: Boolean,
                      val rawRecord: String?,
                      var lastCname: String?,
                      val errorType: String?,
    val distinctRepotingDomains: Int? = null,
    val reportingOverHTTPS: Int? = null,
    val reportingOverMAILTO: Int? = null,

    // Wie viele Adressen enthalten nicht die Subdomain
    val distinctExternalDomains: Int? = null,
    val externalOverHTTPS: Int? = null,
    val externalOverMAILTO: Int? = null
    )