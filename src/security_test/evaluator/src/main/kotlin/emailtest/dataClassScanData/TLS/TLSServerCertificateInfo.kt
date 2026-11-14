package emailtest.dataClassScanData.TLS

import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable

@Serializable
data class TLSServerCertificateInfo(val issuerCommonName: String?,
                                    val issuerOrganisationName: String?,
                                    val issuerCountry: String?,

                                    val subjectCommonName: String?,
                                    val sanList: List<String>?,
                                    val sanDnsMatch : Boolean,
                                    val sanStrictIdentifierMatch : Boolean,

                                    val validFrom: Instant,
                                    val validUntil: Instant,
                                    val validPeriod : Long,

                                    val signatureAlgorithm: String?,
                                    val publicKeyAlgorithm: String?,
                                    val publicKeyLength: Int?,

                                    )