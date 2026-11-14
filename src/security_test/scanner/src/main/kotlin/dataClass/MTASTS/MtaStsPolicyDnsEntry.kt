package dataClass.MTASTS

import kotlinx.serialization.Serializable

@Serializable
data class MtaStsPolicyDnsEntry(val hasARecord: Boolean,
                                val ip: String?,
                                val hasCname: Boolean,
                                val lastCNAME: String?,
                                val hasADFlag: Boolean? = null,
                                var ipCountryCode: String? = null)