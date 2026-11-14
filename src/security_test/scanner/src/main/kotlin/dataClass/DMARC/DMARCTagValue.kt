package dataClass.DMARC

import kotlinx.serialization.Serializable

@Serializable
data class DMARCTagValue(val value: String, val explicit: Boolean)
