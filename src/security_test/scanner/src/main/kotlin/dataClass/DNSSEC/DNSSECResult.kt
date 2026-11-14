package dataClass.DNSSEC

import kotlinx.serialization.Serializable

@Serializable
data class DNSSECResult(

    val domain: String,
    val resolver: String,
    val type: String,
    val validAnswer: Boolean,
    val hasADFlag: Boolean,
    val hasADFlagPubResolver: Boolean,
    val RCODE: String,
    val errorLog: String?
)
