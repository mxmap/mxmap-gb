package dataClass.DKIM

import kotlinx.serialization.Serializable

@Serializable
data class DKIMResult(val domain: String, val result: String,
                      val domainKeyDomain: String, val otherDomain: String?) {
}