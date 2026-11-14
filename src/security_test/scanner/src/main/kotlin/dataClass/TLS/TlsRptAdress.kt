package dataClass.TLS

import kotlinx.serialization.Serializable
import java.util.Collections.emptyList

@Serializable
data class TlsRptAdress(var schemeMailto: Boolean,
                        var schemeHttps: Boolean,
                        val hostname: String,
                        var ccData: MutableList<String> = emptyList()) {
    val getHostname: String get() = hostname
}