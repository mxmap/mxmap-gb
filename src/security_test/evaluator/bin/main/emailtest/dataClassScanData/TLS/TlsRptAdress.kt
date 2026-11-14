package emailtest.dataClassScanData.TLS

import kotlinx.serialization.Serializable
import java.util.Collections

@Serializable
data class TlsRptAdress(var schemeMailto: Boolean,
                        var schemeHttps: Boolean,
                        val hostname: String,
                        var ccData: MutableList<String> = Collections.emptyList()
) {
    val getHostname: String get() = hostname
}