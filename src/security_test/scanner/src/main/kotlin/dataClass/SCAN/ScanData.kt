package dataClass.SCAN

import kotlinx.serialization.Serializable

@Serializable
data class ScanData(val domain: String, val mxRecord: String?,
                    val ipAddress: String?, val adFlagForMx: Boolean?,
                    val adFlagForA: Boolean?, val ipCountryCode: String? = null)


fun List<ScanData>.getAllCountryCodes(): List<String> { return map{it.ipCountryCode ?: ""}.distinct()
}