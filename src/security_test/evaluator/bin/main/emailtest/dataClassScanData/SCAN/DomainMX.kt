package emailtest.dataClassScanData.SCAN

data class DomainMX(val domain: String, val mxRecord: String?, val adFlagForMx: Boolean?, val adFlagForDNSSECCheck: Boolean)