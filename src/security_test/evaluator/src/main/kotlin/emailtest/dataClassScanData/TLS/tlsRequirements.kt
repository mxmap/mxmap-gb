package emailtest.dataClassScanData.TLS

data class tlsRequirements(val version: String, val cipherSuite: String, val curvesData: Array<String>)