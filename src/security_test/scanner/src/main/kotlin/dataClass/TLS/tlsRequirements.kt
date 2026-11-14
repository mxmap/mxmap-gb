package dataClass.TLS

data class tlsRequirements(val version: String, val cipherSuite: String? = null,
                           val curvesData: Array<String>? = null, val signatureAlgorithms: Array<String>? = null)