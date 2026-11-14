package dataClass.DMARC

data class DMARCMeasurementResult(val dmarcResults: List<DMARCPolicy>, val externalDomains: List<String>)
