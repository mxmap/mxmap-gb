package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.DMARC

data class DMARCMeasurementResult(val dmarcResults: List<DMARCPolicy>, val externalDomains: List<String>)
