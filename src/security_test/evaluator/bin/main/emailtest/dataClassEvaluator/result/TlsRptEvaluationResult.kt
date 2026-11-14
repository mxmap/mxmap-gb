package emailtest.dataClassEvaluator.result

import emailtest.dataClassEvaluator.forJSON.DataTransport.TlsRptData
import emailtest.dataClassEvaluator.forJSON.externalDependency

data class TlsRptEvaluationResult(val tlsRptData: TlsRptData, val reportingAdresses: List<externalDependency>)