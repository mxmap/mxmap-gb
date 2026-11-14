package emailtest.dataClassEvaluator.result

import emailtest.dataClassEvaluator.forJSON.externalDependency
import emailtest.dataClassEvaluator.forJSON.MtaStsErrorEntry
import emailtest.dataClassEvaluator.forJSON.DataTransport.aggDomainDataTransport

data class aggDomainDataTransportResult(
    val aggDomainDataTransport: aggDomainDataTransport,
    val mtaStsErrorList: List<MtaStsErrorEntry>,
    val externalDependencyList: List<externalDependency>
    )