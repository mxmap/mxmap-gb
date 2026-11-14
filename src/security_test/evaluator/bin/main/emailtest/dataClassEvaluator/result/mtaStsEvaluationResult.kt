package emailtest.dataClassEvaluator.result

import emailtest.dataClassEvaluator.forJSON.DataTransport.MtaStsData
import emailtest.dataClassEvaluator.forJSON.MtaStsErrorEntry
import emailtest.dataClassEvaluator.forJSON.externalDependency

data class mtaStsEvaluationResult(val mtaStsData: MtaStsData,
                                  val mtaStsErrorList: List<MtaStsErrorEntry>? = null,
                                  val cnameDependency: List<externalDependency>? = null )