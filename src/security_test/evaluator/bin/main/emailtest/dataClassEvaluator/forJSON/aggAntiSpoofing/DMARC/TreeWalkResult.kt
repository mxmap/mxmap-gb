package emailtest.dataClassEvaluator.forJSON.aggAntiSpoofing.DMARC

import models.dataClass.DigResult

data class TreeWalkResult(
    val cachedTreeWalkPolicyResults: MutableMap<String,DigResult>,
    val psdDomain: String?
)
