package dataClass.DMARC

import models.dataClass.DigResult

data class TreeWalkResult(
    val cachedTreeWalkPolicyResults: MutableMap<String,DigResult>,
    val psdDomain: String?
)
