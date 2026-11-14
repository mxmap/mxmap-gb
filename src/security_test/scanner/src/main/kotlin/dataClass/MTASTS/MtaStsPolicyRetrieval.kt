package dataClass.MTASTS

import kotlinx.serialization.Serializable

@Serializable
data class MtaStsPolicyRetrieval(val hasPolicy: Boolean,
                                 val errorType: String?,
                                 val errorMessage: String?,
                                 val rawPolicy: String?)