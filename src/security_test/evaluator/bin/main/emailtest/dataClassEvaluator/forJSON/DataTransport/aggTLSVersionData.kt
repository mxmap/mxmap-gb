package emailtest.dataClassEvaluator.forJSON.DataTransport

import emailtest.models.TlsVersion
import kotlinx.serialization.Serializable

@Serializable
data class aggTLSVersionData(

    val atLeastOneValidTlsResult: Boolean,
    val allValidTlsResult: Boolean,

    //Bereits vorhanden TLS-Versionsprüfung: Übernommen aus DatabaseRow
    val hasNoStarttlsSupport: Boolean? = null,
    //val hasSslv2AtLeastOneMta: Boolean? = null,
    //val hasSslv3AtLeastOneMta: Boolean? = null,
    val hasTls1AtLeastOneMta: Boolean? = null,
    val hasTls1_1AtLeastOneMta: Boolean? = null,
    val hasTls1_2AtLeastOneMta: Boolean? = null,
    //val hasTls1_3AtLeastOneMta: Boolean? = null,

    val minVersionAtLeastOneMta: String? = null,
    //val maxVersionAtLeastOneMta: String? = null,
    //val minVersionAllMta: String? = null,
    //val maxVersionAllMta: String? = null,

)