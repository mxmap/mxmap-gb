package emailtest.dataClassEvaluator.forJSON

import kotlinx.serialization.Serializable

@Serializable
data class MXData(

    val domain: String,
    val mxRecord: String,
    val ipAddress: List<String>,
    val countryCode: String,
    val invalidRecord: Boolean,

    // Ermöglicht ein einfacheres Rausfiltern von Fehlerhaften Mailservern, wo der Fehler
    // nicht bei
    val connectionError: Boolean,


    // Ergebnisse bei dem "normalen" TLS-Verbindungsaufbau
    var errorType: String? ,
    var defaultTlsVersion: String? = null, // Nur 1.2. und 1.3. sind hier möglich
    var defaultCipherSuite: String? = null,
    val issuerCN: String?,
    val issuerOrgName: String?,
    val issuerCountry: String?,
    val distinctSanCount: Int?,
    val sanDnsMatch: Boolean?,
    val sanStrictIdentifierMatch : Boolean?,
    val validPeriod : Long?,
    val sigAlg: String?,
    val pubKeyAlg: String?,
    val pubKeyLen: Int?,



    // Fallback: gibt es zumindest für den Versionscheck ein gültiges Ergebnis
    // (Kein STARTTLS oder eine TLS-Version wird unterstützt)
    val validTlsVerResult: Boolean,

    //Bereits vorhanden TLS-Versionsprüfung: Übernommen aus DatabaseRow
    val hasNoStarttlsSupport: Boolean? = null,
    //val hasSslv2: Boolean? = null,
    //val hasSslv3: Boolean? = null,
    val hasTls1: Boolean? = null,
    val hasTls1_1: Boolean? = null,
    val hasTls1_2: Boolean? = null,
    //val hasTls1_3: Boolean? = null,
    val minVersion: String? = null,
    //val maxVersion: String? = null,

    // MTA-STS
    val hasMtaSts: Boolean,
    val hasValidMtaStsPolicy: Boolean,
    val mxInPolicy: Boolean,

    val hasDANEForMxOnly : Boolean,
    val hasValidDane : Boolean,
    val cnameTLSA : String?,

    // DNSSEC
    val MxDNSSECPubResolver: Boolean,
    val MxDNSSECLocResolver: Boolean,
    val MxDNSSECFullyValidated: Boolean,
    val MxDNSSECValidResult: Boolean,
    val MxDNNSECRCODE: String,
    val DNSSECerror: String?,

    // TLS 1.2. Ergebnisse
    val tls12Results: Map<String, String?>

)
