package dataClass.DMARC

import kotlinx.serialization.Serializable

@Serializable
data class dmarcGeneralData(
    val hasPolicy: Boolean,
    val hasADFlag: Boolean? = null,

    // Informationen über mögliche Fehler
    var errorType: String? = null,
    var errorMessage: String? = null,

    // In Schritt 1 DNS-Spezifische Felder
    val rawPolicyOld: String? = null,
    val oldOrgDomain: String? = null,
    val policyLocationDomain: String? = null,
    val policyLocation: String? = null,
    val cnameRecord: String? = null,

    var policyMode: String? = null,

    // RFC spezifische Änderungen 9989: Wichtig für Alignment
    // und Policy Discovery, wenn davon abhängig
    var newOrgDomain: String? = null,
    var newRawDMARCPolicy: String? = null, // Vereinfacht: Ohne genaue Syntaxprüfung

)
