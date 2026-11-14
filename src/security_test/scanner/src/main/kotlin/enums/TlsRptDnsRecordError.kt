package models.enums

enum class TlsRptDnsRecordError(val stringText: String) {
    // Leerer Dns-Record
    EmptyDnsRecord("EmptyDnsRecord"),
    // Kein key=value Format (= Fehlt)
    NoKeyValueFormat("NoKeyValueFormat"),

    NoDnsRecord("NoDnsRecord"),

    MultipleDnsRecords("MultipleDnsRecords"),

    // Kein gültiges Versionsfeld
    NoVersionField("NoVersionField"),
    // Versionsfeld ABNF-Konform, jedoch nicht gemäß Vorgabe
    VersionValueMatchesABNFOnly("VersionValueMatchesABNFOnly"),


    // Es kommt ein weiteres Versionsfehld vor mit ungültigem Wert
    InvalidAnotherVersionField("InvalidAnotherVersionField"),
    // Mindestens der Inhalt von Key oder Value ist fehlerhaft
    SyntaxErrorOtherField("SyntaxErrorOtherField"),


    // General Rua-Value Errors
    InvalidRuaValue("InvalidRuaValue"),
    // rua-Feld hat keinen Wert
    EmptyRuaValue("EmptyRuaValue"),
    // Dns-Eintrag enthält kein rua-Feld
    MissingRua("MissingRua"),

    // Leeres URI-Feld
    EmptyReportUri("EmptyReportUri"),
    // Nicht RFC-Konformes URI-Scheme
    InvalidUriScheme("InvalidUriScheme"),
    // Syntaktisch ungültige URI
    InvalidReportUri("InvalidReportUri"),

    // Fehler, der bei der Auswertung des rua-Werts aufgetreten ist
    GeneralRuaError("GeneralRuaError"),


    // Reporting Domain besitzt keine MX-Records
    ReportingDomainNoMXRecods("ReportingDomainNoMXRecods"),

    // Mx/Mailserver besitzt keine IP-Adressen/A-Records
    ReportingMXNoIPAddress("ReportingMXNoIPAddress"),

    // Mx/Mailserver besitzt keine IP-Adressen/A-Records
    ReportingHttpsNoIPAddress("ReportingHttpsNoIPAddress")

}