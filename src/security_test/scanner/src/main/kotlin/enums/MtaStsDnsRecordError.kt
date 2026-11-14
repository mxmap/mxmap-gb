package models.enums

enum class MtaStsDnsRecordError(val stringText: String) {
    // Leerer Dns-Record
    EmptyDnsRecord("EmptyDnsRecord"),

    // Kein gültiges key=value Format (Das '='-Zeichen fehlt)
    NoKeyValueFormat("NoKeyValueFormat"),

    MultipleDnsRecords("MultipleDnsRecords"),

    // Kein gültiges Versionsfeld
    NoVersionField("NoVersionField"),

    // Versionsfeld ABNF-Konform, jedoch nicht gemäß Vorgabe
    VersionValueMatchesABNFOnly("VersionValueMatchesABNFOnly"),

    // Mindestens der Inhalt von Key oder Value ist fehlerhaft
    SyntaxErrorOtherField("SyntaxErrorOtherField"),

    // ID-Feld ist nicht im DNS-Eintrag hinterlegt
    NoIDField("NoIDField"),

    // Wert des ID-Felds ist ungültig
    InvalidIDField("InvalidIDField"),
}