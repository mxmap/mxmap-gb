package models.enums

enum class MtaStsPolicyError(val stringText: String) {
    EmptyPolicy("EmptyPolicy"),
    // Mindestens eine Zeile erfüllt das generelle Key:Value-Format nicht
    SyntaxErrorKeyValueFormat("SyntaxErrorKeyValueFormat"),

    SyntaxErrorNoVersion("SyntaxErrorNoVersion"),
    SyntaxErrorInvalidVersion( "SyntaxErrorInvalidVersion"),

    SyntaxErrorNoMode( "SyntaxErrorNoMode"),
    SyntaxErrorInvalidMode( "SyntaxErrorInvalidMode"),

    SyntaxErrorNoMaxAge( "SyntaxErrorNoMaxAge"),
    SyntaxErrorInvalidMaxAge( "SyntaxErrorInvalidMaxAge"),
    SyntaxErrorTooLongMaxAge( "SyntaxErrorTooLongMaxAge"),

    SyntaxErrorNoMxPattern("SyntaxErrorNoMxPattern"),
    SyntaxErrorInvalidMxPattern("SyntaxErrorInvalidMxPattern"),

    // Felder die nicht für die Auswertung relevant sind und nicht syntaktisch korrekt sind
    SyntaxErrorOtherFields("SyntaxErrorOtherFields")

}