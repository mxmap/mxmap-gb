package models.enums

enum class MtaStsPolicyRetrievalError(val stringText: String) {
    None("None"),
    HTTPResponseCode("HTTPResponseCode"),
    ContentTypeNotTextPlain("ContentTypeNotTextPlain"),
    PolicySizeTooLarge("PolicySizeTooLarge"),
    GeneralRetrievalError("GeneralRetrievalError")
}