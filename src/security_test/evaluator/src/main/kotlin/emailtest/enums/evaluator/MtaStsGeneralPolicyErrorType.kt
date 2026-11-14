package emailtest.enums.evaluator

enum class MtaStsGeneralPolicyErrorType {

    missingEntry,

    dnsRecordSyntaxError,

    policydnsLookupError,

    //Uberarbeiten in Scanner
    policyTcpError,
    policyTlsError,


    policyRetrievalError,
    policySyntaxError,

    policyAllMtaInvalid,
    policyAtLeastOneMtaInvalid,

    // Für errorMeldungen
    policyMtaNoValidTls,
    policyMtaNotInPolicy

}