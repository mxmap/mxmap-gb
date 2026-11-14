package enums

enum class DMARCError(val stringText: String) {

    MutlipleRecords("MutlipleRecords"),
    SyntaxError("SyntaxError"),
    NotValidatedExternalReporting("NotValidatedExternalReporting"),
    DMARCAtMainDomainLocation("DMARCAtMainDomainLocation"),
    ReportingDomainNoMXRecods("ReportingDomainNoMXRecods"),
    ReportingMXNoIPAddress("ReportingMXNoIPAddress")
}