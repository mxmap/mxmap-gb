package enums

enum class DigAnswerStatus(val stringText: String) {

    NOERROR("NOERROR"),
    NXDOMAIN("NXDOMAIN"),

    // Wenn kein Header aus Dig-Inhalt rauszulesen ist
    NOHEADER("NOHEADER"),
    SERVFAIL("SERVFAIL"),
    NOERRORandADFlag("NOERRORandADFlag"),


}
