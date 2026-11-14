package enums

enum class DKIMClassification(val stringText: String) {
    PossibleDKIM("PossibleDKIM"),
    Wildcard("Wildcard"),
    NoDKIM("NoDKIM"),
    OtherError("OtherError")

}