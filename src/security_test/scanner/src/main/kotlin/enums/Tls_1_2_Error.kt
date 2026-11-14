package enums

enum class Tls_1_2_Error(val stringText: String) {

    TooShortRSAKey("TooShortRSAKey"),
    WrongCertPubKey("WrongCertPubKey"),
    ECFieldLength("ECFieldLength")

}

enum class PubKeyAlgorithm(val stringText: String) {
    RSA("RSA"),
    ECDSA("EC")
}