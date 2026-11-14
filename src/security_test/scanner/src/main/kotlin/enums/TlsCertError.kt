package models.enums

enum class TlsCertError(val stringText: String)  {
    // Generelle TLS-Fehlermeldungen
    ExpiredCertificate("ExpiredCertificate"),
    SANMismatch("SANMismatch"),

    // Kategorie für: Zertifikat fehlt in der empfangenen Zertifikatskette,
    // Selbssigniertes Zertifikat, unvertrauenswürdige CA
    RootCAUntrusted("RootCAUntrusted"),
    UnsupportedProtocolVersion("UnsupportedProtocolVersion"),

    // Socket Verbindungsfehler
    SocketVerbindungsfehler("SocketVerbindungsfehler"),

    // SMTP STARTTLS Fehler
    SmtpErrorNoGreetingReply("SmtpErrorNoGreetingReply"),
    SmtpErrorNoEHLO("SmtpErrorNoEHLO"),
    SmtpErrorNoSTARTTLSOffered("SmtpErrorNoSTARTTLSOffered"),
    SmtpErrorSTARTTLS("SmtpErrorSTARTTLS");

}