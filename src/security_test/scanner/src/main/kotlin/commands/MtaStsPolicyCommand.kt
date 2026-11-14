package commands

import Dig
import dataClass.MTASTS.MtaStsPolicy
import dataClass.MTASTS.MtaStsPolicyContent
import dataClass.MTASTS.MtaStsPolicyDnsEntry
import dataClass.MTASTS.MtaStsPolicyObject
import dataClass.MTASTS.MtaStsPolicyRetrieval
import dataClass.TLS.TLSDataCollector
import models.enums.MtaStsGeneralPolicyErrorType
import models.enums.MtaStsPolicyError
import models.enums.MtaStsPolicyRetrievalError
import models.enums.TlsCertError
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

class MtaStsPolicyCommand(private val domain: String) {


    /*
    fun run(timeout: Int): MtaStsResult {

        // return
    }
*/


    // Rufe über HTTPS die MTA-STS-Policy ab, Prüfe auf Fehler und gib sie als Ergebnis zurück
    public fun retrievePolicy(): MtaStsPolicyRetrieval {

        try {


            // Baue den Sender für die Abfragen
            val client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build()


            // Baue die GET-Anfrage selbst
            val request = HttpRequest.newBuilder()
                .uri(URI.create("https://mta-sts.${domain}/.well-known/mta-sts.txt"))
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build()

            // InputStream wegen möglichen DoS-Angriffen mit großem HTTP-Bodyinhalt
            val response = client.send(request, HttpResponse.BodyHandlers.ofInputStream())

            // Lade jetzt erst die begrenzte Zahl an Body-Bytes herunter (gegen DoS)
            // use-Block für automatisches schließen im Fehlerfall, readNBytes macht dies nicht
            val rawData = response.body().use {
                    stream -> stream.readNBytes(65540)
            }
            val policyAsString = rawData.toString(Charsets.UTF_8)


            //Response-Code muss 200 sein (RFC)
            if (response.statusCode() != 200)  {
                return MtaStsPolicyRetrieval(
                    false, MtaStsPolicyRetrievalError.HTTPResponseCode.stringText,
                    null, null
                )
            }

            // Finde den ersten Content-Type
            val contentType = response.headers()
                .firstValue("Content-Type")
                .orElse("")


            // Soft-Fail: Speichere die Policy dennoch ab
            // Zähle die Bytes 64 * 1024
            if(rawData.size  > 65536) {
                return MtaStsPolicyRetrieval(
                    true, MtaStsPolicyRetrievalError.PolicySizeTooLarge.stringText,
                    null, policyAsString
                )
            }

            // Gemäß RFC, mimecast erwähnt jedoch, dass in der Praxis andere Content-Types genutzt werden
            if (!contentType.lowercase().contains("text/plain")) {
                return MtaStsPolicyRetrieval(
                    true, MtaStsPolicyRetrievalError.ContentTypeNotTextPlain.stringText,
                    null, policyAsString
                )
            }

            // Erfolgsfall
            return MtaStsPolicyRetrieval(true, null, null, policyAsString)

        } catch (e: Exception) {



            val errorType = e::class.simpleName ?: "UnbekannteException"

            val errorMessage = if (e.message.isNullOrBlank()) {
                errorType // Wenn keine Message da ist, nur den Typ ausgeben
            } else {
                "$errorType: ${e.message}" // Ansonsten Typ und Message
            }


            return MtaStsPolicyRetrieval(
                false,
                MtaStsPolicyRetrievalError.GeneralRetrievalError.stringText, errorMessage, null
            )
        }

    }

    // Vor dem Policy-Abruf, baue eine TLS-Verbindung auf zum Webserver
    public fun testTLSHandshake(): TLSDataCollector? {
            val tlsCheck = TlsHttpCertCheck("mta-sts.$domain")
            return tlsCheck.testHttpsTlsHandshake()
    }

    //  Ist für die sts-domain eine IP-Adresse angegeben?
    public fun discoverPolicyARecord(): MtaStsPolicyDnsEntry {

        val discoveryDomain = "mta-sts.$domain"
        val digResult = Dig.dig(discoveryDomain, "A")

        if(digResult.answer.isEmpty()) {
            return MtaStsPolicyDnsEntry(false, null, false, null, null)
        }

        // Gebe der einfachheit halber nur die letzte Domainadresse zurück
        return MtaStsPolicyDnsEntry(
            true, digResult.answer.first(),
            digResult.cnameChain.isNotEmpty(),
            digResult.cnameChain.lastOrNull(),
            digResult.adFlag
        )
    }

    public fun setCCForPolicyIP(entry: MtaStsPolicyDnsEntry) {

        if(entry.hasARecord) {
            val ccResult = Dig.getCCForIP(entry.ip)
            entry.ipCountryCode = ccResult
        }
    }


    // Prüfe die Syntax der übergebenen MTA-STS-Policy
    public fun validatePolicy(rawPolicy: String?): MtaStsPolicyContent {

            // Leere Policy übergeben?
            if(rawPolicy.isNullOrEmpty()) {
                return createParsedPolicyError(rawPolicy , MtaStsPolicyError.EmptyPolicy)
            }

            // Pattern nach RFC 5321
            val mxPattern = Regex("^(\\*\\.)?([a-zA-Z0-9]([a-zA-Z0-9\\-]*[a-zA-Z0-9])?)(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]*[a-zA-Z0-9])?)*$")
            val mxList = mutableListOf<String>()

            // Text an Zeilenumbrüchen spalten (CRLF oder LF gemäß Grammatik!) -> Limitation: Hier auch CR
            val linesRaw = rawPolicy.lines()

            // Grammatik erlaubt ein CRLF/ LF am Ende der letzten Zeile -> Das sorgt für ein leeres letztes Zeilenelement
            val lines =  if (linesRaw.isNotEmpty() && linesRaw.last().isEmpty()) {
                linesRaw.dropLast(1)
            } else {
                linesRaw
            }




            val tokens = mutableMapOf<String, String>()

            for (line in lines) {

                // Berücksichtige für das weitere Vorgehen andere Felder mit einem möglichen ":" im Value
                val parts = line.split(":",limit = 2)

                // Prüfe auf leere Key-Value Felder oder nicht vorhandene Key/Value-Paare, auch leere Zeilen sind nicht
                // Teil der Grammatik
                if (parts.size < 2) {

                    return createParsedPolicyError(rawPolicy , MtaStsPolicyError.SyntaxErrorKeyValueFormat)

                }else {

                    if(parts.any { it.isEmpty() })
                        return createParsedPolicyError(rawPolicy , MtaStsPolicyError.SyntaxErrorKeyValueFormat)

                }

                // Um den Key erlaubt die ABNF keine Leerzeichen
                val key = parts[0]
                // In der ABNF erlaubter Whitespace vor und nach dem Value wird entfernt
                val value = parts[1].trim()

                // Sonderfall mx-Feld
                if(key == "mx" ) {

                    if(!value.matches(mxPattern)) {
                        return createParsedPolicyError(rawPolicy , MtaStsPolicyError.SyntaxErrorInvalidMxPattern)
                    }
                    mxList.add(value)
                    continue
                }

                // Berücksichtige bei Feldern, die einmal vorkommen sollen, nur den ersten Eintrag
                if (!tokens.containsKey(key)) {
                    tokens[key] = value

                    // Syntaxprüfung der Kernfelder
                    when (key) {
                        "version" -> {
                            if (value != "STSv1")
                                return createParsedPolicyError(rawPolicy , MtaStsPolicyError.SyntaxErrorInvalidVersion)
                        }
                        "mode" -> {
                            if(value != "testing" && value != "enforce" && value != "none")
                                return createParsedPolicyError(rawPolicy , MtaStsPolicyError.SyntaxErrorInvalidMode)
                        }
                        "max_age" -> {
                            if(!value.matches(Regex("^[0-9]{1,10}$")))
                                return createParsedPolicyError(rawPolicy , MtaStsPolicyError.SyntaxErrorInvalidMaxAge)

                            // MAX-Wert gemäß RFC
                            if(value.toLong() > 31557600)
                                return createParsedPolicyError(rawPolicy , MtaStsPolicyError.SyntaxErrorTooLongMaxAge)
                        }
                        else -> {
                            val otherFieldCheck = validatePolicyOtherFields(rawPolicy, key, value)
                            if(otherFieldCheck != null)  {
                                return createParsedPolicyError(rawPolicy , otherFieldCheck)
                            }
                        }
                    }

                }else {

                    // Weiteres Feld nach Grammatik auswerten
                    val otherFieldCheck = validatePolicyOtherFields(rawPolicy, key, value)
                    if(otherFieldCheck != null)  {
                        return createParsedPolicyError(rawPolicy , otherFieldCheck)
                    }

                }

            }

            // Prüfe auf das verpflichtende Vorhandensein bestimmter Felder
            // RFC Validierung der Pflichtfelder
            if (tokens["version"] == null)
                return createParsedPolicyError(rawPolicy , MtaStsPolicyError.SyntaxErrorNoVersion)

            if(tokens["mode"] == null)
                return createParsedPolicyError(rawPolicy , MtaStsPolicyError.SyntaxErrorNoMode)

            if(tokens["max_age"] == null)
                return createParsedPolicyError(rawPolicy , MtaStsPolicyError.SyntaxErrorNoMaxAge)

            // Mindestens ein MX-Pattern-Feld verlangt, wenn die Policy nicht auf "none" steht
            if(mxList.isEmpty() && tokens["mode"] != "none") {
                return createParsedPolicyError(rawPolicy , MtaStsPolicyError.SyntaxErrorNoMxPattern)
            }

        return createParsedPolicyValid(rawPolicy, mxList, tokens["mode"], tokens["max_age"])
    }


    private fun createParsedPolicyError(rawPolicy : String? ,error: MtaStsPolicyError ): MtaStsPolicyContent {
        return MtaStsPolicyContent(rawPolicy, error.stringText, null)
    }


    private fun createParsedPolicyValid(rawPolicy : String, mxList: List<String>, mode: String?, max_age: String?): MtaStsPolicyContent {
        val policyData = MtaStsPolicyObject(max_age, mode, mxList)
        return MtaStsPolicyContent(rawPolicy, null, policyData)
    }


    private fun validatePolicyOtherFields(rawPolicy: String, key: String, value: String): MtaStsPolicyError? {
        // Soll ignoriert werden -> Synatxprüfung nach sonstigem Feld
        if(!key.matches(Regex("^[a-zA-Z0-9][a-zA-Z0-9._\\-]{0,31}$")))
            return MtaStsPolicyError.SyntaxErrorOtherFields

        // Der Einfachheit folgende Annahme: Die Policy hat eine gültige UTF-8 Kodierung
        // Limitation: Erkennt keine Leerzeichen am Ende der Zeile
        if(!value.matches(Regex("^[^\\x00-\\x20\\x7F]([^\\x00-\\x1F\\x7F]*[^\\x00-\\x20\\x7F])?$")))
            return MtaStsPolicyError.SyntaxErrorOtherFields

        return null
    }


    // Erstelle ein vollumfängliches Ergebnisobjekt auf Basis der vorherigen Messungen
    public fun createPolicyObject(dnsEntry: MtaStsPolicyDnsEntry, tlsTest: TLSDataCollector?,
                                  retrieval: MtaStsPolicyRetrieval?, content: MtaStsPolicyContent?  ): MtaStsPolicy {

        var generalErrorType : MtaStsGeneralPolicyErrorType? = null
        if(!dnsEntry.hasARecord) {
                generalErrorType = MtaStsGeneralPolicyErrorType.policydnsLookupError

        }else if(tlsTest?.errorType != null && tlsTest?.errorType!!.startsWith(TlsCertError.SocketVerbindungsfehler.stringText)) {
            generalErrorType = MtaStsGeneralPolicyErrorType.policyTcpError

        }else if(tlsTest?.errorType != null) {
            generalErrorType = MtaStsGeneralPolicyErrorType.policyTlsError

        }else if(retrieval?.errorType != null) {
            generalErrorType = MtaStsGeneralPolicyErrorType.policyRetrievalError

        }else if(content?.errorType != null) {
            generalErrorType = MtaStsGeneralPolicyErrorType.policySyntaxError
        }

        var hasValidMtaSts =  generalErrorType == null

        return MtaStsPolicy(
            domain, hasValidMtaSts, generalErrorType, dnsEntry,
            tlsTest, retrieval, content
        )

    }
}

