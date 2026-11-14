package commands

import dataClass.TLS.tlsRequirements
import dataClass.TLS.TLSDataCollector
import models.enums.TlsCertError
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets

class TlsSmtpCertCheck(hostname: String, ip: String? = null) : TLS(25, hostname, ip) {

    fun testSmtpTlsHandshake(tlsRequirements: tlsRequirements? = null, ignoreCertValidity:Boolean = false): TLSDataCollector? {
        var socket: Socket? = null
        try {
            // 1. IP bereinigen (nur erste IP nutzen)
            //val cleanIp = ip?.split(",")?.firstOrNull()?.trim()?.takeIf { it.isNotEmpty() }
            val targetHost = ip ?: hostname

            // 2. Expliziter Connect-Timeout )
            socket = Socket()
            socket.connect(InetSocketAddress(targetHost, 25), 30000)
            socket.soTimeout = 30000

            val input = socket.getInputStream()
            val output = socket.getOutputStream()

            // 3. Greeting lesen
            val greeting = readRawSmtpResponse(input)
            if (greeting == null || greeting.code !in 200..299) {
                closeSession(socket, output, input)
                val errText = greeting?.let { "${TlsCertError.SmtpErrorNoGreetingReply.stringText}(${it.code}): ${it.firstLine}" }
                    ?: TlsCertError.SmtpErrorNoGreetingReply.stringText
                return TLSDataCollector(hostname, ip, null, null, null, errText)
            }

            // 4. EHLO senden
            sendSmtpCommand(output, "EHLO de.mail-sicherheit-test.de")
            val ehloReply = readRawSmtpResponse(input)
            if (ehloReply == null || ehloReply.code !in 200..299) {
                closeSession(socket, output, input)
                return TLSDataCollector(hostname, ip, null, null, null, TlsCertError.SmtpErrorNoEHLO.stringText)
            }

            // 5. STARTTLS-Fähigkeit prüfen (case-insensitive)
            if (!ehloReply.fullText.contains("STARTTLS", ignoreCase = true)) {
                closeSession(socket, output, input)
                return TLSDataCollector(hostname, ip, null, null, null, TlsCertError.SmtpErrorNoSTARTTLSOffered.stringText)
            }

            // 6. STARTTLS anfordern
            sendSmtpCommand(output, "STARTTLS")
            val startTlsReply = readRawSmtpResponse(input)
            if (startTlsReply == null || startTlsReply.code != 220) {
                closeSession(socket, output, input )
                val errText = startTlsReply?.let { "${TlsCertError.SmtpErrorSTARTTLS.stringText}(${it.code}): ${it.firstLine}" }
                    ?: TlsCertError.SmtpErrorSTARTTLS.stringText
                return TLSDataCollector(hostname, ip, null, null, null, errText)
            }

            // 7. Handshake durchführen (Socket ist unbuffered und exakt synchron)
            return testTLS(socket, tlsRequirements, ignoreCertValidity)

        } catch (e: Exception) {
            runCatching { socket?.close() }
            val errorType = e::class.simpleName ?: "Exception"
            val msg = e.message?.let { ": $it" } ?: ""
            return TLSDataCollector(hostname, ip, null, null, null,
                "${TlsCertError.SocketVerbindungsfehler.stringText}:$errorType$msg")
        }
    }

    private fun sendSmtpCommand(output: OutputStream, command: String) {
        val bytes = (command + "\r\n").toByteArray(StandardCharsets.US_ASCII)
        output.write(bytes)
        output.flush()
    }

    private fun closeSession(socket: Socket, output: OutputStream, input: InputStream) {
        runCatching {
            sendSmtpCommand(output, "QUIT")
            // Verhindert TCP-RST: Kurz das "221 Bye" des Servers konsumieren
            input?.let {
                socket.soTimeout = 1000
                it.read(ByteArray(64))
            }
        }
        // Wird nun GARANTIERT immer ausgeführt:
        runCatching { socket.close() }
    }

    // Ungepufferter Zeilenleser: Verhindert Datenverlust vor dem TLS-Upgrade
    private fun readRawSmtpResponse(input: InputStream): SmtpResponse? {
        val rawLines = mutableListOf<String>()
        var line: String
        var reachedEof = false
        do {
            val sb = StringBuilder()
            while (true) {
                val b = input.read()
                if (b == -1) {
                    reachedEof = true
                    break
                }
                if (b == '\n'.code) break
                if (b != '\r'.code) sb.append(b.toChar())
            }
            line = sb.toString()
            if (line.isNotEmpty() || !reachedEof) {
                rawLines.add(line)
            }

            if (reachedEof) break

            // RFC 5321: Ende bei "250 OK" (Leerzeichen an Pos 4) oder 3-stelligem Code
            val isComplete = (line.length >= 4 && line[3] == ' ') ||
                    (line.length == 3 && line.all { it.isDigit() })
        } while (!isComplete)

        val first = rawLines.firstOrNull() ?: return null
        val code = first.take(3).toIntOrNull() ?: 0
        return SmtpResponse(code, first, rawLines.joinToString("\n"))
    }

    private data class SmtpResponse(val code: Int, val firstLine: String, val fullText: String)
}