package commands

import dataClass.TLS.tlsRequirements
import dataClass.TLS.TLSDataCollector
import models.enums.TlsCertError
import java.net.Socket

class TlsHttpCertCheck( hostname: String, ip: String? = null, port: Int = 443 ): TLS( port, hostname, ip) {


    public fun testHttpsTlsHandshake(tlsRequirements: tlsRequirements? = null): TLSDataCollector? {
        var socket: Socket? = null // TCP Socket aufbauen
        try {
            val usedHostname = ip ?: hostname

            // TCP Socket aufbauen
            socket = Socket(usedHostname, 443)
            socket?.soTimeout = 40000

            return testTLS(socket, tlsRequirements)



        } catch (e: Exception) {
            if(socket != null && !socket.isClosed()) {
                runCatching {
                    socket?.close()
                }
            }

            // Den Namen der Exception-Klasse holen
            val errorType = e::class.simpleName ?: "UnbekannteException"

            // Einen sinnvollen Fehlertext zusammenbauen
            val errorMessage = if (e.message.isNullOrBlank()) {
                errorType // Wenn keine Message da ist, nur den Typ ausgeben
            } else {
                "$errorType: ${e.message}"
            }

            return TLSDataCollector(hostname, ip, null, null,
                null, "${TlsCertError.SocketVerbindungsfehler.stringText}: $errorMessage")

        }

    }
}