package commands

import dataClass.SPF.SPFResult
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import Config

public class SPFCommand(val domain: String) {

    // Ruft externes Python-Skript auf, dass die Syntax des SPF-DNS-Records validiert und den Record geparst zurückgibt
    suspend fun testSPF(): SPFResult? {

        try {

            //
            val pb = ProcessBuilder(
                "python3",
                "/app/SPF_DMARC_Scripts/spfTest.py",
                domain,
                Config["DNS_NAMESERVER"]
            )

            pb.redirectErrorStream(true) // Fehler von Python in den normalen Output leiten

            val process = pb.start()

            // stdout und stderr getrennt einlesen
            val output = process.inputStream.bufferedReader().use { it.readText() }
            val stderr = process.errorStream.bufferedReader().use { it.readText() }
            val exitCode = process.waitFor()

            if (stderr.isNotBlank()) {
                // Warnings oder Fehler separat loggen, ohne das JSON zu zerstören
                System.err.println("Python Stderr ($domain): $stderr")
            }

            val spfResult = Json.decodeFromString<SPFResult>(output.trim())


           // val output = process.inputStream.bufferedReader().use { it.readText() }
           // val exitCode = process.waitFor()
           // print(output)

           // val spfResult = Json.decodeFromString<SPFResult>(output)


            return spfResult

        } catch (e: Exception) {
            println("Es gab einen Fehler: ${e.message}")
            return null
        }
}



}