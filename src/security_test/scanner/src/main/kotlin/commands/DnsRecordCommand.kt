package commands

abstract class DnsRecordCommand(val domain: String) {

    protected fun splitDnsRecord(rawDnsRecord: String): List<String> {
        // 2. Strikt am Semikolon aufteilen
        val pairs = rawDnsRecord.split(";").map { it.trim() }

        // Letzte Zeile darf Leer sein (nach möglichem ;)
        if (pairs.isNotEmpty() && pairs.last().isEmpty()) {
            return pairs.dropLast(1)
        } else {
            return pairs
        }
    }

    protected fun checkDnsExtensionFields(key: String, value: String): Boolean {

        if (!key.matches(Regex("^[a-zA-Z0-9]{1}[a-zA-Z0-9_\\-.]{0,31}$")))
            return false

        if (!value.matches(Regex("^[\\x21-\\x3A\\x3C\\x3E-\\x7E]+$")))
            return false

        return true
    }
}