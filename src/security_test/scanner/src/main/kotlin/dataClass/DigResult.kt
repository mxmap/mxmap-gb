package models.dataClass

data class DigResult(val answer: List<String>,
                     val cnameChain: List<String>,
                     val adFlag: Boolean) {
    val hasCname: Boolean get() = cnameChain.isNotEmpty()
    val lastCname: String? get() = cnameChain.lastOrNull()

    val hasAnswer: Boolean get() = answer.isNotEmpty()
    val getFirstAnswer: String? get() = answer.firstOrNull()



    val hasMultipleAnswers: Boolean get() = answer.size > 1

    // Abfrage ob genau ein Ergebnis Bedingung erfüllt ohne Objektkopie zu erstellen
    fun singleResultOrNull(predicate: (String) -> Boolean): String? {
        return answer.singleOrNull(predicate)
    }

    // Neues DigResult-Objekt mit gefilterten Ergebnissen (z.b. für DMARC, SPF-Tags)
    fun filterAnswers(predicate: (String) -> Boolean): DigResult {
        return this.copy(answer = this.answer.filter(predicate))
    }

}