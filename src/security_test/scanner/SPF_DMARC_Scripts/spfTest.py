
from checkdmarc import spf
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from dataclasses_json import dataclass_json
import argparse

@dataclass_json
@dataclass
class MechanismCount:
    a: int = 0
    mx: int = 0
    ptr: int = 0
    ip4: int = 0
    ip6: int = 0
    include: int = 0
    exists: int = 0

@dataclass_json
@dataclass
class IncludeData:
    domain: str
    dnsLookups: int
    record: str
    voidDnsLookups: int
    mCount: MechanismCount

@dataclass_json
@dataclass
class RedirectData:
    domain: str
    dnsLookups: int
    record: str 
    voidDnsLookups: int
    mCount: MechanismCount

@dataclass_json
@dataclass
class spfGeneralData:
    valid: bool
    record: str | None
    errorType: str | None
    warnings: List[str]
    lengthWarning: bool
    oldSPFRecordWarning: bool
    dnsLookups: int | None
    voidDnsLookups: int | None
    allQualifier: str | None
    mCount: MechanismCount
    redirectCount: int | None

@dataclass_json
@dataclass
class SPFResult:
    domain: str
    spf_General_Data: spfGeneralData
    includeData: List[IncludeData] = field(default_factory=list)
    redirectData: List[RedirectData] = field(default_factory=list)

# Die Parsing-Logik für Mechanismen (ohne redirect)
def count_mechanisms(mechanisms_list: List[Dict[str, Any]]) -> MechanismCount:
    counts = MechanismCount()
    for mech in mechanisms_list:
        m_type = mech.get("mechanism", "").lower()

        #besitzt Aufzählungsliste Attribute mit Namen "m_type"
        if hasattr(counts, m_type):
            # Setze den Wert des Attributs um 1 höher
            setattr(counts, m_type, getattr(counts, m_type) + 1)

    return counts


def parse_checkdmarc_spf(domain: str, data: Dict[str, Any]) -> SPFResult:
 
    parsed_record = data.get("parsed") or {}
    
    mechanisms = parsed_record.get("mechanisms", []) or []
    # Mechanismen auf Top-Level zählen
    main_mech_count = count_mechanisms(mechanisms)

    warnings = data.get("warnings") or []
    warnings_str = " ".join(warnings).lower()
    # Warnungen, die laut Sourcecode ausgegeben werden, werden als Indikator genommen
    length_warning = "RFC 7208 § 3.4 recommends keeping answers under ~450 bytes" in warnings_str 
    old_spf_warning = "SPF type DNS records found" in warnings_str

    # All-Qualifier (z.B. "-all" erfassen)
    all_qualifier = parsed_record.get("all")

    # 3. Direkte Includes parsen (SPFIncludeMechanism)
    includes_list = []
    for mech in mechanisms:
        if mech.get("mechanism") == "include":

            #Vermeidung von Absturz
            incl_parsed = mech.get("parsed") or {}
            incl_mechanisms = incl_parsed.get("mechanisms", [])
            
            includes_list.append(IncludeData(
                domain=mech.get("value", ""),  # Bei Includes steht die Domain in 'value' (s. Sourcecode SPFMechanism)
                dnsLookups=mech.get("dns_lookups", -1),
                record=mech.get("record") or "",
                voidDnsLookups=mech.get("void_dns_lookups", -1),
                mCount=count_mechanisms(incl_mechanisms)
            ))

    # 4. Redirects verarbeiten (SPFRedirect)
    redirects_list = []
    current_redirect = parsed_record.get("redirect")
    redirect_count = 0
    # Hat der Haupt-Record einen Redirect? Dann Counter auf 1 setzen.
    if current_redirect:
       redirect_count = 1

    # Schleife durchläuft jeden Redirect in der Kette
    while current_redirect:
        red_parsed = current_redirect.get("parsed") or {}
        red_mechanisms = red_parsed.get("mechanisms", [])
        
        # Mechanismen für den spezifischen Redirect zählen
        red_mech_count = count_mechanisms(red_mechanisms)
        
        # Gibt es noch einen weiteren Redirect in der Kette
        next_redirect = red_parsed.get("redirect")
        if next_redirect:
            redirect_count = 1 + redirect_count 
            
        # Diesen Redirect zur Liste hinzufügen
        redirects_list.append(RedirectData(
            domain=current_redirect.get("domain", "none"),
            dnsLookups=current_redirect.get("dns_lookups", -1),
            record=current_redirect.get("record") or "none",
            voidDnsLookups=current_redirect.get("void_dns_lookups", -1),
            mCount=red_mech_count
        ))
        
        # Zeiger auf den nächsten Redirect setzen 
        current_redirect = next_redirect

    spf_General_Data = spfGeneralData (
        valid=data.get("valid", False),
        record=data.get("record"),
        errorType=data.get("error"),
        warnings=warnings,
        lengthWarning=length_warning,
        oldSPFRecordWarning=old_spf_warning,
        dnsLookups=data.get("dns_lookups"),
        voidDnsLookups=data.get("void_dns_lookups"),
        allQualifier=all_qualifier,
        mCount=main_mech_count,
        redirectCount = redirect_count,
    )

    return SPFResult(
        domain=domain,
        spf_General_Data=spf_General_Data,
        includeData=includes_list,
        redirectData=redirects_list
    )







"""Copyright 2019-2025 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
---------------------------------------------------------------------------
MODIFICATION NOTICE (gemäß Apache 2.0 Abschnitt 4b):
This file was modified by Joris Butschko on 10.08.2026 for the 
Bachelor thesis "Analyse der Umsetzung von E-Mail-Sicherheitsstandards und externer Anbieterabhängigkeiten 
bei Kommunen in Großbritannien im Vergleich zu Deutschland".

Changes made: ToDo
- added value of second error arguments  
- removed ignore_too_many_lookups=false lookup param for spf.parse_spf_record
->throw limit specific errors
---------------------------------------------------------------------------

"""
# Für Testzwecke leicht angepasste Version von der spf.check_spf(domain) Bibliotheksfunktion
# Die Implementierung basiert vollständig
# Gib bei DNS-Fehlern auch die Domain (arg[1]) mit aus
# Zudem: Wirf Fehler bzgl. Lookup-Limits
def modified_check_spf(domain: str, nameserver: list[str]):
        spf_results = {
            "record": None,
            "valid": True,
            "dns_lookups": None,
            "void_dns_lookups": None,
        }
        try:
            #Edit Parameterübergabe angepasst
            spf_query = spf.query_spf_record(
                domain,
                #quoted_txt_segments=True,
                nameservers=nameserver
            )
            #Edit Ende
            spf_results["record"] = spf_query["record"]
            spf_results["warnings"] = spf_query["warnings"]

            #Edit Parameterübergabe angepasst
            parsed_spf = spf.parse_spf_record(
                spf_results["record"],
                domain,
                nameservers=nameserver
            )
            #Edit Ende
    
            spf_results["dns_lookups"] = parsed_spf["dns_lookups"]
            spf_results["void_dns_lookups"] = parsed_spf["void_dns_lookups"]
    
            if "error" in parsed_spf:
                spf_results["valid"] = False
                spf_results["error"] = parsed_spf["error"]
    
            spf_results["parsed"] = parsed_spf["parsed"]
            spf_results["warnings"] += parsed_spf["warnings"]
    
        except spf.SPFError as error:
            spf_results["error"] = ""

            # Edit (gib wenn vorhanden auch das zweite Argument des Fehlers aus 
            # ( ist z.B. die Domain)):
            args_laenge = len(error.args)
            if args_laenge >= 2:
                # Es gibt mindestens 2 Argumente im Fehler (z.B. Domain not found)
                spf_results["error"] = f"{error.args[0]} {error.args[1]}"
            elif args_laenge == 1:
                # Es gibt genau 1 Argument
                spf_results["error"] = str(error.args[0])
            else:
                # Das Tuple ist leer
                spf_results["error"] = "Keine Fehlerausgabe"

            #Edit Ende 
                   
            spf_results["valid"] = False
            if hasattr(error, "data") and error.data:
                for key in error.data:
                    spf_results[key] = error.data[key]
    
        return spf_results


def teste_spf():

    # zum Aufruf über die Konsole
    parser = argparse.ArgumentParser(description="SPF-Testskript (Checkdmarc)")
    parser.add_argument("domain", help="Die Domain, für die SPF geprüft wird")
    parser.add_argument("nameserver", help='Adresse des Resolvers für die DNS-Abfragen')
    args = parser.parse_args()

    # Resolver der für die Anfrage genutzt wird
    nameserver_as_list = [args.nameserver]
    try:

        # get_spf_record() holt und validiert den SPF-Eintrag
        spf_result = modified_check_spf(args.domain, nameserver_as_list)
        
        # 1. Das Resultat einheitlich ausgeben
        filtered_result = parse_checkdmarc_spf(args.domain, spf_result)

        
        # 2. Ausgabe des gefilterten Dictionaries als sauberes JSON
        print(filtered_result.to_json(indent=2))
        
    except Exception as e:
        print(f"Fehler bei der Validierung: {e}")

# Beispielaufruf
if __name__ == "__main__":
    teste_spf()

