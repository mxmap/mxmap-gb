"""DMARC record validation"""

from __future__ import annotations

import logging
import re
from typing import Literal, TypedDict

import pyleri

import json
import argparse


SYNTAX_ERROR_MARKER = "->"

WSP_REGEX = r"[ \t]"


"""Copyright 2019-2023 Sean Whalen

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
This file was modified by Joris Butschko on 07.08.2026 for the 
Bachelor thesis "Analyse der Umsetzung von E-Mail-Sicherheitsstandards und externer Anbieterabhängigkeiten 
bei Kommunen in Großbritannien im Vergleich zu Deutschland".

Changes made:
- readded removed syntax check for old dmarc tags
- readded execptions for missing p-Tag and wrong position
- ignore unkown tags
- modified result-object 
---------------------------------------------------------------------------

"""

logger = logging.getLogger(__name__)

DMARC_VERSION_REGEX_STRING = rf"v{WSP_REGEX}*={WSP_REGEX}*DMARC1{WSP_REGEX}*;"
DMARC_TAG_VALUE_REGEX_STRING = (
    rf"([a-z]{{1,5}}){WSP_REGEX}*={WSP_REGEX}*([\w.:@/+!,_\- ]+)"
)

DMARC_TAG_VALUE_REGEX = re.compile(DMARC_TAG_VALUE_REGEX_STRING, re.IGNORECASE)


class _DMARCWarning(Exception):
    """Raised when a non-fatal DMARC error occurs"""


class _DMARCBestPracticeWarning(_DMARCWarning):
    """Raised when a DMARC record does not follow a best practice"""


class DMARCError(Exception):
    """Raised when a fatal DMARC error occurs"""

    def __init__(self, msg: str, data: DMARCErrorData | None = None):
        """
        Args:
            msg (str): The error message
            data (DMARCErrorData): A dictionary of data to include in the results
        """
        self.data = data
        Exception.__init__(self, msg)



class DMARCSyntaxError(DMARCError):
    """Raised when a DMARC syntax error is found"""

# Fehlerklasse für alten RFC wieder hinzugefügt
class DMARCPolicyTagWrongPosition(DMARCSyntaxError):
    """Raised when p-Tag is not the second key tag"""

class InvalidDMARCTag(DMARCSyntaxError):
    """Raised when an invalid DMARC tag is found"""

# Wurde (wieder) hinzugefügt, da nach altem RFC validiert wird:
class MissingDMARCPolicyTag(DMARCSyntaxError):
    """Raised when no policy tag is found"""

class InvalidDMARCTagValue(DMARCSyntaxError):
    """Raised when an invalid DMARC tag value is found"""


class DMARCRecordStartsWithWhitespace(DMARCSyntaxError):
    """Raised when DMARC record starts with whitespace"""


class InvalidDMARCReportURI(InvalidDMARCTagValue):
    """Raised when an invalid DMARC reporting URI is found"""



class DMARCRecordInWrongLocation(DMARCError):
    """Raised when a DMARC record is found at the root of a domain"""



class _DMARCGrammar(pyleri.Grammar):
    """Defines Pyleri grammar for DMARC records"""

    version_tag = pyleri.Regex(DMARC_VERSION_REGEX_STRING, re.IGNORECASE)
    tag_value = pyleri.Regex(DMARC_TAG_VALUE_REGEX_STRING, re.IGNORECASE)
    START = pyleri.Sequence(
        version_tag,
        pyleri.List(
            tag_value, delimiter=pyleri.Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"), opt=True
        ),
    )


class DMARCTagMapItem(TypedDict):
    name: str
    required: bool
    description: str


class DMARCTagMapItemWithDefault(DMARCTagMapItem):
    default: str | int


class DMARCTagMapItemWithValues(DMARCTagMapItem):
    values: dict[str, str | int]


class DMARCTagMapItemWithDefaultAndValues(DMARCTagMapItem):
    default: str | int
    values: dict[str, str | int]


class DMARCTagMap(TypedDict):
    adkim: DMARCTagMapItemWithDefault
    aspf: DMARCTagMapItemWithDefault
    fo: DMARCTagMapItemWithDefaultAndValues
    np: DMARCTagMapItemWithValues
    p: DMARCTagMapItemWithValues
    psd: DMARCTagMapItemWithDefaultAndValues
    rua: DMARCTagMapItem
    ruf: DMARCTagMapItem
    sp: DMARCTagMapItemWithValues
    t: DMARCTagMapItemWithDefaultAndValues
    v: DMARCTagMapItem


class DMARCTagDetails(TypedDict):
    name: str
    default: str | int | None
    description: str


class DMARCRecordQueryResults(TypedDict):
    record: str
    location: str
    warnings: list[str]





# TypedDicts for DMARC tag values
class DMARCTagValue(TypedDict):
    """Base structure for a DMARC tag value without descriptions"""

    value: str 
    explicit: bool


class _DMARCTagValueOptionalFields(TypedDict, total=False):
    """Optional fields for DMARC tag values with descriptions"""

    default: str | int


class DMARCTagValueWithDescription(DMARCTagValue, _DMARCTagValueOptionalFields):
    """Structure for a DMARC tag value with descriptions"""

    name: str
    description: str


# Type aliases for parsed tags dictionaries
DMARCParsedTags = dict[str, DMARCTagValue]
DMARCParsedTagsWithDescriptions = dict[str, DMARCTagValueWithDescription]





class ParsedDMARCRecordWithDescriptions(TypedDict):
    """Return type for parse_dmarc_record with descriptions"""

    tags: DMARCParsedTagsWithDescriptions
    warnings: list[str]


# Folgende Klassen sind relevant für die Ergebnisse

# Klassenformat für ein rua/ruf-Ergebnis
class ParsedDMARCReportURI(TypedDict):
    """Structure for a parsed DMARC report URI (rua/ruf)"""
    scheme: str
    address: str
    domain: str
    size_limit: str | None


# Zwei seperate Listen für die rua und ruf Ergebnisse mit eigenem Typ wurden hinzugefügt
class ParsedDMARCRecord(TypedDict):
    """Return type for parse_dmarc_record without descriptions"""

    tags: dict[str, DMARCTagValue]

    ruaURIList: list[ParsedDMARCReportURI] | None
    rufURIList: list[ParsedDMARCReportURI] | None

    warnings: list[str]


# Einheitliches Objekt mit ggf. Nullable Werten, damit das parsen in Kotlin einfacher fällt
class DMARCResults(TypedDict):
    """Success return type for check_dmarc"""
    record: str
    valid: bool
    error: str | None
    tags: dict[str, DMARCTagValue] | None
    ruaURIList: list[ParsedDMARCReportURI] | None
    rufURIList: list[ParsedDMARCReportURI] | None


class _DMARCErrorResultsOptionalFields(TypedDict, total=False):
    """Optional fields for DMARCErrorResults"""

    target: str


class DMARCErrorResults(_DMARCErrorResultsOptionalFields):
    """Error return type for check_dmarc"""

    record: str | None
    location: str | None
    valid: Literal[False]
    error: str | None


class DMARCErrorData(TypedDict, total=False):
    """Optional data structure for DMARCError"""

    target: str


version_tag = pyleri.Regex(DMARC_VERSION_REGEX_STRING, re.IGNORECASE)
tag_value = pyleri.Regex(DMARC_TAG_VALUE_REGEX_STRING, re.IGNORECASE)
START = pyleri.Sequence(
    version_tag,
    pyleri.List(
        tag_value, delimiter=pyleri.Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"), opt=True
    ),
)


dmarc_tags: DMARCTagMap = {
    "adkim": {
        "name": "DKIM Alignment Mode",
        "required": False,
        "default": "r",
        "description": (
            "In relaxed mode, "
            "the Organizational "
            "Domains of both the "
            "DKIM-authenticated "
            "signing domain (taken "
            "from the value of the "
            '"d=" tag in the '
            "signature) and that "
            "of the RFC 5322 "
            "From domain "
            "must be equal if the "
            "identifiers are to be "
            "considered aligned."
        ),
    },
    "aspf": {
        "name": "SPF alignment mode",
        "required": False,
        "default": "r",
        "description": (
            "In relaxed mode, "
            "the SPF-authenticated "
            "domain and RFC 5322 "
            "From domain must have "
            "the same "
            "Organizational Domain. "
            "In strict mode, only "
            "an exact DNS domain "
            "match is considered to "
            "produce Identifier "
            "Alignment."
        ),
    },
    "fo": {
        "name": "Failure Reporting Options",
        "required": False,
        "default": "0",
        "description": (
            "Provides requested "
            "options for generation "
            "of failure reports. "
            "Report generators MAY "
            "choose to adhere to the "
            "requested options. "
            "This tag's content "
            "MUST be ignored if "
            'a "ruf" tag (below) is '
            "not also specified. "
            "The value of this tag is "
            "a colon-separated list "
            "of characters that "
            "indicate failure "
            "reporting options."
        ),
        "values": {
            "0": (
                "Generate a DMARC failure "
                "report if all underlying "
                "authentication mechanisms "
                "fail to produce an aligned "
                '"pass" result.'
            ),
            "1": (
                "Generate a DMARC failure "
                "report if any underlying "
                "authentication mechanism "
                "produced something other "
                "than an aligned "
                '"pass" result.'
            ),
            "d": (
                "Generate a DKIM failure "
                "report if the message had "
                "a signature that failed "
                "evaluation, regardless of "
                "its alignment. DKIM-"
                "specific reporting is "
                "described in AFRF-DKIM."
            ),
            "s": (
                "Generate an SPF failure "
                "report if the message "
                "failed SPF evaluation, "
                "regardless of its alignment. "
                "SPF-specific reporting is "
                "described in AFRF-SPF"
            ),
        },
    },
    "np": {
        "name": "Non-existent Subdomain Policy",
        "required": False,
        "description": (
            "Indicates the policy to "
            "be enacted by the "
            "Receiver at the request "
            "of the Domain Owner for "
            "non-existent subdomains "
            "of the domain queried. "
            "Its syntax is identical "
            'to that of the "p" tag. '
            "If absent, the policy "
            'specified by the "sp" tag '
            "(if present) or the "
            '"p" tag MUST be applied '
            "for non-existent subdomains."
        ),
        "values": {
            "none": (
                "The Domain Owner requests "
                "no specific action be "
                "taken regarding delivery "
                "of messages."
            ),
            "quarantine": (
                "The Domain Owner "
                "wishes to have "
                "email that fails "
                "the DMARC mechanism "
                "check be treated by "
                "Mail Receivers as "
                "suspicious."
            ),
            "reject": (
                "The Domain Owner wishes "
                "for Mail Receivers to "
                "reject email that fails "
                "the DMARC mechanism check. "
                "Rejection SHOULD occur "
                "during the SMTP "
                "transaction."
            ),
        },
    },
    "p": {
        "name": "Requested Mail Receiver Policy",
        "required": True, # Im alten RFC noch Pflicht
        "description": (
            "Specifies the policy to "
            "be enacted by the "
            "Receiver at the "
            "request of the "
            "Domain Owner. The "
            "policy applies to "
            "the domain and to its "
            "subdomains, unless "
            "subdomain policy "
            "is explicitly described "
            'using the "sp" tag.'
        ),
        "values": {
            "none": (
                "The Domain Owner requests "
                "no specific action be "
                "taken regarding delivery "
                "of messages."
            ),
            "quarantine": (
                "The Domain Owner "
                "wishes to have "
                "email that fails "
                "the DMARC mechanism "
                "check be treated by "
                "Mail Receivers as "
                "suspicious. "
                "Depending on the "
                "capabilities of the "
                "MailReceiver, "
                'this can mean "place into spam folder", '
                '"scrutinize with additional intensity", '
                'and/or "flag as suspicious".'
            ),
            "reject": (
                "The Domain Owner wishes "
                "for Mail Receivers to "
                "reject email that fails "
                "the DMARC mechanism check. "
                "Rejection SHOULD occur "
                "during the SMTP "
                "transaction."
            ),
        },
    },
    "pct": {
        "name": "Percentage",
        "required": False,
        "default": "100",
        "description": (
            "Integer percentage of "
            "messages from the "
            "Domain Owner's "
            "mail stream to which "
            "the DMARC policy is to "
            "be applied. "
            "However, this "
            "MUST NOT be applied to "
            "the DMARC-generated "
            "reports, all of which "
            "must be sent and "
            "received unhindered. "
            "The purpose of the "
            '"pct" tag is to allow '
            "Domain Owners to enact "
            "a slow rollout of "
            "enforcement of the "
            "DMARC mechanism. "
            "Removed in DMARCbis."
        ),
    },
    "psd": {
        "name": "PSD Flag",
        "required": False,
        "default": "u",
        "description": (
            "A flag indicating whether the domain is a Public Suffix Domain (PSD)."
        ),
        "values": {
            "y": (
                "The domain is a PSD. "
                "This tag is included "
                "by PSOs to indicate "
                "that the domain is a "
                "Public Suffix Domain."
            ),
            "n": (
                "The DMARC Policy Record "
                "is published for a domain "
                "that is not a PSD, but it "
                "is the Organizational "
                "Domain for itself and "
                "its subdomains."
            ),
            "u": (
                "The default indicates "
                "that the DMARC Policy "
                "Record is published for "
                "a domain that is not a "
                "PSD, and may or may not "
                "be an Organizational "
                "Domain for itself and "
                "its subdomains."
            ),
        },
    },
    "rf": {
        "name": "Report Format",
        "required": False,
        "default": "afrf",
        "description": (
            "A list separated by "
            "colons of one or more "
            "report formats as "
            "requested by the "
            "Domain Owner to be "
            "used when a message "
            "fails both SPF and DKIM "
            "tests to report details "
            "of the individual "
            'failure. Only "afrf" '
            "(the auth-failure report "
            "type) is currently "
            "supported in the "
            "DMARC standard. "
            "Removed in DMARCbis."
        ),
        "values": {
            "afrf": (
                '"Authentication Failure '
                "Reporting Using the "
                'Abuse Reporting Format", '
                "RFC 6591, April 2012, "
                "<https://www.rfc-editor.org/info/rfc6591>"
            ),
        },
    },
    "ri": {
        "name": "Report Interval",
        "required": False,
        "default": "86400",
        "description": (
            "Indicates a request to "
            "Receivers to generate "
            "aggregate reports "
            "separated by no more "
            "than the requested "
            "number of seconds. "
            "DMARC implementations "
            "MUST be able to provide "
            "daily reports and "
            "SHOULD be able to "
            "provide hourly reports "
            "when requested. "
            "However, anything other "
            "than a daily report is "
            "understood to be "
            "accommodated on a "
            "best-effort basis. "
            "Removed in DMARCbis."
        ),
    },
    "rua": {
        "name": "Aggregate Feedback Addresses",
        "required": False,
        "description": (
            "A comma-separated list "
            "of DMARC URIs to which "
            "aggregate feedback "
            "is to be sent."
        ),
    },
    "ruf": {
        "name": "Forensic Feedback Addresses",
        "required": False,
        "description": (
            "A comma-separated list "
            "of DMARC URIs to which "
            "forensic feedback "
            "is to be sent."
        ),
    },
    "sp": {
        "name": "Subdomain Policy",
        "required": False,
        "description": (
            "Indicates the policy to "
            "be enacted by the "
            "Receiver at the request "
            "of the Domain Owner. "
            "It applies only to "
            "subdomains of the "
            "domain queried, and not "
            "to the domain itself. "
            "Its syntax is identical "
            'to that of the "p" tag '
            "defined above. If "
            "absent, the policy "
            'specified by the "p" '
            "tag MUST be applied "
            "for subdomains."
        ),
        "values": {
            "none": (
                "The Domain Owner requests "
                "no specific action be "
                "taken regarding delivery "
                "of messages."
            ),
            "quarantine": (
                "The Domain Owner "
                "wishes to have "
                "email that fails "
                "the DMARC mechanism "
                "check be treated by "
                "Mail Receivers as "
                "suspicious. "
                "Depending on the "
                "capabilities of the "
                "MailReceiver, "
                'this can mean "place into spam folder", '
                '"scrutinize with additional intensity", '
                'and/or "flag as suspicious".'
            ),
            "reject": (
                "The Domain Owner wishes "
                "for Mail Receivers to "
                "reject email that fails "
                "the DMARC mechanism check. "
                "Rejection SHOULD occur "
                "during the SMTP "
                "transaction."
            ),
        },
    },
    "t": {
        "name": "DMARC Policy Test Mode",
        "required": False,
        "default": "n",
        "description": (
            "Signals whether or not "
            "the Domain Owner wishes "
            "the Domain Owner Assessment "
            "Policy declared in the "
            '"p", "sp", and/or "np" tags '
            "to actually be applied. "
            "This tag does not affect "
            "the generation of DMARC "
            "reports, and it has no "
            "effect on any policy that "
            'is "none".'
        ),
        "values": {
            "y": (
                "A request that the actor "
                "performing the DMARC "
                "validation check not "
                "apply the policy, but "
                "instead apply any special "
                "handling rules it might "
                "have in place. The Domain "
                "Owner is currently testing "
                "its specified DMARC "
                "assessment policy."
            ),
            "n": (
                "The default is a request "
                "to apply the Domain Owner "
                "Assessment Policy as "
                "specified to any message "
                "that produces a DMARC "
                '"fail" result.'
            ),
        },
    },
    "v": {
        "name": "Version",
        "required": True,
        "description": (
            "Identifies the record "
            "retrieved as a DMARC "
            "record. It MUST have the "
            'value of "DMARC1". The '
            "value of this tag MUST "
            "match precisely; if it "
            "does not or it is absent, "
            "the entire retrieved "
            "record MUST be ignored. "
            "It MUST be the first "
            "tag in the list."
        ),
    },
}




def get_dmarc_tag_description(
    tag: str, value: str | list[str] | None = None
) -> DMARCTagDetails:
    """
    Get the name, default value, and description for a DMARC tag, amd/or a
    description for a tag value

    Args:
        tag (str): A DMARC tag
        value: An optional value

    Returns:
        dict: a ``dict`` with the following keys:
                     - ``name`` - the tag name
                     - ``default``- the tag's default value
                     - ``description`` - A description of the tag or value
    """
    name = dmarc_tags[tag]["name"]
    description = dmarc_tags[tag]["description"]
    default = None
    allowed_values = {}
    if "default" in dmarc_tags[tag]:
        default = dmarc_tags[tag]["default"]
    if "values" in dmarc_tags[tag]:
        allowed_values = dmarc_tags[tag]["values"]
    if type(value) is str and value in allowed_values:
        description = allowed_values[value]
    elif type(value) is list and len(allowed_values):
        new_description = ""
        for sub_value in value:
            if sub_value in allowed_values:
                value_description = allowed_values[sub_value]
                new_description += f"{sub_value}: {value_description}\n\n"
        new_description = new_description.strip()
        if new_description != "":
            description = new_description

    return {"name": name, "default": default, "description": description}


def parse_dmarc_report_uri(uri: str) -> ParsedDMARCReportURI:
    """
    Parses a DMARC Reporting (i.e. ``rua``/``ruf``) URI

    .. note::
        ``mailto`` is the only reporting URI scheme supported in DMARC1

    Args:
        uri: A DMARC URI

    Returns:
        dict: a ``dict`` of the URI's components:
                    - ``scheme``
                    - ``address``
                    - ``size_limit``
    Raises:
        :exc:`checkdmarc.dmarc.InvalidDMARCReportURI`

    """
    uri = uri.strip()

    #hinzugefügt aus anderer Klasse
    MAILTO_REGEX_STRING = (
    r"^(mailto):([\w\-!#$%&'*+-/=?^_`{|}~]"
    r"[\w\-.!#$%&'*+-/=?^_`{|}~]*@[\w\-.]+)(!\w+)?")

    MAILTO_REGEX = re.compile(MAILTO_REGEX_STRING, re.IGNORECASE)
    # ende

    mailto_matches = MAILTO_REGEX.findall(uri)
    if len(mailto_matches) != 1:
        raise InvalidDMARCReportURI(
            f"{uri} is not a valid DMARC report URI"
            + (
                ""
                if uri.startswith("mailto:")
                else (
                    " - please make sure that the URI begins with "
                    "a schema such as mailto:"
                )
            )
        )
    match = mailto_matches[0]
    scheme = match[0].lower()
    email_address = match[1]

    #Neu: Speichere die Domain ab
    email_domain = email_address.split("@")[-1]

    size_limit = match[2].lstrip("!")
    if size_limit == "":
        size_limit = None

    #Neu: Speicherung der Domain
    return {"scheme": scheme, "address": email_address, "domain": email_domain, "size_limit": size_limit}





def parse_dmarc_record(
    record: str,
    domain: str,
    *,
    include_tag_descriptions: bool = False,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
) -> ParsedDMARCRecord | ParsedDMARCRecordWithDescriptions:
    """
    Parses a DMARC record

    Args:
        record (str): A DMARC record
        domain (str): The domain where the record is found
        parked (bool): Indicates if a domain is parked
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        ignore_unrelated_records (bool): Ignore unrelated TXT records
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors
        syntax_error_marker (str): The maker for pointing out syntax errors

    Returns:
        dict: a ``dict`` with the following keys:
         - ``tags`` - a ``dict`` of DMARC tags

           - ``value`` - The DMARC tag value
           - ``explicit`` - ``bool``: A value is explicitly set
           - ``default`` - The tag's default value
           - ``description`` - A description of the tag/value

         - ``warnings`` - A ``list`` of warnings

         .. note::
            ``default`` and ``description`` are only included if
            ``include_tag_descriptions`` is set to ``True``

    Raises:
        :exc:`checkdmarc.dmarc.DMARCSyntaxError`
        :exc:`checkdmarc.dmarc.InvalidDMARCTag`
        :exc:`checkdmarc.dmarc.InvalidDMARCTagValue`
        :exc:`checkdmarc.dmarc.InvalidDMARCReportURI`
        :exc:`checkdmarc.dmarc.UnverifiedDMARCURIDestination`
        :exc:`checkdmarc.dmarc.UnrelatedTXTRecordFoundAtDMARC`
        :exc:`checkdmarc.dmarc.DMARCReportEmailAddressMissingMXRecords`

    """
    logger.debug(f"Parsing the DMARC record for {domain}")
    spf_in_dmarc_error_msg = (
        "Found a SPF record where a DMARC record "
        "should be; most likely, the _dmarc "
        "subdomain record does not actually exist, "
        "and the request for TXT records was "
        "redirected to the base domain."
    )


    warnings = []
    record = record.strip('"')
    dmarc_syntax_checker = _DMARCGrammar()
    parsed_record = dmarc_syntax_checker.parse(record)
    if not parsed_record.is_valid:
        expecting = [str(x).strip('"') for x in list(parsed_record.expecting)]
        marked_record = (
            record[: parsed_record.pos]
            + syntax_error_marker
            + record[parsed_record.pos :]
        )
        expecting = " or ".join(expecting)
        raise DMARCSyntaxError(
            f"Error: Expected {expecting} at position "
            f"{parsed_record.pos} "
            f"(marked with {syntax_error_marker}) in: "
            f"{marked_record}"
        )

    # Find explicit tags
    pairs: list[tuple[str, str]] = DMARC_TAG_VALUE_REGEX.findall(record)
    tags = {}

    # Tags defined in RFC 7489 but removed in RFC 9989. We still recognize
    # them for backward compatibility (pre-9989 readers may parse them)
    # Edit: Prüfe weiterhin die Syntax dieser Tags
    removed_tags = ("pct", "rf", "ri")

    seen_tags: list[str] = []
    duplicate_tags: list[str] = []
    for pair in pairs:
        tag = pair[0].lower()
        # RFC 9989: Unknown tags MUST be ignored. Removed-in-9989 tags
        # (pct/rf/ri) get their own warning below.
        if tag not in dmarc_tags:
            warnings.append(
                f"Unknown DMARC tag '{tag}' was ignored "
                "(RFC 9989 requires unknown tags to be ignored -> Edit: Auch RFC 7489)."
            )
            continue
        # Check for duplicate tags
        if tag in seen_tags:
            if tag not in duplicate_tags:
                duplicate_tags.append(tag)
        else:
            seen_tags.append(tag)
        if len(duplicate_tags):
            duplicate_tags_str = ",".join(duplicate_tags)
            raise InvalidDMARCTag(
                f"Duplicate {duplicate_tags_str} tags are not permitted"
            )
        if tag in removed_tags:
            warnings.append(f"Support for the {tag} tag was removed in RFC 9989")

        value = pair[1].lower().strip()
        tags[tag] = {"value": value, "explicit": True}

    # Include implicit tags and their defaults
    for tag in dmarc_tags:
        if tag not in tags and "default" in dmarc_tags[tag]:
            tags[tag] = {"value": dmarc_tags[tag]["default"], "explicit": False}

    # Edit: Behalte es bei auf das Vorhandensein des p-Tags zu prüfen
    if "p" not in tags:
        raise MissingDMARCPolicyTag (f"p Tag is missing")
             

    tags["p"]["value"] = tags["p"]["value"].lower()
    if "sp" not in tags:
        tags["sp"] = {"value": tags["p"]["value"], "explicit": False}
    # Normalize sp value for validation consistency (mirrors p behavior)
    tags["sp"]["value"] = tags["sp"]["value"].lower()
    if "np" not in tags:
        if tags["sp"]["explicit"]:
            tags["np"] = {"value": tags["sp"]["value"], "explicit": False}
        else:
            tags["np"] = {"value": tags["p"]["value"], "explicit": False}
    tags["np"]["value"] = tags["np"]["value"].lower()
    # RFC 9989 only requires that the v tag come first; the p tag may appear
    # in any position. Older readers (pre-9989 implementations of RFC 7489)
    # may still expect p immediately after v, so warn when it isn't there.
    if tags["p"]["explicit"] and list(tags.keys())[1] != "p":
        raise DMARCPolicyTagWrongPosition("The p tag does not immediately follow the v tag")

    tags["v"]["value"] = tags["v"]["value"].upper()

    # Validate tag values
    for tag in tags:
        tag_value = tags[tag]["value"]
        allowed_values = []
        explicit = tags[tag]["explicit"]
        if "values" in dmarc_tags[tag]:
            allowed_values = dmarc_tags[tag]["values"]
        if tag == "p" and tag_value == "none":
            warnings.append(
                f"A p tag value of none makes DMARC unenforced on email sent as {domain}."
            )
        if tag == "sp" and tag_value == "none" and explicit:
            warnings.append(
                f"An sp tag value of none makes DMARC unenforced on email sent as a subdomain of {domain}."
            )
        if tag == "fo":
            tag_value = tag_value.split(":")
            if "0" in tag_value and "1" in tag_value:
                warnings.append(
                    "When 1 is present in the fo tag, including in the fo tag 0 is redundant."
                )
            for value in tag_value:
                if value not in allowed_values:
                    raise InvalidDMARCTagValue(
                        f"{value} is not a valid option for the DMARC fo tag."
                    )
        # Edit: Alte Tags werden weiterhin validiert
        elif tag == "rf":
            tag_value = tag_value.lower().split(":")
            for value in tag_value:
                if value not in allowed_values:
                    raise InvalidDMARCTagValue(
                        f"{value} is not a valid option for the DMARC rf tag."
                    )
        elif allowed_values and tag_value not in allowed_values:
            allowed_values_str = ",".join(allowed_values)
            raise InvalidDMARCTagValue(
                f"Tag {tag} must have one of the following values: "
                f"{allowed_values_str} - not {tags[tag]['value']}"
            )

    # Edit: Alte Tags wieder hinzufügen pct, ri
    try:
        tags["pct"]["value"] = int(tags["pct"]["value"])
    except ValueError:
        raise InvalidDMARCTagValue("The value of the pct tag must be an integer.")

    try:
        #Edit: Einheitlicher Typ String für deserialisierung
        test = int(tags["ri"]["value"])
    except ValueError:
        raise InvalidDMARCTagValue("The value of the ri tag must be an integer.")
    #Ende

    # Edit: mache ein Seperate Liste für formartierte rua und ruf Ergebnisse
    parsed_rua_list = []
    if "rua" in tags:
        uris = tags["rua"]["value"].split(",")
        for uri in uris:
            try:
                uri = parse_dmarc_report_uri(uri)
                parsed_rua_list.append(uri)
                email_address = uri["address"]
                if uri["size_limit"]:
                    warnings.append(
                        "The size limit (`!size`) on rua URI for "
                        f"{email_address} is obsolete in RFC 9989 "
                        "(reporters MUST ignore it); pre-9989 readers may "
                        "still honor it and produce incomplete reports."
                    )
                
                
            except _DMARCWarning as warning:
                warnings.append(str(warning))


        # Edit: Der rua-Value in der Tagaufzählung bleibt ein String
        #tags["rua"]["value"] = parsed_uris
        

        if len(parsed_rua_list) > 2:
            warnings.append(
                str(
                    _DMARCBestPracticeWarning(
                        "Some DMARC reporters might not send to more than two rua URIs."
                    )
                )
            )
    else:
        warnings.append(
            str(
                _DMARCBestPracticeWarning(
                    "rua tag (destination for aggregate reports) not found."
                )
            )
        )

    parsed_ruf_list = []
    if "ruf" in tags:
        
        uris = tags["ruf"]["value"].split(",")
        for uri in uris:
            try:
                uri = parse_dmarc_report_uri(uri)
                parsed_ruf_list.append(uri)
                email_address = uri["address"]
                if uri["size_limit"]:
                    warnings.append(
                        "The size limit (`!size`) on ruf URI for "
                        f"{email_address} is obsolete in RFC 9989 "
                        "(reporters MUST ignore it); pre-9989 readers may "
                        "still honor it and produce incomplete reports."
                    )

            except _DMARCWarning as warning:
                warnings.append(str(warning))

        # Edit: Speichere ruf-Ergebnisse sperat ab
        #tags["ruf"]["value"] = parsed_ruf_list
        if len(parsed_ruf_list) > 2:
            warnings.append(
                str(
                    _DMARCBestPracticeWarning(
                        "Some DMARC reporters might not send to more than two ruf URIs."
                    )
                )
            )

    # Edit: pct Prüfung wieder hinzugefügt
    if tags["pct"]["value"] < 0 or tags["pct"]["value"] > 100:
        raise DMARCSyntaxError("pct value must be an integer between 0 and 100.")
    elif tags["pct"]["value"] == 0:
        warnings.append("A pct value of 0 disables DMARC enforcement.")
    elif tags["pct"]["value"] < 100:
        warning_msg = (
            "pct value is less than 100. This leads to "
            "inconsistent and unpredictable policy "
            "enforcement. Consider using p=none to "
            "monitor results instead."
        )
        warnings.append(str(_DMARCBestPracticeWarning(warning_msg)))

    # Edit: Einheitlicher Typ String für spätere deserialisierung
    tags["pct"]["value"] = str(tags["pct"]["value"])


    # Add descriptions if requested
    if include_tag_descriptions:
        for tag, tag_details in tags.items():
            details = get_dmarc_tag_description(tag, tag_details["value"])
            tag_details["name"] = details["name"]
            if details["default"]:
                tag_details["default"] = details["default"]
            tag_details["description"] = details["description"]

    return {"tags": tags, "ruaURIList" : parsed_rua_list , "rufURIList" : parsed_ruf_list ,"warnings": warnings}


def check_dmarc(
    record: str,
    domain: str
) -> DMARCResults | DMARCErrorResults:
    """
    Returns a dictionary with a parsed DMARC record or an error

    Args:
        domain (str): A domain name
        parked (bool): The domain is parked
        include_dmarc_tag_descriptions (bool): Include tag descriptions
        ignore_unrelated_records (bool): Ignore unrelated TXT records
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS
        retries (int): The number of times to retry on timeout or other transient errors


    Returns:
        dict: a ``dict`` with the following keys:

                     - ``record`` - the unparsed DMARC record string
                     - ``location`` - the domain where the record was found
                     - ``warnings`` - warning conditions found

                    If a DNS error occurs, the dictionary will have the
                    following keys:

                  - ``error``  - An error message
                  - ``valid`` - False

    """
    try:
        parsed_dmarc_record = parse_dmarc_record(
            record,
            domain,
            include_tag_descriptions= False,
        )

        dmarc_results: DMARCResults = {
            "record": record,
            "valid": True,
            "error": None,
            "tags": parsed_dmarc_record["tags"],
            "ruaURIList": parsed_dmarc_record["ruaURIList"],
            "rufURIList": parsed_dmarc_record["rufURIList"]
        }
        return dmarc_results
    
    except DMARCError as error:
        error_results: DMARCResults = {
            "record": record,
            "valid": False,
            "error": str(error),
            "tags": None,
            "ruaURIList": None,
            "rufURIList": None
        }
        return error_results



#main Funktion die check_dmarc ausführt
def main():
    # Beispiel-Daten zum Testen
    #test_domain = "example.com"
    #test_record = " v=DMARC1; p=reject; rua=mailto:dmarc@example.com , mailto:dmarc@example3.com ; ruf=mailto:dmarc@example2.com, mailto:dmarc@example4.com ; pct=10; "

    #print(f"Überprüfe DMARC-Record für: {test_domain}")
    #print(f"Record: {test_record}\n")

    # check_dmarc aufrufen
    #ergebnis = check_dmarc(
    #    record=test_record,
    #    domain=test_domain
    #)



    # Das Ergebnis formatiert als JSON auf der Konsole ausgeben
    #print(json.dumps(ergebnis, indent=4))


    parser = argparse.ArgumentParser(description="DMARC Validation-Skript")
    parser.add_argument("domain", help="Die Domain, für die der Record gilt")
    parser.add_argument("record", help='Der DMARC-Record als String')


    args = parser.parse_args()

    # Funktion mit den übergebenen Argumenten aufrufen
    ergebnis = check_dmarc(
        record=args.record,
        domain=args.domain
    )

    # Ergebnis formatiert ausgeben
    print(json.dumps(ergebnis, indent=4))




# Dieser Block sorgt dafür, dass main() nur ausgeführt wird,
# wenn man die Datei direkt startet (z.B. mit 'python skript.py').
if __name__ == "__main__":
    main()