"""Pydantic models translated from the Kotlin evaluator data classes."""

from pydantic import BaseModel, Field


class DMARCTagValue(BaseModel):
    value: str
    explicit: bool


class ParsedDMARCReportURI(BaseModel):
    scheme: str
    address: str
    domain: str
    size_limit: str | None


class dmarcGeneralData(BaseModel):
    hasPolicy: bool
    hasADFlag: bool | None = None
    errorType: str | None = None
    errorMessage: str | None = None
    rawPolicyOld: str | None = None
    oldOrgDomain: str | None = None
    policyLocationDomain: str | None = None
    policyLocation: str | None = None
    cnameRecord: str | None = None
    policyMode: str | None = None
    newOrgDomain: str | None = None
    newRawDMARCPolicy: str | None = None


class DMARCResults(BaseModel):
    record: str
    valid: bool
    error: str | None
    tags: dict[str, DMARCTagValue] | None
    ruaURIList: list[ParsedDMARCReportURI] | None
    rufURIList: list[ParsedDMARCReportURI] | None


class dmarcReportDomain(BaseModel):
    policyForDomain: str
    policyLocationDomain: str
    reportDomain: str
    reportVia: str
    ruaAddressList: list[ParsedDMARCReportURI] | None = None
    rufAddressList: list[ParsedDMARCReportURI] | None = None
    sameOrgDomain: bool = False
    validatedDomain: bool = False
    externalADFlag: bool | None = None
    countryCodeList: str | None = None


class DMARCPolicy(BaseModel):
    domain: str
    generalDMARCData: dmarcGeneralData
    policyTags: dict[str, DMARCTagValue] | None = None
    reportDomains: list[dmarcReportDomain] | None = None


class DMARCMeasurementResult(BaseModel):
    dmarcResults: list[DMARCPolicy]
    externalDomains: list[str]


class DigResult(BaseModel):
    answer: list[str]
    cnameChain: list[str]
    adFlag: bool


class TreeWalkResult(BaseModel):
    cachedTreeWalkPolicyResults: dict[str, DigResult]
    psdDomain: str | None


class MechanismCount(BaseModel):
    a: int = 0
    mx: int = 0
    ptr: int = 0
    ip4: int = 0
    ip6: int = 0
    include: int = 0
    exists: int = 0


class IncludeData(BaseModel):
    domain: str
    dnsLookups: int
    record: str
    voidDnsLookups: int
    mCount: MechanismCount


class RedirectData(BaseModel):
    domain: str
    dnsLookups: int
    record: str
    voidDnsLookups: int
    mCount: MechanismCount


class spfGeneralData(BaseModel):
    valid: bool
    record: str | None
    errorType: str | None
    warnings: list[str]
    lengthWarning: bool
    oldSPFRecordWarning: bool
    dnsLookups: int | None
    voidDnsLookups: int | None
    allQualifier: str | None
    mCount: MechanismCount
    redirectCount: int | None


class SPFResult(BaseModel):
    domain: str
    spf_General_Data: spfGeneralData
    includeData: list[IncludeData] = Field(default_factory=list)
    redirectData: list[RedirectData] = Field(default_factory=list)


class aggAntiSpoofingMetadata(BaseModel):
    isValid: bool
    mxRecordCount: int
    mxRecordList: list[str]


class aggDmarcReportingData(BaseModel):
    reportDomainCount: int
    reportRuaAndRufCount: int
    reportRuaOnlyCount: int
    reportRufOnlyCount: int
    rufAddressCount: int
    ruaAddressCount: int
    externalDomainCount: int
    externalDomainValidatedCount: int
    externalReportAllDNSSEC: int

class outDmarcReportingDomain(BaseModel):
    policyForDomain: str
    policyLocationDomain: str
    reportDomain: str
    reportVia: str
    ruaAddressList: list[str] | None = None
    rufAddressList: list[str] | None = None
    usesSizeLimit: bool = False
    sameOrgDomain: bool = False
    validatedDomain: bool = False
    externalADFlag: bool | None = None
    countryCodeList: str | None = None


class aggDmarcResult(BaseModel):
    generalDMARCData: dmarcGeneralData
    aggDmarcReportingData: aggDmarcReportingData | None
    dmarcTagValues: dict[str, str | None] | None
    dmarcTagValueExplicit: dict[str, bool | None] | None

class aggDnssecDataAntiSpoofing(BaseModel):
    domainDNSSEC: bool
    domainDNSSECPubResolver: bool
    domainDNSSECLocalResolver: bool


class aggSpfResult(BaseModel):
    spfGeneralData: spfGeneralData


_AggDmarcResultType = aggDmarcResult
_AggSpfResultType = aggSpfResult


class aggDomainAntiSpoofing(BaseModel):
    domain: str
    aggDomainAntiSpoofingMetadata: aggAntiSpoofingMetadata
    dnssecResult: aggDnssecDataAntiSpoofing | None = None
    aggDmarcResult: _AggDmarcResultType | None = None
    aggSpfResult: _AggSpfResultType | None = None
    dkimResult: str | None = None


class aggregatedCertificateData(BaseModel):
    issuerCN: str | None
    issuerOrgName: str | None
    issuerCountry: str | None
    distinctSanCount: int | None
    sanDnsMatch: bool | None
    sanStrictIdentifierMatch: bool | None
    validPeriod: int | None
    sigAlg: str | None
    pubKeyAlg: str | None
    EXPubKeyLen: int | None


class aggregatedTlsCertData(BaseModel):
    certData: aggregatedCertificateData | None = None
    tlsVersion: str | None = None
    cipherSuite: str | None = None
    errorType: str | None = None


class aggDaneResult(BaseModel):
    hasValidDaneAllMta: bool
    hasValidDaneAtLeastOneMta: bool
    atLeastOneMtaSupportsDane: bool


class aggDataTransportMetadata(BaseModel):
    isValid: bool
    mxRecordCount: int
    mxRecords: list[str]
    invalidMxCount: int


class aggDNSSECResultDataTransport(BaseModel):
    domainDNSSEC: bool
    domainDNSSECPubResolver: bool
    domainDNSSECLocalResolver: bool
    mxAllDNSSEC: bool
    mxAtLeastOneDNSSEC: bool
    mtaStsDNSRecordDNSSEC: bool | None
    mtaStsPolicyRecordDNSSEC: bool | None
    tlsRptDNSSEC: bool | None


class aggTls12Result(BaseModel):
    validTls12AllMta: bool
    validTls12AtLeastOneMta: bool
    partlyValidTls12AllMta: bool
    partlyValidTls12AtLeastOneMta: bool


class aggTlsCertData(BaseModel):
    atLeastOneMxValidTlsResult: bool
    allMxValidTlsResult: bool


class aggTLSVersionData(BaseModel):
    atLeastOneValidTlsResult: bool
    allValidTlsResult: bool
    hasNoStarttlsSupport: bool | None = None
    #hasSslv2AtLeastOneMta: bool | None = None
    #hasSslv3AtLeastOneMta: bool | None = None
    hasTls1AtLeastOneMta: bool | None = None
    hasTls1_1AtLeastOneMta: bool | None = None
    hasTls1_2AtLeastOneMta: bool | None = None
    #hasTls1_3AtLeastOneMta: bool | None = None
    minVersionAtLeastOneMta: str | None = None
    #maxVersionAtLeastOneMta: str | None = None
    #minVersionAllMta: str | None = None
    #maxVersionAllMta: str | None = None


class MtaStsPolicyObject(BaseModel):
    max_age: str | None
    mode: str | None
    mx_list: list[str]


class MtaStsPolicyValidationResult(BaseModel):
    allMtaValid: bool
    atLeastOneMtaValid: bool
    mtaInvalidTlsCount: int
    mtaNotInPolicyCount: int
    mtaValidCount: int
    mtaValidCountList: list[str]


class MtaStsData(BaseModel):
    usesMtaSts: bool
    generalErrorType: str | None
    rawDnsString: str | None = None
    cnameDnsRecord: str | None = None
    rawPolicy: str | None = None
    cnamePolicy: str | None = None
    ipCountryCode: str | None = None
    policy: MtaStsPolicyObject | None = None
    mtaStsPolicyValidation: MtaStsPolicyValidationResult | None = None
    policytlsData: aggregatedTlsCertData | None = None


class TlsRptData(BaseModel):
    hasTlsrptDnsRecord: bool
    rawRecord: str | None
    lastCname: str | None
    errorType: str | None
    distinctRepotingDomains: int | None = None
    reportingOverHTTPS: int | None = None
    reportingOverMAILTO: int | None = None
    distinctExternalDomains: int | None = None
    externalOverHTTPS: int | None = None
    externalOverMAILTO: int | None = None


class aggDomainDataTransport(BaseModel):
    domain: str
    aggDataTransportMetadata: aggDataTransportMetadata
    tlsCertData: aggTlsCertData | None = None
    tlsVersionData: aggTLSVersionData | None = None
    tls12Result: aggTls12Result | None = None
    mtaStsData: MtaStsData | None = None
    tlsRptData: TlsRptData | None = None
    dnssecResult: aggDNSSECResultDataTransport | None = None
    daneResult: aggDaneResult | None = None


class MtaStsErrorEntry(BaseModel):
    scope: str
    domainname: str
    generalErrorType: str | None
    detailedErrorType: str | None = None


class MXData(BaseModel):
    domain: str
    mxRecord: str
    ipAddress: list[str]
    countryCode: str
    invalidRecord: bool
    connectionError: bool
    errorType: str | None
    defaultTlsVersion: str | None = None
    defaultCipherSuite: str | None = None
    issuerCN: str | None
    issuerOrgName: str | None
    issuerCountry: str | None
    distinctSanCount: int | None
    sanDnsMatch: bool | None
    sanStrictIdentifierMatch: bool | None
    validPeriod: int | None
    sigAlg: str | None
    pubKeyAlg: str | None
    pubKeyLen: int | None
    validTlsVerResult: bool
    hasNoStarttlsSupport: bool | None = None
    #hasSslv2: bool | None = None
    #hasSslv3: bool | None = None
    hasTls1: bool | None = None
    hasTls1_1: bool | None = None
    hasTls1_2: bool | None = None
    #hasTls1_3: bool | None = None
    minVersion: str | None = None
    #maxVersion: str | None = None
    hasMtaSts: bool
    hasValidMtaStsPolicy: bool
    mxInPolicy: bool
    hasDANEForMxOnly: bool
    hasValidDane: bool
    cnameTLSA: str | None
    MxDNSSECPubResolver: bool
    MxDNSSECLocResolver: bool
    MxDNSSECFullyValidated: bool
    MxDNSSECValidResult: bool
    MxDNNSECRCODE: str
    DNSSECerror: str | None
    tls12Results: dict[str, str | None]


class externalDependency(BaseModel):
    usedByDomain: str
    dependencyType: str
    hostnamePartOf: str
    domain: str
    ipCountryCode: str | None = None


class domainInfo(BaseModel):
    domainname: str
    code: str|None = None
    name: str|None = None
    region: str| None = None
    tier_id: str | None = None
    aggDomainDataTransport: aggDomainDataTransport
    mxData: list[MXData]
    mtaStsErrorList: list[MtaStsErrorEntry]
    aggDomainAntiSpoofing: aggDomainAntiSpoofing
    dmarcReportDomain: list[outDmarcReportingDomain]
    externalDependencyList: list[externalDependency]


class SecurityOutput(BaseModel):
    """Top-level output envelope for security scan results."""

    generated: str
    commit: str | None = None
    total: int
    #counts: dict[str, int]
    municipalities: list[domainInfo]