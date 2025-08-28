from typing import List, Optional, Dict, Any
from pydantic import BaseModel

class TargetClassification(BaseModel):
    type: str
    classification: str

class WhoisInfo(BaseModel):
    domain: str
    registrar: Optional[str]
    creation_date: Optional[str]
    expiration_date: Optional[str]
    updated_date: Optional[str]
    name_servers: Optional[List[str]]
    status: Optional[str]
    emails: Optional[List[str]]
    registrant_country: Optional[str]
    registrant_org: Optional[str]
    admin_email: Optional[str]
    tech_email: Optional[str]
    dnssec: Optional[str]
    domain_age_days: Optional[int]
    domain_age_years: Optional[float]

class DNSAnalysis(BaseModel):
    spf_record: Optional[str]
    dmarc_record: Optional[str]
    dkim_records: Optional[List[str]]
    mx_priority: Optional[List[Dict[str, Any]]]
    subdomain_takeover_risk: Optional[bool]

class DNSInfo(BaseModel):
    A: Optional[List[str]]
    AAAA: Optional[List[str]]
    CNAME: Optional[List[str]]
    MX: Optional[List[str]]
    NS: Optional[List[str]]
    SOA: Optional[List[str]]
    TXT: Optional[List[str]]
    PTR: Optional[List[str]]
    SRV: Optional[List[str]]
    CAA: Optional[List[str]]
    analysis: Optional[DNSAnalysis]

class VirusTotalWhoisInfo(BaseModel):
    registrar: Optional[str]

class VirusTotalReputation(BaseModel):
    total_scans: Optional[int]
    malicious: Optional[int]
    suspicious: Optional[int]
    clean: Optional[int]

class VirusTotalInfo(BaseModel):
    target: str
    lookup_type: str
    reputation: Optional[VirusTotalReputation]
    detected_urls: Optional[List[Any]]
    detected_samples: Optional[List[Any]]
    resolutions: Optional[List[Any]]
    subdomains: Optional[List[str]]
    whois_info: Optional[VirusTotalWhoisInfo]
    ssl_certificates: Optional[List[Any]]
    timestamp: Optional[str]

class ShodanInfo(BaseModel):
    query: str
    query_type: str
    results: Optional[List[Any]]
    total_results: Optional[int]
    vulnerabilities: Optional[List[Any]]
    exposed_services: Optional[List[Any]]
    geolocation: Optional[Dict[str, Any]]
    timestamp: Optional[str]
    error: Optional[str]

class PassiveDNSInfo(BaseModel):
    target: str
    historical_ips: Optional[List[Any]]
    historical_domains: Optional[List[Any]]
    first_seen: Optional[str]
    last_seen: Optional[str]

class ReconFindings(BaseModel):
    whois: Optional[WhoisInfo]
    dns: Optional[DNSInfo]
    virustotal: Optional[VirusTotalInfo]
    shodan: Optional[ShodanInfo]
    passive_dns: Optional[PassiveDNSInfo]
    subdomains: Optional[List[str]]
    zone_transfer: Optional[Dict[str, Any]]
    port_scan: Optional[Dict[str, Any]]
    web_crawl: Optional[Dict[str, Any]]
    directory_bruteforce: Optional[Dict[str, Any]]
    security_headers: Optional[Dict[str, Any]]

class Vulnerability(BaseModel):
    impact: Optional[str]
    # Add more fields as needed

class ReconReport(BaseModel):
    target: str
    target_classification: TargetClassification
    mission_type: str
    start_time: str
    findings: ReconFindings
    vulnerabilities: List[Vulnerability]
    recommendations: List[str]
    classification: str
    end_time: str
    mission_duration: str
    mission_status: str
