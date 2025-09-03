from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS AND CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY AND RECOMMENDATION MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class CMSVulnerability(BaseModel):
    type: str
    severity: SeverityLevel
    description: str
    evidence: Union[str, Dict[str, Any]]
    recommendation: str


class CMSRecommendation(BaseModel):
    message: str
    priority: Optional[SeverityLevel] = None


# ═══════════════════════════════════════════════════════════════════════════════
# CMS DETECTION MODELS (POLYMORPHIC)
# ═══════════════════════════════════════════════════════════════════════════════

class BaseCMSDetection(BaseModel):
    """Base CMS detection model - handles generic cases and edge cases"""
    url: str
    cms: Optional[str] = None
    version: Optional[str] = None
    confidence: int = 0
    working_url: Optional[str] = None
    server: Optional[str] = None
    error: Optional[str] = None
    social_media: Optional[Dict[str, List[str]]] = None


class WordPressCMSDetection(BaseCMSDetection):
    """WordPress-specific CMS detection"""
    cms: str = "WordPress"
    # WordPress typically has version info and social media links


class ShopifyCMSDetection(BaseCMSDetection):
    """Shopify-specific CMS detection"""
    cms: str = "Shopify"
    version: Optional[str] = None  # Shopify usually doesn't expose version
    saas_details: Optional[Dict[str, Any]] = None
    security_analysis: Optional[Dict[str, Any]] = None


class WixCMSDetection(BaseCMSDetection):
    """Wix-specific CMS detection"""
    cms: str = "Wix"
    version: Optional[str] = None  # Wix is SaaS, no version
    site_id: Optional[str] = None
    wix_indicators: Optional[Dict[str, Any]] = None


class SquarespaceCMSDetection(BaseCMSDetection):
    """Squarespace-specific CMS detection"""
    cms: str = "Squarespace"
    version: Optional[str] = None  # Squarespace is SaaS, no version
    squarespace_config: Optional[Dict[str, Any]] = None


class JoomlaCMSDetection(BaseCMSDetection):
    """Joomla-specific CMS detection"""
    cms: str = "Joomla"
    components: Optional[List[str]] = None
    modules: Optional[List[str]] = None


class DrupalCMSDetection(BaseCMSDetection):
    """Drupal-specific CMS detection"""
    cms: str = "Drupal"
    modules: Optional[List[str]] = None
    themes: Optional[List[str]] = None


class UnknownCMSDetection(BaseCMSDetection):
    """For cases where no CMS is detected but social media/other data is found"""
    cms: Optional[str] = None
    confidence: int = 0


class FailedCMSDetection(BaseCMSDetection):
    """For failed connection scenarios"""
    cms: Optional[str] = None
    version: Optional[str] = None
    confidence: int = 0
    working_url: Optional[str] = None



# ═══════════════════════════════════════════════════════════════════════════════
# SCAN COMPONENT MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class PluginsThemes(BaseModel):
    url: str
    plugins: List[str] = []
    themes: List[str] = []
    vulnerabilities: List[Dict[str, Any]] = []


class UserEnumeration(BaseModel):
    url: str
    users: List[str] = []
    vulnerable: bool = False


class MalwareScan(BaseModel):
    url: str
    malware: List[str] = []
    suspicious_scripts: List[str] = []
    defaced: bool = False


class OWASPVulnerability(BaseModel):
    type: str
    severity: SeverityLevel
    evidence: str
    matches_count: Optional[int] = None


class OWASPVulnerabilities(BaseModel):
    url: str
    vulnerabilities: List[OWASPVulnerability] = []


class ConfigWeakness(BaseModel):
    type: str
    severity: SeverityLevel
    evidence: str


class ConfigWeaknesses(BaseModel):
    url: str
    weaknesses: List[ConfigWeakness] = []
    admin_exposed: bool = False


class BruteForce(BaseModel):
    url: str
    vulnerable: bool = False
    details: List[Dict[str, Any]] = []


class ContentMonitoring(BaseModel):
    url: str
    changes: List[str] = []
    baseline_hash: Optional[str] = None
    current_hash: Optional[str] = None
    working_url: str
    baseline_path: str


class DomainReputation(BaseModel):
    domain: str
    reputation: Dict[str, int]
    blacklisted: bool = False
    error: Optional[str] = None
    working_url: str


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN FINDINGS CONTAINER
# ═══════════════════════════════════════════════════════════════════════════════

class CMSFindings(BaseModel):
    """Container for all CMS scan findings"""
    cms_detection: Union[
        WordPressCMSDetection, 
        ShopifyCMSDetection, 
        WixCMSDetection,
        SquarespaceCMSDetection,
        JoomlaCMSDetection,
        DrupalCMSDetection,
        UnknownCMSDetection,
        FailedCMSDetection,
        BaseCMSDetection
    ]
    plugins_themes: Optional[PluginsThemes] = None
    user_enumeration: Optional[UserEnumeration] = None
    malware_scan: Optional[MalwareScan] = None
    owasp_vulnerabilities: Optional[OWASPVulnerabilities] = None
    config_weaknesses: Optional[ConfigWeaknesses] = None
    brute_force: Optional[BruteForce] = None
    content_monitoring: Optional[ContentMonitoring] = None
    domain_reputation: Optional[DomainReputation] = None


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN CMS REPORT MODEL
# ═══════════════════════════════════════════════════════════════════════════════

class CMSReport(BaseModel):
    """Complete CMS scan report"""
    target: str
    start_time: str
    end_time: Optional[str] = None
    duration: Optional[str] = None
    status: ScanStatus
    findings: Optional[CMSFindings] = None
    vulnerabilities: List[CMSVulnerability] = []
    recommendations: List[str] = []
    error: Optional[str] = None

    class Config:
        use_enum_values = True


# ═══════════════════════════════════════════════════════════════════════════════
# FACTORY FUNCTIONS FOR POLYMORPHIC CMS DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def create_cms_detection(data: Dict[str, Any]) -> Union[
    WordPressCMSDetection, 
    ShopifyCMSDetection, 
    WixCMSDetection,
    SquarespaceCMSDetection,
    JoomlaCMSDetection,
    DrupalCMSDetection,
    UnknownCMSDetection,
    FailedCMSDetection,
    BaseCMSDetection
]:
    """
    Factory function to create the appropriate CMS detection model
    based on the detected CMS type and scan results
    """
    # Handle connection failures first
    if "error" in data and data["error"]:
        return FailedCMSDetection(**data)
    
    cms_type = data.get('cms')
    if cms_type:
        cms_lower = cms_type.lower()
        
        if cms_lower == 'wordpress':
            return WordPressCMSDetection(**data)
        elif cms_lower == 'shopify':
            return ShopifyCMSDetection(**data)
        elif cms_lower == 'wix':
            return WixCMSDetection(**data)
        elif cms_lower == 'squarespace':
            return SquarespaceCMSDetection(**data)
        elif cms_lower == 'joomla':
            return JoomlaCMSDetection(**data)
        elif cms_lower == 'drupal':
            return DrupalCMSDetection(**data)
        else:
            # Unknown CMS type but detected
            return BaseCMSDetection(**data)
    else:
        # No CMS detected but might have social media or other data
        return UnknownCMSDetection(**data)


def parse_cms_report(json_data: Union[str, Dict[str, Any]]) -> CMSReport:
    """
    Parse CMS scan JSON data into appropriate models
    """
    if isinstance(json_data, str):
        import json
        data = json.loads(json_data)
    else:
        data = json_data.copy()
    
    # Handle findings if they exist
    if "findings" in data and data["findings"]:
        findings_data = data["findings"].copy()
        
        # Create CMS detection with polymorphic approach
        if "cms_detection" in findings_data:
            cms_detection_data = findings_data["cms_detection"]
            cms_detection = create_cms_detection(cms_detection_data)
            findings_data["cms_detection"] = cms_detection
        
        # Create findings object
        data["findings"] = CMSFindings(**findings_data)
    
    # Convert vulnerabilities to proper models
    if "vulnerabilities" in data:
        vulnerabilities = []
        for vuln in data["vulnerabilities"]:
            if isinstance(vuln, dict):
                vulnerabilities.append(CMSVulnerability(**vuln))
            else:
                vulnerabilities.append(vuln)
        data["vulnerabilities"] = vulnerabilities
    
    return CMSReport(**data)


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def get_cms_type(report: CMSReport) -> Optional[str]:
    """Get the CMS type from a report"""
    if report.findings and report.findings.cms_detection:
        return report.findings.cms_detection.cms
    return None


def is_wordpress(report: CMSReport) -> bool:
    """Check if the report is for WordPress"""
    return isinstance(report.findings.cms_detection, WordPressCMSDetection) if report.findings else False


def is_shopify(report: CMSReport) -> bool:
    """Check if the report is for Shopify"""
    return isinstance(report.findings.cms_detection, ShopifyCMSDetection) if report.findings else False


def is_wix(report: CMSReport) -> bool:
    """Check if the report is for Wix"""
    return isinstance(report.findings.cms_detection, WixCMSDetection) if report.findings else False


def is_squarespace(report: CMSReport) -> bool:
    """Check if the report is for Squarespace"""
    return isinstance(report.findings.cms_detection, SquarespaceCMSDetection) if report.findings else False


def is_joomla(report: CMSReport) -> bool:
    """Check if the report is for Joomla"""
    return isinstance(report.findings.cms_detection, JoomlaCMSDetection) if report.findings else False


def is_drupal(report: CMSReport) -> bool:
    """Check if the report is for Drupal"""
    return isinstance(report.findings.cms_detection, DrupalCMSDetection) if report.findings else False


def is_failed_scan(report: CMSReport) -> bool:
    """Check if the scan failed due to connection issues"""
    return isinstance(report.findings.cms_detection, FailedCMSDetection) if report.findings else False


def is_unknown_cms(report: CMSReport) -> bool:
    """Check if no CMS was detected"""
    return isinstance(report.findings.cms_detection, UnknownCMSDetection) if report.findings else False


def get_critical_vulnerabilities(report: CMSReport) -> List[CMSVulnerability]:
    """Get all critical vulnerabilities from the report"""
    return [vuln for vuln in report.vulnerabilities 
            if vuln.severity == SeverityLevel.CRITICAL]


def get_social_media_links(report: CMSReport) -> Optional[Dict[str, List[str]]]:
    """Get social media links if available"""
    if report.findings and report.findings.cms_detection:
        return report.findings.cms_detection.social_media
    return None


def get_security_headers(report: CMSReport) -> Optional[Dict[str, str]]:
    """Get security headers if available (Shopify only)"""
    if is_shopify(report) and report.findings.cms_detection.security_analysis:
        return report.findings.cms_detection.security_analysis.get('security_headers')
    return None


def get_saas_details(report: CMSReport) -> Optional[Dict[str, Any]]:
    """Get SaaS platform details (Shopify, Wix, etc.)"""
    if is_shopify(report):
        return report.findings.cms_detection.saas_details
    elif is_wix(report):
        return report.findings.cms_detection.wix_indicators
    elif is_squarespace(report):
        return report.findings.cms_detection.squarespace_config
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# TYPE ANNOTATIONS FOR EXTERNAL USE
# ═══════════════════════════════════════════════════════════════════════════════

# Export main types for external use
__all__ = [
    "CMSReport",
    "CMSFindings", 
    "BaseCMSDetection",
    "WordPressCMSDetection",
    "ShopifyCMSDetection",
    "WixCMSDetection",
    "SquarespaceCMSDetection",
    "JoomlaCMSDetection",
    "DrupalCMSDetection",
    "UnknownCMSDetection",
    "FailedCMSDetection",
    "CMSVulnerability",
    "ScanStatus",
    "SeverityLevel",
    "parse_cms_report",
    "create_cms_detection",
    "get_cms_type",
    "is_wordpress",
    "is_shopify",
    "is_wix",
    "is_squarespace",
    "is_joomla",
    "is_drupal",
    "is_failed_scan",
    "is_unknown_cms",
    "get_critical_vulnerabilities",
    "get_social_media_links",
    "get_security_headers",
    "get_saas_details"
]


# ═══════════════════════════════════════════════════════════════════════════════
# EXAMPLE USAGE
# ═══════════════════════════════════════════════════════════════════════════════

"""
Example usage:

# Parse a CMS scan report
import json
with open('cms_scan_report.json', 'r') as f:
    json_data = json.load(f)

# Create the report with polymorphic CMS detection
report = parse_cms_report(json_data)

# Check scan results and access appropriate fields
if is_failed_scan(report):
    print(f"Scan failed: {report.error}")
elif is_unknown_cms(report):
    print("No CMS detected")
    social_media = get_social_media_links(report)
    if social_media:
        print(f"Found social media: {social_media}")
elif is_wordpress(report):
    print(f"WordPress version: {report.findings.cms_detection.version}")
    social_media = get_social_media_links(report)
    print(f"Social media: {social_media}")
elif is_shopify(report):
    saas_details = get_saas_details(report)
    security_headers = get_security_headers(report)
    print(f"Shopify theme: {saas_details.get('theme') if saas_details else 'Unknown'}")
    print(f"Security headers: {security_headers}")
elif is_wix(report):
    print(f"Wix site detected")
    saas_details = get_saas_details(report)
    print(f"Wix details: {saas_details}")

# Get vulnerabilities regardless of CMS type
critical_vulns = get_critical_vulnerabilities(report)
print(f"Critical vulnerabilities: {len(critical_vulns)}")
"""