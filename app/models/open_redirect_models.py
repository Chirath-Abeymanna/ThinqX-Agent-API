"""
Data models for Open Redirect Detection Tool
Compatible with defensive cybersecurity platforms and SIEM integration
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Any, Tuple
from pydantic import BaseModel
from enum import Enum
import time
import json
from datetime import datetime
from uuid import uuid4

class VulnerabilityLevel(Enum):
    """Vulnerability severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RedirectType(Enum):
    """Types of redirect mechanisms"""
    HEADER_BASED = "Header-Based"
    JAVASCRIPT_BASED = "JavaScript-Based"
    META_TAG_BASED = "Meta-Tag-Based"
    FORM_BASED = "Form-Based"
    DOM_BASED = "DOM-Based"

class ScanStatus(Enum):
    """Scan status enumeration"""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

@dataclass
class RedirectVulnerability:
    """
    Model representing an open redirect vulnerability finding
    """
    url: str
    payload: str
    redirect_type: RedirectType
    final_destination: str
    vulnerability_level: VulnerabilityLevel
    response_code: int
    id: str = field(default_factory=lambda: str(uuid4()))
    parameter_name: str = ""
    sources_sinks: List[str] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    evidence: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

@dataclass
class ScanConfiguration:
    """
    Configuration model for open redirect scans
    """
    target_url: str
    timeout: int = 10
    max_concurrent: int = 20
    user_agent: str = "OpenRedirectDetector/2.0 (Security Scanner)"
    follow_redirects: bool = False
    verify_ssl: bool = False
    test_payloads: List[str] = field(default_factory=list)
    custom_parameters: List[str] = field(default_factory=list)
    scan_depth: int = 1
    include_subdomains: bool = False
    
    def __post_init__(self):
        """Initialize default payloads if not provided"""
        if not self.test_payloads:
            self.test_payloads = [
                "http://evil.com",
                "https://evil.com", 
                "//evil.com",
                "///evil.com",
                "////evil.com",
                "http%3A%2F%2Fevil.com",
                "https%3A%2F%2Fevil.com",
                "%2F%2Fevil.com",
                "https:evil.com",
                "HtTP://evil.com",
                "//evil.com/%2f..",
                "///evil.com/%2f..",
                "//evil.com/%2e%2e",
                "javascript:alert('XSS');//evil.com",
                "/\\evil.com",
                "/.evil.com",
                "http://google.com",
                "https://google.com",
                "//google.com"
            ]

@dataclass
class ScanResult:
    """
    Comprehensive scan results model
    """
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    target_url: str = ""
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None
    duration: float = 0.0
    status: ScanStatus = ScanStatus.PENDING
    vulnerabilities: List[RedirectVulnerability] = field(default_factory=list)
    tests_performed: int = 0
    parameters_tested: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    scan_config: Optional[ScanConfiguration] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        # Handle enum serialization
        result['status'] = self.status.value
        if self.scan_config:
            result['scan_config'] = asdict(self.scan_config)
        result['vulnerabilities'] = [vuln.to_dict() for vuln in self.vulnerabilities]
        return result
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)
    
    def add_vulnerability(self, vulnerability: RedirectVulnerability):
        """Add a vulnerability finding"""
        self.vulnerabilities.append(vulnerability)
    
    def complete_scan(self, duration: float):
        """Mark scan as completed"""
        self.end_time = datetime.now().isoformat()
        self.duration = duration
        self.status = ScanStatus.COMPLETED
    
    def fail_scan(self, error_message: str):
        """Mark scan as failed"""
        self.end_time = datetime.now().isoformat()
        self.status = ScanStatus.FAILED
        self.error_message = error_message

@dataclass
class URLAnalysis:
    """
    Model for URL analysis results
    """
    original_url: str
    base_url: str
    existing_params: Dict[str, str]
    redirect_params_found: List[str]
    test_urls: List[Tuple[str, str]]
    parsed_components: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'original_url': self.original_url,
            'base_url': self.base_url,
            'existing_params': self.existing_params,
            'redirect_params_found': self.redirect_params_found,
            'test_urls': self.test_urls,
            'parsed_components': self.parsed_components
        }

@dataclass
class DetectionRule:
    """
    Model for detection rules and patterns
    """
    rule_id: str
    name: str
    description: str
    patterns: List[str]
    severity: VulnerabilityLevel
    confidence_threshold: float
    enabled: bool = True
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

@dataclass
class PlatformIntegration:
    """
    Model for cybersecurity platform integration
    """
    platform_name: str
    api_endpoint: str
    api_key: Optional[str] = None
    auth_token: Optional[str] = None
    verify_ssl: bool = True
    timeout: int = 30
    headers: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

class OpenRedirectDetectionModel:
    """
    Main model class for managing open redirect detection data
    """
    
    def __init__(self):
        self.scan_results: Dict[str, ScanResult] = {}
        self.detection_rules: Dict[str, DetectionRule] = {}
        self.platform_integrations: Dict[str, PlatformIntegration] = {}
        
        # Load default detection rules
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default detection rules"""
        default_rules = [
            DetectionRule(
                rule_id="OR-001",
                name="HTTP Header Redirect",
                description="Detects redirects via Location HTTP header",
                patterns=[
                    r"location:\s*",
                    r"refresh:\s*",
                    r"redirect:\s*"
                ],
                severity=VulnerabilityLevel.HIGH,
                confidence_threshold=0.7
            ),
            DetectionRule(
                rule_id="OR-002",
                name="JavaScript Redirect",
                description="Detects JavaScript-based redirects",
                patterns=[
                    r"location\.href",
                    r"window\.location",
                    r"location\.replace",
                    r"window\.open"
                ],
                severity=VulnerabilityLevel.MEDIUM,
                confidence_threshold=0.6
            ),
            DetectionRule(
                rule_id="OR-003",
                name="Meta Tag Redirect",
                description="Detects meta refresh redirects",
                patterns=[
                    r"http-equiv=\"refresh\"",
                    r"content=\"\d+;url="
                ],
                severity=VulnerabilityLevel.MEDIUM,
                confidence_threshold=0.65
            )
        ]
        
        for rule in default_rules:
            self.detection_rules[rule.rule_id] = rule
    
    def create_scan_result(self, target_url: str, config: ScanConfiguration) -> ScanResult:
        """Create a new scan result entry"""
        scan_result = ScanResult(
            target_url=target_url,
            scan_config=config,
            status=ScanStatus.RUNNING
        )
        self.scan_results[scan_result.scan_id] = scan_result
        return scan_result
    
    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Retrieve a scan result by ID"""
        return self.scan_results.get(scan_id)
    
    def get_all_scans(self) -> List[ScanResult]:
        """Get all scan results"""
        return list(self.scan_results.values())
    
    def add_detection_rule(self, rule: DetectionRule):
        """Add a new detection rule"""
        self.detection_rules[rule.rule_id] = rule
    
    def get_detection_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Get a detection rule by ID"""
        return self.detection_rules.get(rule_id)
    
    def add_platform_integration(self, integration: PlatformIntegration):
        """Add platform integration configuration"""
        self.platform_integrations[integration.platform_name] = integration
    
    def export_to_siem_format(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Export scan results to SIEM-compatible format
        """
        return {
            "event_type": "security_scan",
            "scan_type": "open_redirect",
            "scan_id": scan_result.scan_id,
            "target": scan_result.target_url,
            "timestamp": scan_result.end_time or scan_result.start_time,
            "duration": scan_result.duration,
            "status": scan_result.status.value,
            "vulnerabilities_count": len(scan_result.vulnerabilities),
            "vulnerabilities": [
                {
                    "id": vuln.id,
                    "type": vuln.redirect_type.value,
                    "severity": vuln.vulnerability_level.value,
                    "parameter": vuln.parameter_name,
                    "payload": vuln.payload,
                    "destination": vuln.final_destination,
                    "confidence": vuln.confidence_score,
                    "timestamp": vuln.timestamp
                }
                for vuln in scan_result.vulnerabilities
            ],
            "metadata": {
                "tests_performed": scan_result.tests_performed,
                "parameters_tested": scan_result.parameters_tested
            }
        }
    
    def generate_report(self, scan_result: ScanResult, format: str = "json") -> str:
        """
        Generate comprehensive security report
        """
        report_data = {
            "report_type": "open_redirect_assessment",
            "generated_at": datetime.now().isoformat(),
            "scan_summary": {
                "scan_id": scan_result.scan_id,
                "target_url": scan_result.target_url,
                "start_time": scan_result.start_time,
                "end_time": scan_result.end_time,
                "duration": f"{scan_result.duration:.2f} seconds",
                "status": scan_result.status.value,
                "total_tests": scan_result.tests_performed,
                "vulnerabilities_found": len(scan_result.vulnerabilities)
            },
            "vulnerability_details": [
                {
                    "id": vuln.id,
                    "severity": vuln.vulnerability_level.value,
                    "type": vuln.redirect_type.value,
                    "parameter": vuln.parameter_name,
                    "payload": vuln.payload,
                    "redirects_to": vuln.final_destination,
                    "confidence_score": vuln.confidence_score,
                    "http_status": vuln.response_code,
                    "timestamp": vuln.timestamp
                }
                for vuln in scan_result.vulnerabilities
            ],
            "recommendations": self._generate_recommendations(scan_result)
        }
        
        if format.lower() == "json":
            return json.dumps(report_data, indent=2)
        else:
            # For other formats (HTML, PDF, etc.), you would implement conversion here
            return json.dumps(report_data, indent=2)
    
    def _generate_recommendations(self, scan_result: ScanResult) -> List[Dict[str, str]]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if scan_result.vulnerabilities:
            recommendations.append({
                "priority": "HIGH",
                "recommendation": "Implement proper URL validation and whitelisting for all redirect parameters",
                "details": "Use allow lists for valid redirect destinations instead of trying to block malicious ones"
            })
            
            recommendations.append({
                "priority": "MEDIUM",
                "recommendation": "Add CSRF protection for redirect functionality",
                "details": "Ensure redirect actions are protected against Cross-Site Request Forgery attacks"
            })
        
        recommendations.append({
            "priority": "LOW",
            "recommendation": "Regularly audit redirect functionality",
            "details": "Schedule periodic security assessments of all redirect mechanisms"
        })
        
        return recommendations

# Example usage and utility functions
def create_vulnerability_from_dict(data: Dict[str, Any]) -> RedirectVulnerability:
    """Create Vulnerability object from dictionary"""
    print("Data Awa 🔪")
    return RedirectVulnerability(
        url=data.get('url', ''),
        payload=data.get('payload', ''),
        redirect_type=RedirectType(data.get('redirect_type', 'Header-Based')),
        final_destination=data.get('final_destination', ''),
        vulnerability_level=VulnerabilityLevel(data.get('vulnerability_level', 'LOW')),
        response_code=data.get('response_code', 0),
        parameter_name=data.get('parameter_name', ''),
        sources_sinks=data.get('sources_sinks', []),
        redirect_chain=data.get('redirect_chain', []),
        confidence_score=data.get('confidence_score', 0.0),
        evidence=data.get('evidence', {}),
        context=data.get('context', {})
        
    )

def load_scan_results_from_file(filename: str) -> List[ScanResult]:
    """Load scan results from JSON file"""
    print("Scan Result Load una 🔪")
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        
        results = []
        for result_data in data:
            scan_result = ScanResult(
                scan_id=result_data.get('scan_id', ''),
                target_url=result_data.get('target_url', ''),
                start_time=result_data.get('start_time', ''),
                end_time=result_data.get('end_time'),
                duration=result_data.get('duration', 0.0),
                status=ScanStatus(result_data.get('status', 'PENDING')),
                tests_performed=result_data.get('tests_performed', 0),
                parameters_tested=result_data.get('parameters_tested', []),
                error_message=result_data.get('error_message')
            )
            
            # Load vulnerabilities
            for vuln_data in result_data.get('vulnerabilities', []):
                scan_result.add_vulnerability(create_vulnerability_from_dict(vuln_data))
            
            results.append(scan_result)
        
        return results
    except Exception as e:
        print(f"Error loading scan results: {e}")
        return []

class OpenRedirectReport(BaseModel):
    """
    Pydantic model for API response
    """
    scan_id: str
    target_url: str
    start_time: str
    end_time: Optional[str] = None
    duration: float = 0.0
    status: str
    vulnerabilities: List[Dict[str, Any]] = []
    tests_performed: int = 0
    parameters_tested: List[str] = []
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = {}