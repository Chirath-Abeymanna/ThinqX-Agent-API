from app.Agents.recon_agent import run_recon_agent
from app.models.recon_models import ReconReport
from typing import Dict, Any

def run_recon_agent_service(target: str, mission_type: str = "comprehensive") -> Dict[str, Any]:
    """
    Runs the recon agent and returns the resulting report dict for REST API.
    """
    result = run_recon_agent(target, mission_type)

    # Ensure all findings fields are present and safely defaulted
    findings = result.get('findings', {})
    findings_defaults = {
        "whois": None,
        "dns": None,
        "virustotal": None,
        "shodan": None,
        "passive_dns": None,
        "subdomains": [],
        "zone_transfer": None,
        "port_scan": None,
        "web_crawl": None,
        "directory_bruteforce": None,
        "security_headers": None
    }
    for key, default in findings_defaults.items():
        if key not in findings or findings[key] is None:
            findings[key] = default if default is not None else ""
    result['findings'] = findings

    # Parse and return structured ReconReport
    structured = ReconReport.parse_obj(result)
    return structured.dict()
