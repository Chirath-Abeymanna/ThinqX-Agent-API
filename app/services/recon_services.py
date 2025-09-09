from app.Agents.recon_agent import run_recon_agent
from app.models.recon_models import ReconReport
from typing import Dict, Any

def run_recon_agent_service(target: str, mission_type: str = "comprehensive") -> Dict[str, Any]:
    """
    Runs the recon agent and returns the resulting report dict for REST API.
    """
    result = run_recon_agent(target, mission_type)
    return result
