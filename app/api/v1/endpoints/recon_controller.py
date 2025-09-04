
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.recon_service import run_recon_agent
from app.models.recon_models import ReconReport

router = APIRouter(prefix="/recon", tags=["recon"])

class ReconRequest(BaseModel):
    target: str
    mission_type: str = "comprehensive"

@router.post("/scan", response_model=ReconReport)
def scan_domain(request: ReconRequest):
    """
    Run recon-agent for the given domain and return the JSON result.
    """
    print(f"Received scan request: {request.json()}")
    try:
        result = run_recon_agent(request.target, request.mission_type)
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
