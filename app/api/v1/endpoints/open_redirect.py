from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.open_redirect import run_openredirect_agent_service
from app.models.open_redirect_models import OpenRedirectReport

router = APIRouter(prefix="/openredirect", tags=["openredirect"])

from typing import Dict, Any, Optional

class OpenRedirectRequest(BaseModel):
    target: str 
    mission_type: str = "comprehensive"

class OpenRedirectResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    error: Optional[str] = None
    detail: Optional[str] = None

@router.post("/scan", response_model=OpenRedirectResponse)
async def scan_domain(request: OpenRedirectRequest):
    """
    Run open_redirect-agent for the given domain and return the JSON result.
    """
    print(f"Meka thamai ena domain eka: {request.target}")
    try:
        # Validate input
        if not request.target.startswith(('http://', 'https://')):
            request.target = f"https://{request.target}"
            
        print(f"Normalized target URL: {request.target}")
        
        result = await run_openredirect_agent_service(request.target, request.mission_type)
        # print(f"Service returned result type: {type(result)}")
        # print(f"Service returned result content: {result}")
        
        if not result:
            raise HTTPException(status_code=500, detail="Scan completed but no results were returned")
            
        print(f"Scan completed successfully")
        
        # Ensure we return a properly structured response
        return OpenRedirectResponse(
            success=True,
            data=result,
            message="Scan completed successfully"
        )
    except HTTPException as http_exc:
        # Re-raise HTTP exceptions
        raise http_exc
    except Exception as exc:
        import traceback
        error_detail = traceback.format_exc()
        print(f"Error occurred: {error_detail}")
        # Return a properly structured error response
        return OpenRedirectResponse(
            success=False,
            error=str(exc),
            detail=error_detail
        )
