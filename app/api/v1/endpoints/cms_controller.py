"""
CMS Scanner API endpoints
"""
from typing import Dict, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.cms_service import run_cms_scan_service

router = APIRouter(prefix="/cms", tags=["cms-scanner"])


# Request/Response Models
class CMSScanRequest(BaseModel):
    """Request model for CMS scan"""
    target: str = Field(..., description="Target domain or URL to scan", example="example.com")

    model_config = {
        'json_schema_extra': {
            'examples': [
                { 'target': 'iit.ac.lk' }
            ]
        }
    }


@router.post("/scan")
async def start_cms_scan(request: CMSScanRequest) -> Dict[str, Any]:
    """
    Start a comprehensive CMS security scan and return results immediately.
    
    Detects CMS type (WordPress, Shopify, Wix, Drupal, etc.) and performs:
    - CMS version detection
    - Plugin/theme enumeration
    - Vulnerability assessment
    - Security configuration analysis
    - User enumeration testing
    - Malware detection
    - Domain reputation check
    
    Args:
        request: CMSScanRequest containing target domain/URL
    
    Returns:
        Dict: Complete CMS scan results
    
    Raises:
        HTTPException: If the scan fails
    """
    try:
        # Validate target
        if not request.target.strip():
            raise HTTPException(status_code=400, detail="Target cannot be empty")
        
        # Run the CMS scan and return results immediately
        result = await run_cms_scan_service(request.target)
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CMS scan failed: {str(e)}")


@router.get("/health")
async def health_check():
    """
    Health check endpoint for CMS scanner service.
    
    Returns:
        Dict: Service health status
    """
    return {
        "service": "CMS Scanner",
        "status": "healthy",
        "message": "CMS scanner service is running"
    }
