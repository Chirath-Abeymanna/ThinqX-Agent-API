"""
Common API request/response models
"""
from typing import Dict, Any, Optional, List
from pydantic import BaseModel

class OpenRedirectRequest(BaseModel):
    """Request model for open redirect scan"""
    target: str
    mission_type: str = "comprehensive"

class OpenRedirectResponse(BaseModel):
    """Response model for open redirect scan"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    error: Optional[str] = None
    detail: Optional[str] = None
