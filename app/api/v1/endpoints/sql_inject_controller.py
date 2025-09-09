from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.sql_inject_service import get_sql_injection_report

router = APIRouter(prefix="/sql-injection", tags=["SQL Injection"])

class SQLInjectionRequest(BaseModel):
	target_url: str

@router.post("/scan", response_model=dict)
def scan_sql_injection(request: SQLInjectionRequest):
	if not request.target_url:
		raise HTTPException(status_code=400, detail="target_url is required")
	result = get_sql_injection_report(request.target_url)
	return result
