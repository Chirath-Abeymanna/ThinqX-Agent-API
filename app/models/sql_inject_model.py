from typing import List, Optional, Any
from pydantic import BaseModel

class InjectionResult(BaseModel):
	parameter: Optional[str]
	payload: str
	type: str
	confidence: float
	extracted_data: Optional[Any]
	error_message: Optional[str]

class TestResult(BaseModel):
	payload: str
	type: str
	success: bool
	response_time: float
	confidence: float

class AssessmentSummary(BaseModel):
	total_parameters_tested: int
	vulnerable_parameters: int
	total_injection_tests: int
	successful_injections: int
	confidence_score: float
	risk_level: str

class TechnicalDetails(BaseModel):
	discovered_parameters: List[str]
	all_test_results: List[TestResult]

class SQLInjectionReport(BaseModel):
	target_url: str
	assessment_summary: AssessmentSummary
	vulnerable_parameters: List[str]
	successful_injections: List[InjectionResult]
	recommendations: List[str]
	technical_details: TechnicalDetails
