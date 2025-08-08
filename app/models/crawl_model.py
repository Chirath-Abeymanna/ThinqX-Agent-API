"""
Pydantic models for web crawler API requests and responses
"""
from pydantic import BaseModel, validator, Field
from typing import Dict, List, Any, Optional
from datetime import datetime
import re


class CrawlRequest(BaseModel):
    """Request model for web crawling"""
    domain: str = Field(..., description="Target domain or URL to crawl (e.g., example.com or https://example.com)")
    max_threads: Optional[int] = Field(10, ge=1, le=50, description="Maximum number of threads (1-50)")
    max_depth: Optional[int] = Field(3, ge=1, le=10, description="Maximum crawl depth (1-10)")
    save_report: Optional[bool] = Field(True, description="Whether to save report to file")
    
    @validator('domain')
    def validate_domain(cls, v):
        """Validate and normalize domain/URL format"""
        if not v or not v.strip():
            raise ValueError('Domain cannot be empty')
        
        v = v.strip()
        
        # If it's a full URL, extract just the domain
        if v.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(v)
            if not parsed.netloc:
                raise ValueError('Invalid URL format')
            v = parsed.netloc
        
        # Remove trailing slash if present
        v = v.rstrip('/')
        
        # Remove www. prefix if present (optional - you can remove this if you want to keep www)
        if v.startswith('www.'):
            v = v[4:]
        
        # Basic domain validation - more lenient to handle various formats
        if not v or '.' not in v:
            raise ValueError('Invalid domain format - must contain at least one dot')
        
        # Check for obvious invalid characters
        invalid_chars = ['<', '>', '"', ' ', '\t', '\n', '\r']
        if any(char in v for char in invalid_chars):
            raise ValueError('Domain contains invalid characters')
        
        return v.lower()


class CrawlResultItem(BaseModel):
    """Individual crawl result item"""
    url: str
    status_code: int
    content_type: str
    content_length: int
    response_time: float
    title: str = ""
    forms_count: int = 0
    technologies: List[str] = []
    file_category: str = ""
    sensitivity_level: str = "low"


class CrawlSummary(BaseModel):
    """Crawl summary statistics"""
    target_domain: str
    crawl_duration: float
    urls_discovered: int
    urls_successfully_crawled: int
    errors_encountered: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None


class DiscoveryStatistics(BaseModel):
    """Discovery statistics"""
    total_files_found: int
    total_forms_found: int
    sensitive_files_found: int
    hidden_files_discovered: int


class SecurityAnalysis(BaseModel):
    """Security analysis results"""
    security_headers_coverage: Dict[str, int]
    forms_discovered: int
    cookies_found: int


class CategoryFindings(BaseModel):
    """Categorized findings"""
    count: int
    sensitivity_breakdown: Dict[str, int]
    urls: List[CrawlResultItem]


class DetailedResult(BaseModel):
    """Detailed result for high-priority findings"""
    url: str
    category: str
    sensitivity_level: str
    status_code: int
    content_type: str
    content_length: int
    response_time: float
    title: str
    forms: List[Dict[str, Any]] = []
    technologies: List[str] = []
    security_headers: Dict[str, str] = {}
    cookies: List[Dict[str, Any]] = []
    comments_count: int = 0
    scripts_count: int = 0
    redirect_chain: List[str] = []


class CrawlResponse(BaseModel):
    """Response model for web crawling results"""
    success: bool
    message: str
    crawl_summary: Optional[CrawlSummary] = None
    discovery_statistics: Optional[DiscoveryStatistics] = None
    categorized_findings: Optional[Dict[str, CategoryFindings]] = None
    sensitivity_analysis: Optional[Dict[str, int]] = None
    technology_fingerprints: Optional[Dict[str, int]] = None
    security_analysis: Optional[SecurityAnalysis] = None
    detailed_results: Optional[List[DetailedResult]] = []
    report_file: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ErrorResponse(BaseModel):
    """Error response model"""
    success: bool = False
    error: str
    detail: Optional[str] = None
    error_code: Optional[str] = None


class StatusResponse(BaseModel):
    """Status response for checking crawler status"""
    status: str  # "running", "completed", "failed", "not_found"
    progress: Optional[str] = None
    estimated_time_remaining: Optional[int] = None
