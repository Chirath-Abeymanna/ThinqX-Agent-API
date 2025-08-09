"""
Web Crawler API endpoints
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends

from app.models.crawl_model import (
    CrawlRequest, 
    CrawlResponse, 
)
from app.services.crawler_service import crawler_service

router = APIRouter(prefix="/crawler", tags=["web-crawler"])


@router.post("/scan", response_model=CrawlResponse)
async def start_web_crawl(
    request: CrawlRequest,
    background_tasks: BackgroundTasks
):
    """
    Start a web crawling scan for the specified domain or URL.
    
    This endpoint works exactly like running the web crawler agent from command line.
    It will run the complete scan without time restrictions and return all results.
    The scan will take as much time as needed to complete thoroughly.
    
    Args:
        request: CrawlRequest containing domain/URL and crawl parameters
        background_tasks: FastAPI background tasks for cleanup
    
    Returns:
        CrawlResponse: Complete crawl results including all vulnerabilities and findings
    
    Raises:
        HTTPException: If the crawl fails to start or encounters errors
    """
    try:
        # Validate request
        if not request.domain:
            raise HTTPException(status_code=400, detail="Domain is required")
        
        # Start the crawl
        task_id = crawler_service.start_crawl_async(
            domain=request.domain,
            max_threads=request.max_threads,
            max_depth=request.max_depth
        )
        
        # Wait for completion without timeout - let it run as long as needed
        result = crawler_service.wait_for_completion(task_id)
        
        if not result:
            raise HTTPException(
                status_code=500, 
                detail="Crawl task not found or failed to initialize"
            )
        
        # Save report to file if requested (like command line version)
        if request.save_report and result.success:
            try:
                task = crawler_service.get_task_status(task_id)
                if task and task.crawler:
                    report_file = task.crawler.save_report()
                    if report_file:
                        result.report_file = report_file
            except Exception as e:
                # Don't fail the whole request if file saving fails
                print(f"Warning: Failed to save report file: {e}")
        
        # Add cleanup task to remove old tasks
        background_tasks.add_task(crawler_service.cleanup_old_tasks)
        
        return result
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error during crawl: {str(e)}"
        )
