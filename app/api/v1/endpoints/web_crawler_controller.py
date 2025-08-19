"""
Web Crawler API endpoints
"""
import time
from typing import Dict

from fastapi import APIRouter, HTTPException, BackgroundTasks

from app.models.crawl_model import (
    CrawlRequest,
    CrawlResponse,
    StatusResponse
)
from app.services.crawler_service import crawler_service
from app.core.config import settings

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
        ) from e


@router.post("/scan/async", response_model=Dict[str, str])
async def start_web_crawl_async(request: CrawlRequest):
    """
    Start a web crawling scan asynchronously and return a task ID.
    
    Use this endpoint for long-running scans. Poll the status endpoint
    to check progress and retrieve results when completed.
    
    Args:
        request: CrawlRequest containing domain and crawl parameters
    
    Returns:
        Dict containing task_id for status tracking
    """
    try:
        if not request.domain:
            raise HTTPException(status_code=400, detail="Domain is required")
        
        task_id = crawler_service.start_crawl_async(
            domain=request.domain,
            max_threads=request.max_threads,
            max_depth=request.max_depth
        )
        
        return {
            "task_id": task_id,
            "message": "Crawl started successfully",
            "status_url": f"/crawler/status/{task_id}",
            "results_url": f"/crawler/results/{task_id}"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start crawl: {str(e)}"
        ) from e


@router.get("/status/{task_id}", response_model=StatusResponse)
async def get_crawl_status(task_id: str):
    """
    Get the status of a running or completed crawl task.
    
    Args:
        task_id: Task ID returned from /scan/async endpoint
    
    Returns:
        StatusResponse: Current status and progress information
    """
    task = crawler_service.get_task_status(task_id)
    
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    # Calculate estimated time remaining
    estimated_time = None
    if task.status == "running" and task.start_time:
        elapsed = (time.time() - task.start_time.timestamp())
        # Rough estimate: assume 30-60 seconds per depth level
        estimated_total = task.max_depth * 45
        estimated_time = max(0, int(estimated_total - elapsed))
    
    return StatusResponse(
        status=task.status,
        progress=task.progress,
        estimated_time_remaining=estimated_time
    )


@router.get("/results/{task_id}", response_model=CrawlResponse)
async def get_crawl_results(task_id: str):
    """
    Get the results of a completed crawl task.
    
    Args:
        task_id: Task ID returned from /scan/async endpoint
    
    Returns:
        CrawlResponse: Complete crawl results if task is completed
    """
    task = crawler_service.get_task_status(task_id)
    
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    if task.status == "running":
        raise HTTPException(
            status_code=202, 
            detail="Task is still running. Check status endpoint for progress."
        )
    if task.status == "failed":
        raise HTTPException(
            status_code=500,
            detail=f"Task failed: {task.error or 'Unknown error'}"
        )
    if task.status == "completed":
        if not task.result:
            raise HTTPException(
                status_code=500,
                detail="Task completed but no results available"
            )
        return task.result
    raise HTTPException(
        status_code=400,
        detail=f"Task in unexpected state: {task.status}"
    )


@router.get("/active-tasks")
async def get_active_tasks():
    """
    Get information about currently active crawl tasks.
    
    Returns:
        Dict: Information about active tasks
    """
    active_tasks = {}
    for task_id, task in crawler_service.active_tasks.items():
        active_tasks[task_id] = {
            "domain": task.domain,
            "status": task.status,
            "progress": task.progress,
            "start_time": task.start_time.isoformat() if task.start_time else None,
            "max_threads": task.max_threads,
            "max_depth": task.max_depth
        }
    
    return {
        "active_tasks_count": len(active_tasks),
        "tasks": active_tasks
    }


@router.delete("/task/{task_id}")
async def cancel_crawl_task(task_id: str):
    """
    Cancel a running crawl task.
    
    Args:
        task_id: Task ID to cancel
    
    Returns:
        Dict: Cancellation status
    """
    task = crawler_service.get_task_status(task_id)
    
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    if task.status != "running":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel task in status: {task.status}"
        )
    
    # Note: This is a simple implementation. 
    # For production, you might want to implement proper thread interruption
    task.status = "cancelled"
    task.progress = "Cancelled by user"
    task.end_time = time.time()
    
    return {"message": f"Task {task_id} has been cancelled"}


@router.get("/health")
async def health_check():
    """
    Health check endpoint for the crawler service.
    
    Returns:
        Dict: Service health information
    """
    return {
        "status": "healthy",
        "service": "Web Crawler API",
        "version": settings.app_version,
        "active_tasks": len(crawler_service.active_tasks),
        "completed_tasks": len(crawler_service.completed_tasks)
    }