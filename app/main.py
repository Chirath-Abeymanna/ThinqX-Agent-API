"""
ThinqX FastAPI Application
Main application entry point with CORS, middleware, and route configuration
"""
from contextlib import asynccontextmanager
import uvicorn

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.api.v1.api import api_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    """
    Application lifespan handler for startup and shutdown events
    """
    # Startup
    print(f"🚀 {settings.app_name} v{settings.app_version} starting up...")
    print(f"🧵 Default threads: {settings.default_max_threads}")
    print(f"🕳️ Default depth: {settings.default_max_depth}")
    print("⏰ No time restrictions - scans run until completion")
    yield
    # Shutdown
    print(f"🛑 {settings.app_name} shutting down...")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="""
    ThinqX Web Crawler API - Advanced vulnerability scanning and web reconnaissance tool.

    ## Features

    * **Intelligent Web Crawling**: OWASP ZAP-like capabilities for comprehensive web scanning
    * **Vulnerability Detection**: Automated discovery of sensitive files, configuration issues, and security weaknesses
    * **Async Processing**: Long-running scans with status tracking and real-time progress updates
    * **Comprehensive Reporting**: Detailed JSON reports with categorized findings and risk assessment
    * **Technology Fingerprinting**: Automatic detection of web technologies, frameworks, and services
    * **Security Analysis**: Analysis of security headers, cookies, forms, and potential attack vectors

    ## Endpoints

    * `POST /api/v1/crawler/scan` - Start synchronous crawl (waits for completion)
    * `POST /api/v1/crawler/scan/async` - Start asynchronous crawl (returns task ID)
    * `GET /api/v1/crawler/status/{task_id}` - Check crawl progress
    * `GET /api/v1/crawler/results/{task_id}` - Get crawl results
    * `GET /api/v1/crawler/active-tasks` - List active crawl tasks

    ## Usage Example

    ```python
    import requests

    # Start a crawl
    response = requests.post("/api/v1/crawler/scan", json={
        "domain": "example.com",
        "max_threads": 10,
        "max_depth": 3
    })

    results = response.json()
    print(f"Found {len(results['detailed_results'])} high-priority vulnerabilities")
    ```
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=settings.cors_methods,
    allow_headers=settings.cors_headers,
)

# Include API routes
app.include_router(api_router)


@app.get("/", tags=["root"])
async def root():
    """
    Root endpoint providing API information
    """
    return {
        "message": f"Welcome to {settings.app_name}",
        "version": settings.app_version,
        "docs": "/docs",
        "redoc": "/redoc",
        "api_prefix": "/api/v1",
        "endpoints": {
            "web_crawler": "/api/v1/crawler",
            "health": "/api/v1/crawler/health"
        }
    }


@app.get("/health", tags=["health"])
async def health():
    """
    Application health check
    """
    return {
        "status": "healthy",
        "application": settings.app_name,
        "version": settings.app_version
    }


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(_, exc):
    """
    Global exception handler for unhandled errors
    """
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "detail": str(exc) if settings.debug else "An unexpected error occurred"
        }
    )


if __name__ == "__main__":
    # Run the application
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        workers=1  # Keep to 1 for thread safety with crawler tasks
    )
