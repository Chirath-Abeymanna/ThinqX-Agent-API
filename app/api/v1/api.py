"""
API v1 router configuration
"""
from fastapi import APIRouter

from app.api.v1.endpoints import web_crawler

api_router = APIRouter(prefix="/api/v1")

# Include all endpoint routers
api_router.include_router(web_crawler.router)

# Note: Include other routers as they are implemented
# api_router.include_router(predict_model_a.router)
