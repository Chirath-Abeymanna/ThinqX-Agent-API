"""
API v1 router configuration
"""
from fastapi import APIRouter


from app.api.v1.endpoints import web_crawler_controller, recon_controller

api_router = APIRouter(prefix="/api/v1")

# Include all endpoint routers

api_router.include_router(web_crawler_controller.router)
api_router.include_router(recon_controller.router)

# Note: Include other routers as they are implemented
# api_router.include_router(predict_model_a.router)
