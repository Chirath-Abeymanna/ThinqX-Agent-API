"""
Application configuration settings
"""
from typing import Optional
import os


class Settings:
    """Application settings"""
    
    # API Settings
    app_name: str = "ThinqX Agents API"
    app_version: str = "1.0.0"
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # Web Crawler Settings
    default_max_threads: int = int(os.getenv("DEFAULT_MAX_THREADS", "10"))
    default_max_depth: int = int(os.getenv("DEFAULT_MAX_DEPTH", "3"))
    
    # Server Settings
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    
    # CORS Settings
    cors_origins: list = ["*"]
    cors_methods: list = ["*"]
    cors_headers: list = ["*"]


# Global settings instance
settings = Settings()
