#!/usr/bin/env python3
"""
ThinqX Web Crawler API Startup Script
"""
import sys
import os
import subprocess
import uvicorn
import traceback

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.core.config import settings

def main():
    """Main startup function"""
    print(f"🚀 Starting {settings.app_name} v{settings.app_version}")
    print(f"🌐 Server will run on http://{settings.host}:{settings.port}")
    print(f"📚 API Documentation: http://{settings.host}:{settings.port}/docs")
    print(f"🔧 ReDoc Documentation: http://{settings.host}:{settings.port}/redoc")
    print("=" * 60)
    
    try:
        uvicorn.run(
            "app.main:app",
            host=settings.host,
            port=settings.port,
            reload=settings.debug,
            workers=1,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
