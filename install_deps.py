#!/usr/bin/env python3
"""
Dependency installer script to handle FastAPI and Pydantic conflicts
"""

import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"\n{description}...")
    print(f"Running: {command}")
    
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ Success: {description}")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {description}")
        print(f"Return code: {e.returncode}")
        if e.stdout:
            print(f"STDOUT: {e.stdout}")
        if e.stderr:
            print(f"STDERR: {e.stderr}")
        return False

def main():
    """Main installation process"""
    print("🚀 Starting dependency installation process...")
    
    # Step 1: Upgrade pip
    if not run_command("python -m pip install --upgrade pip", "Upgrading pip"):
        print("⚠️ Failed to upgrade pip, continuing anyway...")
    
    # Step 2: Uninstall conflicting packages
    print("\n🧹 Cleaning up existing installations...")
    cleanup_packages = ["fastapi", "pydantic", "pydantic-core", "starlette", "uvicorn"]
    
    for package in cleanup_packages:
        run_command(f"python -m pip uninstall -y {package}", f"Uninstalling {package}")
    
    # Step 3: Install core dependencies first
    core_deps = [
        "typing-extensions==4.8.0",
        "pydantic-core==2.10.1",
        "pydantic==2.4.2",
        "starlette==0.27.0",
        "fastapi==0.104.1",
        "uvicorn[standard]==0.24.0"
    ]
    
    print("\n📦 Installing core dependencies...")
    for dep in core_deps:
        if not run_command(f"python -m pip install {dep}", f"Installing {dep}"):
            print(f"❌ Failed to install {dep}")
            return False
    
    # Step 4: Install remaining dependencies
    remaining_deps = [
        "httpx[http2]==0.25.2",
        "colorama==0.4.6",
        "aiofiles==23.2.1",
        "lxml==4.9.3",
        "beautifulsoup4==4.12.2",
        "python-multipart==0.0.6"
    ]
    
    print("\n📦 Installing additional dependencies...")
    for dep in remaining_deps:
        if not run_command(f"python -m pip install {dep}", f"Installing {dep}"):
            print(f"⚠️ Warning: Failed to install {dep}")
    
    # Step 5: Verify installation
    print("\n🔍 Verifying installation...")
    try:
        import fastapi
        import pydantic
        import uvicorn
        import httpx
        import colorama
        import aiofiles
        import lxml
        import bs4
        
        print("✅ All core packages imported successfully!")
        print(f"FastAPI version: {fastapi.__version__}")
        print(f"Pydantic version: {pydantic.__version__}")
        print(f"Uvicorn version: {uvicorn.__version__}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    
    print("\n🎉 Installation completed successfully!")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
