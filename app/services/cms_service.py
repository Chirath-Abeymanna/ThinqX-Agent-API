"""
CMS Scanner Service - Async service for FastAPI
"""
import os
import sys
from typing import Dict, Any

# Add the CMS_DETECTION directory to Python path
cms_detection_path = os.path.join(os.path.dirname(__file__), "..", "Agents", "CMS_DETECTION")
sys.path.insert(0, cms_detection_path)

from cms_scanner_agent import CMSScannerAgent

async def run_cms_scan_service(target: str) -> Dict[str, Any]:
    """
    Runs the CMS scanner agent and returns the resulting report dict for REST API.
    
    Args:
        target: Target domain or URL to scan
        
    Returns:
        Dict containing the complete CMS scan report
    """
    # Change to CMS_DETECTION directory for proper file access
    original_cwd = os.getcwd()
    cms_detection_dir = os.path.abspath(cms_detection_path)
    
    try:
        os.chdir(cms_detection_dir)
        
        # Create and run CMS scanner
        agent = CMSScannerAgent()
        
        # Use the existing event loop (FastAPI's)
        result = await agent.run_cms_scan(target)
        return result
            
    finally:
        # Restore original working directory
        os.chdir(original_cwd)
