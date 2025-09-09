from app.Agents.open_redirect_agent import run_openredirect_agent
from app.models.open_redirect_models import OpenRedirectReport
from typing import Dict, Any
import time

async def run_openredirect_agent_service(target: str, mission_type: str = "comprehensive") -> Dict[str, Any]:
    """
    Runs the redirect agent and returns the resulting report dict for REST API.
    """
    print(f"Starting scan for target: {target} with mission type: {mission_type}")
    
    try:
        print("Starting scan...")
        result = await run_openredirect_agent(target, mission_type)
        print(f"Scan completed with result type: {type(result)}")
        print(f"Raw scan result content: {result}")

        # Handle empty results
        if not result:
            print("Warning: Empty result received from agent")
            return {
                "scan_id": f"scan_{str(abs(hash(target)))[:8]}",
                "target_url": target,
                "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration": 0.0,
                "status": "ERROR",
                "vulnerabilities": [],
                "tests_performed": 0,
                "parameters_tested": [],
                "error_message": "Scan returned no results",
                "metadata": {
                    "is_vulnerable": False,
                    "mission_type": mission_type
                }
            }

        # Handle non-dict results 
        if not isinstance(result, dict):
            print(f"Warning: Unexpected result type: {type(result)}")
            
            try:
                result = dict(result)
            except:
                result = {"raw_result": str(result)}

        vulnerabilities = []
        raw_vulnerabilities = result.get('vulnerabilities', [])
        print(f"Processing {len(raw_vulnerabilities)} vulnerabilities")
        
        print(f"Processing {len(raw_vulnerabilities)} vulnerabilities")
        for vuln in raw_vulnerabilities:
            try:
                if isinstance(vuln, dict):
                    print(f"Processing dictionary vulnerability: {vuln}")
                    vulnerabilities.append(vuln)
                else:
                    print(f"Converting object vulnerability to dict: {vuln}")
                    # More flexible conversion with fallbacks
                    vuln_dict = {
                        'url': getattr(vuln, 'url', ''),
                        'parameter': getattr(vuln, 'parameter_name', ''),
                        'payload': getattr(vuln, 'payload', ''),
                        'type': getattr(vuln.redirect_type, 'value', str(getattr(vuln, 'redirect_type', 'Unknown'))),
                        'destination': getattr(vuln, 'final_destination', ''),
                        'severity': getattr(vuln.vulnerability_level, 'value', str(getattr(vuln, 'vulnerability_level', 'LOW'))),
                        'confidence': float(getattr(vuln, 'confidence_score', 0.0)),
                        'timestamp': str(getattr(vuln, 'timestamp', time.strftime("%Y-%m-%d %H:%M:%S")))
                    }
                    print(f"Converted vulnerability: {vuln_dict}")
                    vulnerabilities.append(vuln_dict)
            except Exception as e:
                print(f"Error processing vulnerability: {str(e)}")
                print(f"Vulnerability data: {vuln}")
                print(f"Traceback: {traceback.format_exc()}")
                # Add partial data if possible
                try:
                    vulnerabilities.append({
                        'url': str(vuln),
                        'error': str(e),
                        'severity': 'ERROR',
                        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                    })
                except:
                    pass
        
        # Convert result to OpenRedirectReport format
        duration_str = result.get('duration', '0')
        if isinstance(duration_str, str):
            duration = float(duration_str.replace('s', ''))
        else:
            duration = float(duration_str)

        report = {
            "scan_id": f"scan_{str(abs(hash(target)))[:8]}",
            "target_url": target,
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": duration,
            "status": result.get('status', 'COMPLETED'),
            "vulnerabilities": vulnerabilities,
            "tests_performed": result.get('tests_performed', 0),
            "parameters_tested": result.get('analysis', {}).get('redirect_params_found', []),
            "error_message": result.get('error'),
            "metadata": {
                "is_vulnerable": result.get('is_vulnerable', False),
                "mission_type": mission_type
            }
        }
        return report

    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        print(f"Error in service: {str(e)}")
        print(f"Traceback: {error_detail}")
        
        # Return structured error response instead of raising
        return {
            "scan_id": f"scan_{str(abs(hash(target)))[:8]}",
            "target_url": target,
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": 0.0,
            "status": "ERROR",
            "vulnerabilities": [],
            "tests_performed": 0,
            "parameters_tested": [],
            "error_message": str(e),
            "metadata": {
                "is_vulnerable": False,
                "mission_type": mission_type,
                "error_detail": error_detail
            }
        }
    
