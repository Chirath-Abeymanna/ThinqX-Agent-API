"""
SQL Injection Assessment Agent
Main agent that orchestrates the complete SQL injection assessment workflow
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs
import aiohttp
from bs4 import BeautifulSoup
import colorama
from colorama import Fore, Style

try:
    from .sqli import AgentState, TargetInfo, InjectionResult, InjectionType
    from .injection_engine import SQLInjectionEngine
    from .payloads import SQLInjectionPayloads
except ImportError:
    from sqli import AgentState, TargetInfo, InjectionResult, InjectionType
    from injection_engine import SQLInjectionEngine
    from payloads import SQLInjectionPayloads

logger = logging.getLogger(__name__)

class SQLInjectionAgent:
    """Main SQL injection assessment agent"""
    
    def __init__(self):
        self.engine = SQLInjectionEngine()
        self.payloads = SQLInjectionPayloads()
    
    async def run_assessment(self, target_url: str) -> Dict[str, Any]:
        """Run the complete SQL injection assessment"""
        print(f"{Fore.CYAN}[+] Starting SQL Injection Assessment{Style.RESET_ALL}")
        print(f"Target: {target_url}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Initialize state
        state = AgentState(
            target_url=target_url,
            messages=[
                {"role": "system", "content": "You are a SQL injection assessment agent. Perform comprehensive testing to identify vulnerabilities."}
            ]
        )
        
        try:
            # Phase 1: Reconnaissance
            state = await self._reconnaissance_phase(state)
            
            # Phase 2: Parameter Discovery
            state = await self._parameter_discovery_phase(state)
            
            # Phase 3: Injection Testing
            state = await self._injection_testing_phase(state)
            
            # Phase 4: Vulnerability Analysis
            state = await self._vulnerability_analysis_phase(state)
            
            # Phase 5: Report Generation
            state = await self._report_generation_phase(state)
            
            return {
                'success': True,
                'state': state,
                'report': {
                    'target_url': target_url,
                    'confidence_score': state.confidence_score,
                    'vulnerable_parameters': state.vulnerable_parameters,
                    'recommendations': state.recommendations
                }
            }
        except Exception as e:
            print(f"{Fore.RED}[-] Assessment failed: {str(e)}{Style.RESET_ALL}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _reconnaissance_phase(self, state: AgentState) -> AgentState:
        """Phase 1: Reconnaissance and target analysis"""
        print(f"{Fore.CYAN}[+] Starting reconnaissance phase for: {state.target_url}{Style.RESET_ALL}")
        
        try:
            # Parse the target URL
            parsed_url = urlparse(state.target_url)
            
            # Create target info
            target_info = TargetInfo(
                url=state.target_url,
                method="GET",  # Default to GET, will be updated if needed
                parameters={},
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                },
                cookies={}
            )
            
            # Extract parameters from URL
            query_params = parse_qs(parsed_url.query)
            for key, values in query_params.items():
                target_info.parameters[key] = values[0] if values else ""
            
            # Test if the target is accessible
            async with aiohttp.ClientSession() as session:
                async with session.get(state.target_url, headers=target_info.headers) as response:
                    if response.status == 200:
                        print(f"{Fore.GREEN}[+] Target is accessible{Style.RESET_ALL}")
                        
                        # Extract forms and parameters
                        content = await response.text()
                        forms_data = await self._extract_forms(content, state.target_url)
                        
                        # Update target info with discovered forms
                        if forms_data:
                            target_info.parameters.update(forms_data.get('parameters', {}))
                            target_info.method = forms_data.get('method', 'GET')
                        
                        state.target_info = target_info
                        state.discovered_parameters = list(target_info.parameters.keys())
                        
                        # Add message to state
                        state.messages.append(
                            {"role": "assistant", "content": f"Reconnaissance completed. Discovered {len(state.discovered_parameters)} parameters."}
                        )
                    else:
                        print(f"{Fore.RED}[-] Target returned status code: {response.status}{Style.RESET_ALL}")
                        state.messages.append(
                            {"role": "assistant", "content": f"Target reconnaissance failed with status code: {response.status}"}
                        )
        
        except Exception as e:
            print(f"{Fore.RED}[-] Reconnaissance error: {str(e)}{Style.RESET_ALL}")
            state.messages.append(
                {"role": "assistant", "content": f"Reconnaissance error: {str(e)}"}
            )
        
        state.current_phase = "parameter_discovery"
        return state
    
    async def _extract_forms(self, content: str, base_url: str) -> Dict[str, Any]:
        """Extract forms and their parameters from HTML content"""
        soup = BeautifulSoup(content, 'html.parser')
        forms = soup.find_all('form')
        
        form_data = {
            'parameters': {},
            'method': 'GET'
        }
        
        for form in forms:
            method = form.get('method', 'GET').upper()
            action = form.get('action', '')
            
            # If no action, use the current URL
            if not action:
                action = base_url
            
            # Extract form inputs
            inputs = form.find_all(['input', 'textarea', 'select'])
            for input_elem in inputs:
                input_name = input_elem.get('name')
                input_type = input_elem.get('type', 'text')
                input_value = input_elem.get('value', '')
                
                if input_name and input_type not in ['submit', 'button', 'image']:
                    form_data['parameters'][input_name] = input_value
            
            form_data['method'] = method
            break  # For now, just use the first form
        
        return form_data
    
    async def _parameter_discovery_phase(self, state: AgentState) -> AgentState:
        """Phase 2: Discover and analyze parameters"""
        print(f"{Fore.CYAN}[+] Starting parameter discovery phase{Style.RESET_ALL}")
        
        if not state.target_info:
            print(f"{Fore.RED}[-] No target info available{Style.RESET_ALL}")
            state.current_phase = "injection_testing"
            return state
        
        # Analyze discovered parameters
        parameter_analysis = []
        for param in state.discovered_parameters:
            analysis = {
                'name': param,
                'type': self._classify_parameter(param),
                'risk_level': self._assess_parameter_risk(param),
                'suggested_payloads': self.payloads.get_payloads_for_parameter(param)
            }
            parameter_analysis.append(analysis)
            
            print(f"{Fore.YELLOW}[*] Parameter: {param} - Type: {analysis['type']} - Risk: {analysis['risk_level']}{Style.RESET_ALL}")
        
        # Add high-risk parameters to vulnerable list
        high_risk_params = [p['name'] for p in parameter_analysis if p['risk_level'] == 'high']
        state.vulnerable_parameters.extend(high_risk_params)
        
        state.messages.append(
            {"role": "assistant", "content": f"Parameter discovery completed. Found {len(state.discovered_parameters)} parameters, {len(high_risk_params)} high-risk."}
        )
        
        state.current_phase = "injection_testing"
        return state
    
    def _classify_parameter(self, param_name: str) -> str:
        """Classify parameter based on its name"""
        param_lower = param_name.lower()
        
        if any(keyword in param_lower for keyword in ['user', 'username', 'login', 'email']):
            return 'authentication'
        elif any(keyword in param_lower for keyword in ['pass', 'password', 'pwd']):
            return 'authentication'
        elif any(keyword in param_lower for keyword in ['id', 'user_id', 'uid']):
            return 'identifier'
        elif any(keyword in param_lower for keyword in ['search', 'query', 'q', 'keyword']):
            return 'search'
        elif any(keyword in param_lower for keyword in ['page', 'offset', 'limit']):
            return 'pagination'
        else:
            return 'generic'
    
    def _assess_parameter_risk(self, param_name: str) -> str:
        """Assess the risk level of a parameter"""
        param_lower = param_name.lower()
        
        # High-risk parameters
        if any(keyword in param_lower for keyword in ['user', 'pass', 'login', 'auth', 'id']):
            return 'high'
        
        # Medium-risk parameters
        elif any(keyword in param_lower for keyword in ['search', 'query', 'q', 'keyword']):
            return 'medium'
        
        # Low-risk parameters
        else:
            return 'low'
    
    async def _injection_testing_phase(self, state: AgentState) -> AgentState:
        """Phase 3: Perform SQL injection testing"""
        print(f"{Fore.CYAN}[+] Starting injection testing phase{Style.RESET_ALL}")
        
        if not state.target_info or not state.discovered_parameters:
            print(f"{Fore.RED}[-] No parameters to test{Style.RESET_ALL}")
            state.current_phase = "vulnerability_analysis"
            return state
        
        total_tests = 0
        successful_injections = 0
        
        # Test each parameter
        for param_name in state.discovered_parameters:
            print(f"{Fore.YELLOW}[*] Testing parameter: {param_name}{Style.RESET_ALL}")
            
            # Get comprehensive payloads for this parameter based on risk level
            risk_level = self._assess_parameter_risk(param_name)
            if risk_level == 'high':
                payloads = self.payloads.get_comprehensive_payloads_for_parameter(param_name)
                print(f"  Using comprehensive payload set ({len(payloads)} payloads) for high-risk parameter")
            else:
                payloads = self.payloads.get_payloads_for_parameter(param_name)
                print(f"  Using standard payload set ({len(payloads)} payloads) for {risk_level}-risk parameter")
            
            # Test with different injection types
            for injection_type in InjectionType:
                type_payloads = self.payloads.get_payloads_by_type(injection_type)
                
                # Test more payloads of each type for comprehensive testing
                payload_limit = 12 if risk_level == 'high' else 8  # More payloads for high-risk parameters
                for payload in type_payloads[:payload_limit]:
                    total_tests += 1
                    
                    print(f"  Testing: {injection_type.value} - {payload[:50]}...")
                    
                    result = await self.engine.test_parameter(
                        state.target_info, param_name, payload, injection_type
                    )
                    
                    state.injection_results.append(result)
                    
                    if result.success:
                        successful_injections += 1
                        print(f"{Fore.GREEN}[+] SUCCESS: {injection_type.value} injection detected!{Style.RESET_ALL}")
                        print(f"    Payload: {payload}")
                        print(f"    Confidence: {result.confidence}")
                        
                        if result.extracted_data:
                            print(f"    Extracted data: {result.extracted_data}")
                        
                        if result.error_message:
                            print(f"    Error: {result.error_message}")
                        
                        # Add to vulnerable parameters if not already there
                        if param_name not in state.vulnerable_parameters:
                            state.vulnerable_parameters.append(param_name)
                    
                    # Small delay to avoid overwhelming the server
                    await asyncio.sleep(0.1)
        
        print(f"{Fore.CYAN}[+] Injection testing completed{Style.RESET_ALL}")
        print(f"  Total tests: {total_tests}")
        print(f"  Successful injections: {successful_injections}")
        print(f"  Success rate: {(successful_injections/total_tests)*100:.2f}%" if total_tests > 0 else "N/A")
        
        state.messages.append(
            {"role": "assistant", "content": f"Injection testing completed. {successful_injections}/{total_tests} successful injections."}
        )
        
        state.current_phase = "vulnerability_analysis"
        return state
    
    async def _vulnerability_analysis_phase(self, state: AgentState) -> AgentState:
        """Phase 4: Analyze vulnerabilities and calculate risk scores"""
        print(f"{Fore.CYAN}[+] Starting vulnerability analysis phase{Style.RESET_ALL}")
        
        # Analyze injection results
        analysis = self.engine.analyze_results(state.injection_results)
        
        # Calculate overall confidence score
        if analysis['successful_injections'] > 0:
            state.confidence_score = analysis['average_confidence']
        else:
            state.confidence_score = 0.0
        
        # Generate recommendations
        recommendations = []
        
        if analysis['successful_injections'] > 0:
            recommendations.append("CRITICAL: SQL injection vulnerabilities detected!")
            recommendations.append("Immediate action required to secure the application")
            
            if 'mysql' in str(analysis.get('error_messages', [])):
                recommendations.append("MySQL database detected - implement proper input validation")
            elif 'postgresql' in str(analysis.get('error_messages', [])):
                recommendations.append("PostgreSQL database detected - implement proper input validation")
            
            recommendations.append("Use parameterized queries or prepared statements")
            recommendations.append("Implement input validation and sanitization")
            recommendations.append("Consider using an ORM framework")
        else:
            recommendations.append("No SQL injection vulnerabilities detected in this assessment")
            recommendations.append("Continue regular security testing")
            recommendations.append("Consider implementing additional security measures")
        
        state.recommendations = recommendations
        
        print(f"{Fore.CYAN}[+] Vulnerability analysis completed{Style.RESET_ALL}")
        print(f"  Confidence score: {state.confidence_score:.2f}")
        print(f"  Vulnerable parameters: {len(state.vulnerable_parameters)}")
        print(f"  Recommendations: {len(recommendations)}")
        
        state.messages.append(
            {"role": "assistant", "content": f"Vulnerability analysis completed. Confidence: {state.confidence_score:.2f}"}
        )
        
        state.current_phase = "report_generation"
        return state
    
    async def _report_generation_phase(self, state: AgentState) -> AgentState:
        """Phase 5: Generate comprehensive report"""
        print(f"{Fore.CYAN}[+] Generating comprehensive report{Style.RESET_ALL}")
        
        # Create detailed report
        report = {
            'target_url': state.target_url,
            'assessment_summary': {
                'total_parameters_tested': len(state.discovered_parameters),
                'vulnerable_parameters': len(state.vulnerable_parameters),
                'total_injection_tests': len(state.injection_results),
                'successful_injections': len([r for r in state.injection_results if r.success]),
                'confidence_score': state.confidence_score,
                'risk_level': self._calculate_risk_level(state.confidence_score)
            },
            'vulnerable_parameters': state.vulnerable_parameters,
            'successful_injections': [
                {
                    'parameter': 'N/A',  # Would need to track this in results
                    'payload': r.payload,
                    'type': r.injection_type.value,
                    'confidence': r.confidence,
                    'extracted_data': r.extracted_data,
                    'error_message': r.error_message
                }
                for r in state.injection_results if r.success
            ],
            'recommendations': state.recommendations,
            'technical_details': {
                'discovered_parameters': state.discovered_parameters,
                'all_test_results': [
                    {
                        'payload': r.payload,
                        'type': r.injection_type.value,
                        'success': r.success,
                        'response_time': r.response_time,
                        'confidence': r.confidence
                    }
                    for r in state.injection_results
                ]
            }
        }
        
        # Save report to file
        report_filename = f"sql_injection_report_{int(time.time())}.json"
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}[+] Report saved to: {report_filename}{Style.RESET_ALL}")
        
        # Print summary
        self._print_summary(report)
        
        state.messages.append(
            {"role": "assistant", "content": f"Report generation completed. Report saved to {report_filename}"}
        )
        
        return state
    
    def _calculate_risk_level(self, confidence_score: float) -> str:
        """Calculate risk level based on confidence score"""
        if confidence_score >= 0.8:
            return 'CRITICAL'
        elif confidence_score >= 0.6:
            return 'HIGH'
        elif confidence_score >= 0.4:
            return 'MEDIUM'
        elif confidence_score >= 0.2:
            return 'LOW'
        else:
            return 'NONE'
    
    def _print_summary(self, report: Dict[str, Any]):
        """Print a summary of the assessment results"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"SQL INJECTION ASSESSMENT SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        summary = report['assessment_summary']
        
        print(f"Target URL: {report['target_url']}")
        print(f"Risk Level: {Fore.RED if summary['risk_level'] in ['CRITICAL', 'HIGH'] else Fore.GREEN}{summary['risk_level']}{Style.RESET_ALL}")
        print(f"Confidence Score: {summary['confidence_score']:.2f}")
        print(f"Parameters Tested: {summary['total_parameters_tested']}")
        print(f"Vulnerable Parameters: {summary['vulnerable_parameters']}")
        print(f"Successful Injections: {summary['successful_injections']}")
        
        if report['vulnerable_parameters']:
            print(f"\n{Fore.RED}Vulnerable Parameters:{Style.RESET_ALL}")
            for param in report['vulnerable_parameters']:
                print(f"  - {param}")
        
        if report['recommendations']:
            print(f"\n{Fore.YELLOW}Recommendations:{Style.RESET_ALL}")
            for rec in report['recommendations']:
                print(f"  - {rec}")
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}") 