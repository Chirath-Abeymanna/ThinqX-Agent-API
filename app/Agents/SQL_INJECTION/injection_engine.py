"""
SQL Injection Testing Engine
Core engine for detecting and analyzing SQL injection vulnerabilities
"""

import asyncio
import re
import time
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode
import aiohttp
from bs4 import BeautifulSoup

try:
    from .sqli import InjectionType, InjectionResult, TargetInfo
    from .payloads import SQLInjectionPayloads
except ImportError:
    from sqli import InjectionType, InjectionResult, TargetInfo
    from payloads import SQLInjectionPayloads

class SQLInjectionEngine:
    """Core engine for SQL injection testing"""
    
    def __init__(self):
        self.payloads = SQLInjectionPayloads()
        self.error_patterns = self._load_error_patterns()
        self.success_patterns = self._load_success_patterns()
        self.timeout = 10
        self.delay_threshold = 3.0  # Seconds to consider time-based injection successful
        
    def _load_error_patterns(self) -> Dict[str, List[str]]:
        """Load database-specific error patterns"""
        return {
            'mysql': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_.*',
                r'valid MySQL result',
                r'MySqlClient\.',
                r'com\.mysql\.jdbc',
                r'MySQLSyntaxErrorException',
                r'You have an error in your SQL syntax',
                r'MySQL server version',
            ],
            'postgresql': [
                r'PostgreSQL.*ERROR',
                r'Warning.*\Wpg_.*',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'PG::SyntaxError:',
                r'org\.postgresql\.util\.PSQLException',
                r'ERROR: syntax error at or near',
            ],
            'mssql': [
                r'Driver.* SQL[\-\_\ ]*Server',
                r'OLE DB.* SQL Server',
                r'(\W|\A)SQL Server[^<]*Driver',
                r'Warning.*mssql_.*',
                r'(\W|\A)SQL Server[^<]*[0-9a-zA-Z]',
                r'System\.Data\.SqlClient\.',
                r'(?i)SQL Server[^<]*Driver',
                r'Msg \d+, Level \d+, State \d+',
            ],
            'oracle': [
                r'\bORA-[0-9][0-9][0-9][0-9]',
                r'Oracle error',
                r'Oracle.*Driver',
                r'Warning.*\Woci_.*',
                r'Microsoft OLE DB Provider for Oracle',
                r'quoted string not properly terminated',
            ],
            'sqlite': [
                r'SQLite/JDBCDriver',
                r'SQLite\.Exception',
                r'System\.Data\.SQLite',
                r'Warning.*sqlite_.*',
                r'\[SQLITE_ERROR\]',
            ],
            'generic': [
                r'SQL syntax.*',
                r'quoted string not properly terminated',
                r'unclosed quotation mark after the character string',
                r'SQLSTATE[0-9]+',
                r'Server Error in',
                r'Microsoft OLE DB Provider for',
                r'Unclosed quotation mark after the character string',
            ]
        }
    
    def _load_success_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that indicate successful injection"""
        return {
            'authentication_bypass': [
                r'welcome.*admin',
                r'logged in',
                r'authentication successful',
                r'dashboard',
                r'logout',
                r'profile',
            ],
            'data_extraction': [
                r'root:',
                r'admin:',
                r'password:',
                r'username:',
                r'email:',
                r'user_id:',
            ],
            'database_info': [
                r'MySQL.*[0-9]+\.[0-9]+\.[0-9]+',
                r'PostgreSQL.*[0-9]+\.[0-9]+\.[0-9]+',
                r'SQL Server.*[0-9]+\.[0-9]+\.[0-9]+',
                r'Oracle.*[0-9]+\.[0-9]+\.[0-9]+',
            ]
        }
    
    async def test_parameter(self, target_info: TargetInfo, param_name: str, 
                           payload: str, injection_type: InjectionType) -> InjectionResult:
        """Test a single parameter with a specific payload"""
        start_time = time.time()
        
        # Prepare the test data
        test_params = target_info.parameters.copy()
        test_params[param_name] = payload
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                if target_info.method.upper() == 'GET':
                    url = self._build_url(target_info.url, test_params)
                    async with session.get(url, headers=target_info.headers, 
                                         cookies=target_info.cookies) as response:
                        return await self._analyze_response(response, payload, injection_type, start_time)
                
                elif target_info.method.upper() == 'POST':
                    async with session.post(target_info.url, data=test_params, 
                                          headers=target_info.headers, 
                                          cookies=target_info.cookies) as response:
                        return await self._analyze_response(response, payload, injection_type, start_time)
                
                else:
                    return InjectionResult(
                        payload=payload,
                        injection_type=injection_type,
                        success=False,
                        response_time=time.time() - start_time,
                        response_size=0,
                        error_message="Unsupported HTTP method"
                    )
                    
        except Exception as e:
            return InjectionResult(
                payload=payload,
                injection_type=injection_type,
                success=False,
                response_time=time.time() - start_time,
                response_size=0,
                error_message=str(e)
            )
    
    async def _analyze_response(self, response: aiohttp.ClientResponse, payload: str, 
                              injection_type: InjectionType, start_time: float) -> InjectionResult:
        """Analyze the response for signs of SQL injection"""
        response_time = time.time() - start_time
        response_text = await response.text()
        response_size = len(response_text)
        
        # Check for time-based injection
        if injection_type == InjectionType.TIME_BASED:
            if response_time > self.delay_threshold:
                return InjectionResult(
                    payload=payload,
                    injection_type=injection_type,
                    success=True,
                    response_time=response_time,
                    response_size=response_size,
                    confidence=0.8
                )
        
        # Check for error-based injection
        elif injection_type == InjectionType.ERROR_BASED:
            detected_db = self._detect_database_from_errors(response_text)
            if detected_db:
                return InjectionResult(
                    payload=payload,
                    injection_type=injection_type,
                    success=True,
                    response_time=response_time,
                    response_size=response_size,
                    error_message=f"Database detected: {detected_db}",
                    confidence=0.9
                )
        
        # Check for boolean-based injection
        elif injection_type == InjectionType.BOOLEAN_BASED:
            if self._detect_boolean_injection(response_text, response.status):
                return InjectionResult(
                    payload=payload,
                    injection_type=injection_type,
                    success=True,
                    response_time=response_time,
                    response_size=response_size,
                    confidence=0.7
                )
        
        # Check for union-based injection
        elif injection_type == InjectionType.UNION_BASED:
            extracted_data = self._extract_data_from_union(response_text)
            if extracted_data:
                return InjectionResult(
                    payload=payload,
                    injection_type=injection_type,
                    success=True,
                    response_time=response_time,
                    response_size=response_size,
                    extracted_data=extracted_data,
                    confidence=0.95
                )
        
        # Check for success patterns
        success_pattern = self._check_success_patterns(response_text)
        if success_pattern:
            return InjectionResult(
                payload=payload,
                injection_type=injection_type,
                success=True,
                response_time=response_time,
                response_size=response_size,
                confidence=0.6
            )
        
        return InjectionResult(
            payload=payload,
            injection_type=injection_type,
            success=False,
            response_time=response_time,
            response_size=response_size
        )
    
    def _detect_database_from_errors(self, response_text: str) -> Optional[str]:
        """Detect database type from error messages"""
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return db_type
        return None
    
    def _detect_boolean_injection(self, response_text: str, status_code: int) -> bool:
        """Detect boolean-based injection by comparing responses"""
        # This would typically compare with a baseline response
        # For now, we'll use some heuristics
        suspicious_indicators = [
            'true' in response_text.lower(),
            'false' in response_text.lower(),
            '1' in response_text,
            '0' in response_text,
            status_code == 200,  # Successful response
        ]
        return sum(suspicious_indicators) >= 2
    
    def _extract_data_from_union(self, response_text: str) -> Optional[str]:
        """Extract data from union-based injection responses"""
        # Look for common data patterns
        data_patterns = [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP address
            r'[a-zA-Z0-9]{8,}',  # Long alphanumeric strings (passwords)
        ]
        
        for pattern in data_patterns:
            matches = re.findall(pattern, response_text)
            if matches:
                return ', '.join(matches[:5])  # Return first 5 matches
        return None
    
    def _check_success_patterns(self, response_text: str) -> Optional[str]:
        """Check for success patterns in the response"""
        for pattern_type, patterns in self.success_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return pattern_type
        return None
    
    def _build_url(self, base_url: str, params: Dict[str, str]) -> str:
        """Build URL with parameters"""
        parsed = urlparse(base_url)
        query_dict = parse_qs(parsed.query)
        
        # Update with test parameters
        for key, value in params.items():
            query_dict[key] = [value]
        
        # Rebuild query string
        new_query = urlencode(query_dict, doseq=True)
        
        # Rebuild URL
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    async def test_parameter_comprehensive(self, target_info: TargetInfo, param_name: str) -> List[InjectionResult]:
        """Test a parameter with multiple injection techniques"""
        results = []
        
        # Get relevant payloads for this parameter
        payloads = self.payloads.get_payloads_for_parameter(param_name)
        
        # Test with different injection types
        for injection_type in InjectionType:
            type_payloads = self.payloads.get_payloads_by_type(injection_type)
            
            # Test first few payloads of each type
            for payload in type_payloads[:3]:  # Limit to 3 payloads per type for efficiency
                result = await self.test_parameter(target_info, param_name, payload, injection_type)
                results.append(result)
                
                # If we found a successful injection, we can be more confident
                if result.success:
                    break
        
        return results
    
    def analyze_results(self, results: List[InjectionResult]) -> Dict[str, Any]:
        """Analyze injection test results and provide summary"""
        successful_injections = [r for r in results if r.success]
        
        analysis = {
            'total_tests': len(results),
            'successful_injections': len(successful_injections),
            'success_rate': len(successful_injections) / len(results) if results else 0,
            'vulnerable_techniques': list(set(r.injection_type for r in successful_injections)),
            'average_confidence': sum(r.confidence for r in successful_injections) / len(successful_injections) if successful_injections else 0,
            'extracted_data': [r.extracted_data for r in successful_injections if r.extracted_data],
            'error_messages': [r.error_message for r in successful_injections if r.error_message],
        }
        
        return analysis 