#!/usr/bin/env python3
"""
Enhanced Open Redirect Detection Tool
Automatically detects open redirect vulnerabilities in web applications
Usage: python open_redirect.py <URL>
"""

import asyncio
import aiohttp
import re
import sys
import ssl
import warnings
import json
import time
import argparse
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote
from bs4 import BeautifulSoup
from enum import Enum
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich import box

# Disable SSL warnings
warnings.filterwarnings('ignore')
ssl._create_default_https_context = ssl._create_unverified_context

# Initialize Rich console
console = Console()

class VulnerabilityLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RedirectType(Enum):
    HEADER_BASED = "Header-Based"
    JAVASCRIPT_BASED = "JavaScript-Based"
    META_TAG_BASED = "Meta-Tag-Based"
    FORM_BASED = "Form-Based"

@dataclass
class RedirectVulnerability:
    url: str
    payload: str
    redirect_type: RedirectType
    final_destination: str
    vulnerability_level: VulnerabilityLevel
    response_code: int
    parameter_name: str = ""
    sources_sinks: List[str] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

class OpenRedirectDetector:
    def __init__(self, timeout: int = 10, max_concurrent: int = 20):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.user_agent = "OpenRedirectDetector/2.0 (Security Scanner)"
        
        # Common redirect parameter names
        self.redirect_params = [
            'url', 'redirect', 'next', 'return', 'goto', 'destination', 'forward',
            'continue', 'redir', 'target', 'link', 'page', 'site', 'domain',
            'redirect_url', 'redirect_uri', 'return_url', 'next_page', 'callback',
            'successUrl', 'failureUrl', 'returnUrl', 'targetUrl', 'backUrl'
        ]
        
        # Test payloads for open redirect detection
        self.test_payloads = [
            # Basic external redirects
            "http://evil.com",
            "https://evil.com", 
            "//evil.com",
            "///evil.com",
            "////evil.com",
            
            # Encoded variants
            "http%3A%2F%2Fevil.com",
            "https%3A%2F%2Fevil.com",
            "%2F%2Fevil.com",
            
            # Protocol manipulation
            "https:evil.com",
            "HtTP://evil.com",
            
            # Path traversal attempts
            "//evil.com/%2f..",
            "///evil.com/%2f..",
            "//evil.com/%2e%2e",
            
            # Bypass attempts
            "javascript:alert('XSS');//evil.com",
            "/\\evil.com",
            "/.evil.com",
            
            # Google.com as benign test
            "http://google.com",
            "https://google.com",
            "//google.com"
        ]
        
        self.findings: List[RedirectVulnerability] = []
        self.tested_combinations: Set[str] = set()

    def display_banner(self):
        """Display tool banner"""
        banner = """
[bold red]
 ██████╗ ██████╗ ███████╗███╗   ██║    ██████╗ ███████╗██████╗ ██╗██████╗ ███████╗ ██████╗████████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║    ██╔══██╗██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔════╝╚══██╔══╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║    ██████╔╝█████╗  ██║  ██║██║██████╔╝█████╗  ██║        ██║   
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║    ██╔══██╗██╔══╝  ██║  ██║██║██╔══██╗██╔══╝  ██║        ██║   
╚██████╔╝██║     ███████╗██║ ╚████║    ██║  ██║███████╗██████╔╝██║██║  ██║███████╗╚██████╗   ██║   
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═╝   
[/bold red]
[bold cyan]                           🔍 Open Redirect Vulnerability Scanner 🔍[/bold cyan]
[dim]                                Automatically detects redirect vulnerabilities[/dim]
        """
        console.print(Panel(banner, box=box.DOUBLE))

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL to determine testing strategy"""
        parsed = urlparse(url)
        existing_params = dict(parse_qsl(parsed.query))
        
        analysis = {
            'original_url': url,
            'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            'existing_params': existing_params,
            'redirect_params_found': [],
            'test_urls': []
        }
        
        # Check if any existing parameters are redirect-related
        for param_name in existing_params.keys():
            if param_name.lower() in [rp.lower() for rp in self.redirect_params]:
                analysis['redirect_params_found'].append(param_name)
        
        # Generate test URLs
        test_params_to_use = analysis['redirect_params_found'] if analysis['redirect_params_found'] else self.redirect_params[:10]
        
        for param_name in test_params_to_use:
            # Create URL with this parameter
            test_params = existing_params.copy()
            test_params[param_name] = "PLACEHOLDER"
            
            new_query = urlencode(test_params)
            test_url = f"{analysis['base_url']}?{new_query}"
            analysis['test_urls'].append((test_url, param_name))
        
        return analysis

    async def test_single_combination(self, session: aiohttp.ClientSession, 
                                    base_url: str, param_name: str, payload: str) -> Optional[RedirectVulnerability]:
        """Test a single URL + parameter + payload combination"""
        
        test_url = base_url.replace("PLACEHOLDER", payload)
        
        # Avoid duplicate tests
        test_key = f"{test_url}_{payload}"
        if test_key in self.tested_combinations:
            return None
        self.tested_combinations.add(test_key)
        
        try:
            async with session.get(test_url, allow_redirects=False, timeout=self.timeout) as response:
                return await self._analyze_response(response, test_url, payload, param_name)
        except Exception:
            return None

    async def _analyze_response(self, response: aiohttp.ClientResponse, 
                              test_url: str, payload: str, param_name: str) -> Optional[RedirectVulnerability]:
        """Analyze HTTP response for redirect vulnerabilities"""
        
        vulnerability = None
        redirect_type = None
        final_destination = ""
        sources_sinks = []
        confidence_score = 0.0
        
        # Check for HTTP redirect headers
        if response.status in range(300, 400):
            location = response.headers.get('Location', '')
            if location and self._is_payload_reflected(payload, location):
                redirect_type = RedirectType.HEADER_BASED
                final_destination = location
                confidence_score = self._calculate_confidence_score(payload, location, 'header')
                
        # Check response body for JavaScript/Meta redirects
        elif response.status == 200:
            try:
                content = await response.text()
                
                # Check for JavaScript redirects
                js_redirect = self._check_javascript_redirect(content, payload)
                if js_redirect:
                    redirect_type = RedirectType.JAVASCRIPT_BASED
                    final_destination = js_redirect['destination']
                    sources_sinks = js_redirect['sources_sinks']
                    confidence_score = self._calculate_confidence_score(payload, final_destination, 'javascript')
                
                # Check for meta tag redirects
                soup = BeautifulSoup(content, 'html.parser')
                meta_redirect = self._check_meta_redirect(soup, payload)
                if meta_redirect:
                    redirect_type = RedirectType.META_TAG_BASED
                    final_destination = meta_redirect
                    confidence_score = self._calculate_confidence_score(payload, final_destination, 'meta')
                    
            except Exception:
                pass
        
        # Create vulnerability if found
        if redirect_type and final_destination and confidence_score > 0.3:
            vulnerability_level = self._assess_vulnerability_level(payload, final_destination, confidence_score)
            
            vulnerability = RedirectVulnerability(
                url=test_url,
                payload=payload,
                redirect_type=redirect_type,
                final_destination=final_destination,
                vulnerability_level=vulnerability_level,
                response_code=response.status,
                parameter_name=param_name,
                sources_sinks=sources_sinks,
                confidence_score=confidence_score
            )
            
        return vulnerability

    def _is_payload_reflected(self, payload: str, destination: str) -> bool:
        """Check if payload is reflected in destination"""
        # Direct match
        if payload in destination:
            return True
        
        # Check for URL encoded versions
        encoded_payload = quote(payload, safe='')
        if encoded_payload in destination:
            return True
        
        # Extract domain from payload and check if it's in destination
        try:
            payload_parsed = urlparse(payload if payload.startswith('http') else f'http://{payload}')
            if payload_parsed.netloc and payload_parsed.netloc in destination:
                return True
        except:
            pass
        
        return False

    def _check_javascript_redirect(self, content: str, payload: str) -> Optional[Dict[str, Any]]:
        """Check for JavaScript-based redirects"""
        if not self._is_payload_reflected(payload, content):
            return None
        
        # Common JavaScript redirect patterns
        js_patterns = [
            r'location\.href\s*=\s*["\']([^"\']*' + re.escape(payload) + r'[^"\']*)["\']',
            r'window\.location\s*=\s*["\']([^"\']*' + re.escape(payload) + r'[^"\']*)["\']',
            r'location\.replace\(["\']([^"\']*' + re.escape(payload) + r'[^"\']*)["\']\)',
            r'window\.open\(["\']([^"\']*' + re.escape(payload) + r'[^"\']*)["\']\)'
        ]
        
        for pattern in js_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return {
                    'destination': match.group(1),
                    'sources_sinks': ['location.href', 'window.location']
                }
        
        return None

    def _check_meta_redirect(self, soup: BeautifulSoup, payload: str) -> Optional[str]:
        """Check for meta tag redirects"""
        meta_tags = soup.find_all('meta', attrs={'http-equiv': 'refresh'})
        
        for meta in meta_tags:
            content = meta.get('content', '')
            if self._is_payload_reflected(payload, content):
                # Extract URL from content
                url_match = re.search(r'url=([^;]+)', content, re.IGNORECASE)
                if url_match:
                    return url_match.group(1)
        
        return None

    def _calculate_confidence_score(self, payload: str, destination: str, redirect_type: str) -> float:
        """Calculate confidence score for vulnerability"""
        score = 0.0
        
        # Base score by type
        type_scores = {'header': 0.9, 'javascript': 0.7, 'meta': 0.8}
        score += type_scores.get(redirect_type, 0.5)
        
        # Check if payload is clearly reflected
        if payload in destination:
            score += 0.4
        
        # Check if it's external redirect
        if self._is_external_redirect(destination):
            score += 0.3
        
        # Check for bypass techniques in payload
        bypass_patterns = ['@', '//', '///', '%2f', '%2e', 'javascript:']
        for pattern in bypass_patterns:
            if pattern in payload.lower():
                score += 0.1
        
        return min(score, 1.0)

    def _assess_vulnerability_level(self, payload: str, destination: str, confidence: float) -> VulnerabilityLevel:
        """Assess vulnerability severity level"""
        
        # Critical: High confidence external redirect
        if confidence >= 0.8 and self._is_external_redirect(destination):
            return VulnerabilityLevel.CRITICAL
        
        # High: External redirect or dangerous protocols
        if confidence >= 0.6 and (self._is_external_redirect(destination) or 
                                'javascript:' in destination.lower()):
            return VulnerabilityLevel.HIGH
        
        # Medium: Moderate confidence or suspicious patterns
        if confidence >= 0.5:
            return VulnerabilityLevel.MEDIUM
        
        return VulnerabilityLevel.LOW

    def _is_external_redirect(self, destination: str) -> bool:
        """Check if destination is external"""
        try:
            if destination.startswith('//'):
                return True
            parsed = urlparse(destination)
            return bool(parsed.netloc and '.' in parsed.netloc)
        except:
            return False

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Main scanning method"""
        start_time = time.time()
        print(f"Starting scan for URL: {url}")
        
        self.display_banner()
        console.print(f"\n[bold green]🎯 TARGET:[/bold green] [cyan]{url}[/cyan]")       
        try:
            # Analyze the URL
            analysis = self.analyze_url(url)
            
            if not analysis['test_urls']:
                console.print(f"[yellow]⚠️ No suitable parameters found for testing[/yellow]")
                console.print(f"[dim]Adding common redirect parameters for testing...[/dim]")
            
            total_tests = len(analysis['test_urls']) * len(self.test_payloads)
            console.print(f"[bold blue]🧪 Running {total_tests} tests...[/bold blue]")
            
            # Set up HTTP session
            connector = aiohttp.TCPConnector(limit=self.max_concurrent, ssl=False)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            vulnerabilities = []
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(),
                    console=console
                ) as progress:
                    
                    task = progress.add_task("Scanning for vulnerabilities...", total=total_tests)
                    
                    # Test all combinations
                    tasks = []
                    for test_url, param_name in analysis['test_urls']:
                        for payload in self.test_payloads:
                            task_coro = self._test_with_progress(session, test_url, param_name, payload, progress, task)
                            tasks.append(task_coro)
                    
                    # Execute all tests
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Collect valid vulnerabilities
                    for result in results:
                        if isinstance(result, RedirectVulnerability):
                            vulnerabilities.append(result)
                            self._display_vulnerability_found(result)
            
            duration = f"{time.time() - start_time:.2f}s"
            
            # Generate results
            results = {
                'status': 'SUCCESS',
                'target': url,
                'duration': duration,
                'tests_performed': total_tests,
                'vulnerabilities': vulnerabilities,
                'is_vulnerable': len(vulnerabilities) > 0,
                'analysis': analysis
            }
            
            self._display_results(results)
            print(f"Returning results with {len(vulnerabilities)} vulnerabilities")
            return results
            
        except Exception as e:
            return {
                'status': 'ERROR',
                'target': url,
                'error': str(e),
                'duration': f"{time.time() - start_time:.2f}s"
            }

    async def _test_with_progress(self, session: aiohttp.ClientSession, 
                                 test_url: str, param_name: str, payload: str,
                                 progress: Progress, task_id) -> Optional[RedirectVulnerability]:
        """Test with progress tracking"""
        try:
            result = await self.test_single_combination(session, test_url, param_name, payload)
            progress.advance(task_id)
            return result
        except:
            progress.advance(task_id)
            return None

    def _display_vulnerability_found(self, vuln: RedirectVulnerability):
        """Display found vulnerability"""
        severity_colors = {
            VulnerabilityLevel.CRITICAL: "bold red",
            VulnerabilityLevel.HIGH: "red", 
            VulnerabilityLevel.MEDIUM: "yellow",
            VulnerabilityLevel.LOW: "blue"
        }
        
        severity_color = severity_colors.get(vuln.vulnerability_level, "white")
        console.print(f"\n[{severity_color}]🚨 VULNERABILITY FOUND![/{severity_color}]")
        console.print(f"🔍 Type: [{severity_color}]{vuln.redirect_type.value}[/{severity_color}]")
        console.print(f"📝 Parameter: [cyan]{vuln.parameter_name}[/cyan]")
        console.print(f"🎯 Payload: [yellow]{vuln.payload}[/yellow]")
        console.print(f"📍 Redirects to: [magenta]{vuln.final_destination}[/magenta]")
        console.print(f"⚠️ Severity: [{severity_color}]{vuln.vulnerability_level.value}[/{severity_color}]")

    def _display_results(self, results: Dict[str, Any]):
        """Display scan results"""
        if results['status'] == 'ERROR':
            console.print(f"\n[bold red]❌ SCAN FAILED[/bold red]")
            console.print(f"[red]Error: {results['error']}[/red]")
            return
        
        # Main result
        is_vulnerable = results['is_vulnerable']
        if is_vulnerable:
            console.print(f"\n[bold red]🚨 VULNERABLE TO OPEN REDIRECT![/bold red]")
            console.print(f"[red]Found {len(results['vulnerabilities'])} vulnerabilities[/red]")
        else:
            console.print(f"\n[bold green]✅ NOT VULNERABLE[/bold green]")
            console.print(f"[green]No open redirect vulnerabilities detected[/green]")
        
        # Summary table
        table = Table(title="📊 SCAN SUMMARY", border_style="cyan")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Target URL", results['target'])
        table.add_row("Scan Duration", results['duration'])
        table.add_row("Tests Performed", str(results['tests_performed']))
        table.add_row("Vulnerabilities Found", str(len(results['vulnerabilities'])))
        table.add_row("Status", "[red]VULNERABLE[/red]" if is_vulnerable else "[green]SECURE[/green]")
        
        console.print(table)
        
        # Detailed vulnerabilities
        if results['vulnerabilities']:
            vuln_table = Table(title="🔍 VULNERABILITY DETAILS", border_style="red")
            vuln_table.add_column("Parameter", style="cyan")
            vuln_table.add_column("Type", style="yellow")
            vuln_table.add_column("Severity", style="red")
            vuln_table.add_column("Destination", style="magenta")
            
            for vuln in results['vulnerabilities']:
                severity_style = {
                    'CRITICAL': '[bold red]CRITICAL[/bold red]',
                    'HIGH': '[red]HIGH[/red]',
                    'MEDIUM': '[yellow]MEDIUM[/yellow]',
                    'LOW': '[blue]LOW[/blue]'
                }.get(vuln.vulnerability_level.value)
                
                dest_display = (vuln.final_destination[:40] + "...") if len(vuln.final_destination) > 43 else vuln.final_destination
                
                vuln_table.add_row(
                    vuln.parameter_name,
                    vuln.redirect_type.value,
                    severity_style,
                    dest_display
                )
            
            console.print(vuln_table)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Open Redirect Vulnerability Scanner',
        epilog='Example: python open_redirect.py https://example.com/login?next=/dashboard'
    )
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('--concurrent', type=int, default=20, help='Max concurrent requests (default: 20)')
    parser.add_argument('--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        console.print("[red]❌ Error: URL must start with http:// or https://[/red]")
        sys.exit(1)
    
    async def run_scan():
        detector = OpenRedirectDetector(timeout=args.timeout, max_concurrent=args.concurrent)
        results = await detector.scan_url(args.url)
        
        # Save output if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump({
                    'scan_results': results,
                    'vulnerabilities': [
                        {
                            'url': v.url,
                            'parameter': v.parameter_name,
                            'payload': v.payload,
                            'type': v.redirect_type.value,
                            'destination': v.final_destination,
                            'severity': v.vulnerability_level.value,
                            'confidence': v.confidence_score,
                            'timestamp': v.timestamp
                        }
                        for v in results.get('vulnerabilities', [])
                    ]
                }, f, indent=2)
            console.print(f"\n[green]📄 Results saved to {args.output}[/green]")
        
        # Exit with appropriate code
        sys.exit(1 if results.get('is_vulnerable', False) else 0)
    
    try:
        asyncio.run(run_scan())
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]❌ Unexpected error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()

# API wrapper function for service usage
async def run_openredirect_agent(target: str, mission_type: str = "comprehensive"):
    """
    Wrapper for running the open redirect scan logic for API usage.
    """
    detector = OpenRedirectDetector()
    results = await detector.scan_url(target)
    return results