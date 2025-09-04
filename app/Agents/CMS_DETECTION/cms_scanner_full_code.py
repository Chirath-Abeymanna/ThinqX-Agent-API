#!/usr/bin/env python3

import os
import sys
import json
import time
import socket
import ssl
import asyncio
import aiohttp
import requests
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import random
import re
import base64
from datetime import datetime
import hashlib
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# ============================================================================
# CONFIGURATION & GLOBAL VARIABLES
# ============================================================================

# Import configuration from config.py
from config import CMS_FINGERPRINTS, USER_ENUMERATION_PATHS, OWASP_PATTERNS, VIRUSTOTAL_API_KEY

# Initialize Rich Console
console = Console()

# ============================================================================
# UTILITY CLASSES & FUNCTIONS
# ============================================================================

class Logger:
    """Advanced logging with Rich styling"""
    
    @staticmethod
    def banner():
        banner_text = "[bold red]🔍 CMS SCANNER AGENT 🔍[/bold red]"                                                 
        subtitle_text = "[cyan]Comprehensive CMS Security Analysis Tool[/cyan]"
        console.print(Panel(banner_text + "\n" + subtitle_text, border_style="red", padding=(1, 2)))
    
    @staticmethod
    def info(message: str):
        console.print(f"[blue][INFO][/blue] {message}")
    
    @staticmethod
    def success(message: str):
        console.print(f"[green]✓ {message}[/green]")
    
    @staticmethod
    def warning(message: str):
        console.print(f"[yellow]⚠ {message}[/yellow]")
    
    @staticmethod
    def error(message: str):
        console.print(f"[red]✗ {message}[/red]")
    
    @staticmethod
    def critical(message: str):
        console.print(f"[bold red]🚨 {message}[/bold red]")

logger = Logger()

# ============================================================================
# CMS RECONNAISSANCE MODULE
# ============================================================================

class CMSRecon:
    """CMS-specific reconnaissance module"""
    
    def __init__(self):
        # Create SSL context that's more permissive
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create connector with SSL context and timeout settings
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30, connect=10, sock_read=10),
            headers={
                'User-Agent': random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ]),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
        )
        self.rate_limit = 0.5  # Seconds between requests to avoid overwhelming server
    
    def _normalize_url(self, url: str) -> List[str]:
        """Normalize URL and return potential variants to try"""
        parsed = urlparse(url)
        urls_to_try = []
        
        # Original URL
        urls_to_try.append(url)
        
        # Add www if not present
        if not parsed.hostname.startswith('www.'):
            www_url = f"{parsed.scheme}://www.{parsed.hostname}"
            if parsed.port:
                www_url += f":{parsed.port}"
            if parsed.path:
                www_url += parsed.path
            urls_to_try.append(www_url)
        
        # Try HTTP if HTTPS fails
        if parsed.scheme == 'https':
            http_url = url.replace('https://', 'http://')
            urls_to_try.append(http_url)
            if not parsed.hostname.startswith('www.'):
                www_http_url = f"http://www.{parsed.hostname}"
                if parsed.port:
                    www_http_url += f":{parsed.port}"
                if parsed.path:
                    www_http_url += parsed.path
                urls_to_try.append(www_http_url)
        
        return urls_to_try
    
    async def _try_request(self, urls: List[str], timeout: int = 10) -> tuple:
        """Try multiple URL variants and return the first successful response"""
        for url in urls:
            try:
                logger.info(f"Trying: {url}")
                async with self.session.get(url, timeout=timeout) as response:
                    if response.status in [200, 301, 302, 303, 307, 308]:
                        # Handle redirects
                        if response.status in [301, 302, 303, 307, 308]:
                            redirect_url = response.headers.get('Location')
                            if redirect_url:
                                if not redirect_url.startswith('http'):
                                    redirect_url = urljoin(url, redirect_url)
                                logger.info(f"Following redirect to: {redirect_url}")
                                async with self.session.get(redirect_url, timeout=timeout) as redirect_response:
                                    if redirect_response.status == 200:
                                        content = await redirect_response.text()
                                        return redirect_response, content, redirect_url
                        else:
                            content = await response.text()
                            return response, content, url
                    
            except asyncio.TimeoutError:
                logger.warning(f"Timeout connecting to {url}")
                continue
            except aiohttp.ClientSSLError as e:
                logger.warning(f"SSL error for {url}: {str(e)}")
                continue
            except aiohttp.ClientConnectorError as e:
                logger.warning(f"Connection error for {url}: {str(e)}")
                continue
            except Exception as e:
                logger.warning(f"Error connecting to {url}: {str(e)}")
                continue
                
        return None, None, None
    
    async def detect_cms(self, url: str) -> Dict[str, Any]:
        """Detect CMS type and version"""
        logger.info(f"🔍 Detecting CMS for {url}")
        cms_info = {'url': url, 'cms': None, 'version': None, 'confidence': 0, 'working_url': None}
        
        # Try multiple URL variants
        urls_to_try = self._normalize_url(url)
        response, content, working_url = await self._try_request(urls_to_try)
        
        if not response or not content:
            logger.error(f"Could not connect to any variant of {url}")
            return {'url': url, 'error': 'Could not establish connection to any URL variant', 'working_url': None}
        
        cms_info['working_url'] = working_url
        logger.success(f"Successfully connected to: {working_url}")
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # First check for SaaS platforms with enhanced detection
            saas_info = await self.detect_saas_platform(url, content, response.headers)
            if saas_info.get('platform'):
                cms_info['cms'] = saas_info['platform']
                cms_info['confidence'] = saas_info.get('confidence', 90)
                cms_info['saas_details'] = saas_info
                
                # Get additional security info for SaaS platforms
                security_info = await self.analyze_saas_security(working_url, saas_info['platform'])
                cms_info['security_analysis'] = security_info
                
                return cms_info
            
            # Regular CMS detection
            for cms, data in CMS_FINGERPRINTS.items():
                score = 0
                candidate_version = None  # track per CMS and assign only if CMS wins
                
                # Check generator tag
                if re.search(data['generator_tag'], content, re.IGNORECASE):
                    score += 50
                    generator = soup.find('meta', {'name': 'generator'})
                    if generator and generator.get('content'):
                        gen_content = generator.get('content', '')
                        if cms == 'WordPress':
                            m = re.search(r'WordPress\s+(\d+\.\d+(?:\.\d+)?)', gen_content, re.IGNORECASE)
                            if m:
                                candidate_version = m.group(1)
                        else:
                            m = re.search(r'(\d+\.\d+\.\d+|\d+\.\d+)', gen_content)
                            if m:
                                candidate_version = m.group(1)
                
                # Check CMS-specific patterns
                for pattern in data['patterns']:
                    if pattern in content.lower():
                        score += 20
                
                # Check version files
                for version_file in data['version_files']:
                    file_url = urljoin(working_url, version_file)
                    try:
                        async with self.session.get(file_url, timeout=5) as file_response:
                            if file_response.status == 200:
                                file_content = await file_response.text()
                                if cms == 'WordPress':
                                    if 'version.php' in version_file:
                                        m2 = re.search(r"\$wp_version\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]", file_content)
                                    else:
                                        m2 = re.search(r'WordPress\s+(\d+\.\d+(?:\.\d+)?)', file_content, re.IGNORECASE)
                                else:
                                    m2 = re.search(r'(\d+\.\d+\.\d+|\d+\.\d+)', file_content)
                                if m2:
                                    candidate_version = m2.group(1)
                                    score += 30
                    except Exception:
                        continue
                
                if score > cms_info['confidence']:
                    cms_info['cms'] = cms
                    cms_info['confidence'] = score
                    if candidate_version:
                        cms_info['version'] = candidate_version
            
            # Check for common server signatures
            server_header = response.headers.get('Server', '').lower()
            if 'apache' in server_header:
                cms_info['server'] = 'Apache'
            elif 'nginx' in server_header:
                cms_info['server'] = 'Nginx'
            elif 'iis' in server_header:
                cms_info['server'] = 'IIS'
            
            # Check for common frameworks
            if 'x-powered-by' in response.headers:
                cms_info['powered_by'] = response.headers['x-powered-by']
            
            logger.success(f"CMS detection completed: {cms_info['cms'] or 'Unknown'} (Confidence: {cms_info['confidence']}%)")
            return cms_info
                
        except Exception as e:
            logger.error(f"CMS detection failed during analysis: {str(e)}")
            return {'url': url, 'working_url': working_url, 'error': str(e)}

    async def detect_saas_platform(self, url: str, content: str, headers: dict = None) -> Dict[str, Any]:
        """Enhanced detection method for SaaS platforms like Wix, Shopify, and Squarespace"""
        saas_info = {'platform': None, 'confidence': 0}
        
        # Enhanced Wix detection
        wix_indicators = [
            # JavaScript/CSS patterns
            r'wixcode-public-utils',
            r'static\.wixstatic\.com',
            r'parastorage-api\.com',
            r'_wix[A-Z]',
            r'wixui-[a-z]',
            r'window\.wixDevelopersAnalytics',
            r'wix-elements-registry',
            r'wix-public-api-sdk',
            r'corvid-frontend-essentials',
            # HTML patterns
            r'data-wix-[a-z]',
            r'wixcode-react-',
            r'class="[^"]*wix[A-Z]',
            # Meta tags
            r'property="wix:',
            r'content="[^"]*wix\.com',
        ]
        
        wix_score = 0
        for pattern in wix_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                wix_score += 10
        
        # Check for Wix-specific headers
        if headers:
            wix_headers = ['x-wix-request-id', 'x-wix-published-version']
            for header in wix_headers:
                if header in headers:
                    wix_score += 20
        
        # Enhanced Shopify detection
        shopify_indicators = [
            # JavaScript patterns
            r'Shopify\.theme',
            r'shop_domain\s*:\s*[\'"][^\'"]*\.myshopify\.com',
            r'Shopify\.shop\s*=',
            r'window\.ShopifyAnalytics',
            r'cdn\.shopify\.com/s/files',
            r'monorail-edge\.shopifysvc\.com',
            r'shopifycloud\.com',
            # HTML patterns
            r'shopify-section-',
            r'shopify-block-',
            r'class="[^"]*shopify-',
            # Meta tags
            r'name="shopify-',
            r'powered-by.*shopify',
        ]
        
        shopify_score = 0
        for pattern in shopify_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                shopify_score += 10
        
        # Check for Shopify-specific headers
        if headers:
            shopify_headers = ['x-shopify-stage', 'x-shopify-shop-api-call-limit']
            for header in shopify_headers:
                if header in headers:
                    shopify_score += 20
        
        # Squarespace detection
        squarespace_indicators = [
            r'squarespace\.com',
            r'squarespace-cdn\.com',
            r'sqsp\.com',
            r'Static\.SQUARESPACE_CONTEXT',
            r'squarespace\.config',
            r'Y\.Squarespace',
        ]
        
        squarespace_score = 0
        for pattern in squarespace_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                squarespace_score += 15
        
        # Determine the platform based on highest score
        if wix_score >= 30:
            saas_info['platform'] = 'Wix'
            saas_info['confidence'] = min(90, 50 + wix_score)
            saas_info['indicators_found'] = wix_score
            
            # Try to extract Wix site ID
            site_id_match = re.search(r'meta-site-id="([^"]+)"', content)
            if site_id_match:
                saas_info['site_id'] = site_id_match.group(1)
                
        elif shopify_score >= 30:
            saas_info['platform'] = 'Shopify'
            saas_info['confidence'] = min(90, 50 + shopify_score)
            saas_info['indicators_found'] = shopify_score
            
            # Try to extract Shopify theme
            theme_match = re.search(r'Shopify\.theme\s*=\s*{"name":"([^"]+)"', content)
            if theme_match:
                saas_info['theme'] = theme_match.group(1)
                
            # Try to extract shop domain
            shop_match = re.search(r'shop_domain\s*:\s*[\'"]([^\'"]*\.myshopify\.com)', content)
            if shop_match:
                saas_info['shop_domain'] = shop_match.group(1)
                
        elif squarespace_score >= 30:
            saas_info['platform'] = 'Squarespace'
            saas_info['confidence'] = min(90, 50 + squarespace_score)
            saas_info['indicators_found'] = squarespace_score
        
        return saas_info
    
    async def analyze_saas_security(self, url: str, platform: str) -> Dict[str, Any]:
        """Analyze security configurations specific to SaaS platforms"""
        results = {
            'url': url,
            'platform': platform,
            'security_headers': {},
            'vulnerabilities': []
        }
        
        urls_to_try = self._normalize_url(url)
        response, content, working_url = await self._try_request(urls_to_try)
        
        if not response or not content:
            return {'url': url, 'error': 'Could not establish connection'}
        
        # Check security headers
        important_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header (clickjacking risk)',
            'Content-Security-Policy': 'Missing CSP header',
            'X-XSS-Protection': 'Missing XSS protection header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header'
        }
        
        for header, warning in important_headers.items():
            if header in response.headers:
                results['security_headers'][header] = response.headers[header]
            else:
                results['vulnerabilities'].append({
                    'type': 'Missing Security Header',
                    'severity': 'MEDIUM',
                    'evidence': warning
                })
        
        # Platform-specific checks
        if platform == 'Shopify':
            # Check for exposed admin paths (less likely on Shopify but worth checking)
            admin_paths = ['/admin', '/admin/auth/login']
            for path in admin_paths:
                full_url = urljoin(working_url, path)
                try:
                    async with self.session.get(full_url, timeout=5) as admin_response:
                        if admin_response.status == 200 and 'shopify' not in admin_response.url.host:
                            results['vulnerabilities'].append({
                                'type': 'Unexpected Admin Access',
                                'severity': 'HIGH',
                                'evidence': f"Admin-like path accessible: {full_url}"
                            })
                except Exception:
                    continue
                    
        elif platform == 'Wix':
            # Wix sites are generally well-secured by default
            # Check for custom code vulnerabilities
            if re.search(r'wixcode.*eval\s*\(', content, re.IGNORECASE):
                results['vulnerabilities'].append({
                    'type': 'Potential Code Injection',
                    'severity': 'HIGH',
                    'evidence': 'Custom code with eval() detected'
                })
        
        return results

    async def scan_plugins_themes(self, url: str, cms: str) -> Dict[str, Any]:
        """Scan for CMS plugins and themes"""
        logger.info(f"🔍 Scanning plugins/themes for {url}")
        results = {'url': url, 'plugins': [], 'themes': [], 'vulnerabilities': []}
        
        # Use working URL from CMS detection if available
        urls_to_try = self._normalize_url(url)
        response, content, working_url = await self._try_request(urls_to_try)
        
        if not response or not content:
            return {'url': url, 'error': 'Could not establish connection'}
        
        if cms not in CMS_FINGERPRINTS:
            logger.warning(f"Unknown CMS type: {cms}")
            return results
        
        # Skip plugin/theme scanning for SaaS platforms
        if cms in ['Wix', 'Shopify', 'Squarespace']:
            logger.info(f"Skipping plugin/theme scan for SaaS platform: {cms}")
            return results
        
        plugin_paths = {
            'WordPress': ['wp-content/plugins/', 'wp-content/mu-plugins/'],
            'Joomla': ['components/', 'modules/', 'plugins/'],
            'Drupal': ['sites/all/modules/', 'sites/all/themes/']
        }.get(cms, [])
        
        theme_paths = {
            'WordPress': ['wp-content/themes/'],
            'Joomla': ['templates/'],
            'Drupal': ['sites/all/themes/']
        }.get(cms, [])
        
        async def check_path(path: str, type: str):
            full_url = urljoin(working_url, path)
            try:
                async with self.session.get(full_url, timeout=5) as response:
                    if response.status == 200:
                        content = await response.text()
                        version = re.search(r'(\d+\.\d+\.\d+|\d+\.\d+)', content)
                        return {
                            'type': type,
                            'path': path,
                            'url': full_url,
                            'version': version.group(0) if version else None
                        }
            except Exception:
                return None
        
        # Check common plugins/themes with limited scope to avoid overwhelming
        common_plugins = ['akismet', 'jetpack', 'contact-form-7', 'yoast', 'elementor']
        common_themes = ['twentytwentythree', 'twentytwentytwo', 'twentytwentyone', 'astra', 'hello-elementor']
        
        tasks = []
        for path in plugin_paths:
            tasks.extend([check_path(f"{path}{plugin}/", 'plugin') for plugin in common_plugins])
        for path in theme_paths:
            tasks.extend([check_path(f"{path}{theme}/", 'theme') for theme in common_themes])
        
        if tasks:
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results_list:
                if result and isinstance(result, dict):
                    if result['type'] == 'plugin':
                        results['plugins'].append(result)
                    else:
                        results['themes'].append(result)
        
        logger.success(f"Found {len(results['plugins'])} plugins and {len(results['themes'])} themes")
        return results
    
    async def user_enumeration(self, url: str) -> Dict[str, Any]:
        """Check for user enumeration vulnerabilities"""
        logger.info(f"🔍 Checking for user enumeration at {url}")
        results = {'url': url, 'users': [], 'vulnerable': False}
        
        # Use working URL
        urls_to_try = self._normalize_url(url)
        response, content, working_url = await self._try_request(urls_to_try)
        
        if not response or not content:
            return {'url': url, 'error': 'Could not establish connection'}
        
        for path in USER_ENUMERATION_PATHS:
            full_url = urljoin(working_url, path)
            try:
                async with self.session.get(full_url, timeout=5) as response:
                    if response.status == 200:
                        content = await response.text()
                        users = re.findall(r'"username":"([^"]+)"|"login":"([^"]+)"', content)
                        if users:
                            results['users'].extend([u[0] or u[1] for u in users])
                            results['vulnerable'] = True
                            break
            except Exception:
                continue
        
        if results['vulnerable']:
            logger.critical(f"🚨 User enumeration vulnerability found at {working_url}")
        return results
    
    async def malware_scan(self, url: str) -> Dict[str, Any]:
        """Scan for malware and malicious code"""
        logger.info(f"🔍 Scanning for malware at {url}")
        results = {'url': url, 'malware': [], 'suspicious_scripts': [], 'defaced': False}
        
        # Use working URL
        urls_to_try = self._normalize_url(url)
        response, content, working_url = await self._try_request(urls_to_try)
        
        if not response or not content:
            return {'url': url, 'error': 'Could not establish connection'}
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check for common malware patterns
            malware_patterns = [
                r'eval\s*\(\s*atob\s*\(',  # Obfuscated JavaScript
                r'document\.write\s*\(\s*unescape\s*\(',  # Unescaped content
                r'<\w+\s+on\w+\s*=',  # Event handler injection
                r'http[s]?://[^\s]*?\.(ru|cn|xyz|top)'  # Suspicious domains
            ]
            
            for pattern in malware_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    results['malware'].append({
                        'pattern': pattern, 
                        'evidence': f'Found {len(matches)} matches in page content',
                        'matches': matches[:5]  # Limit to first 5 matches
                    })
            
            # Check for suspicious scripts
            for script in soup.find_all('script'):
                src = script.get('src')
                if src and any(domain in src for domain in ['.ru', '.cn', '.xyz', '.top']):
                    results['suspicious_scripts'].append(src)
            
            # Check for defacement indicators
            defacement_indicators = ['hacked by', 'defaced by', 'owned by', 'pwned by']
            content_lower = content.lower()
            for indicator in defacement_indicators:
                if indicator in content_lower:
                    results['defaced'] = True
                    logger.critical(f"🚨 Possible site defacement detected at {working_url}")
                    break
            
            return results
            
        except Exception as e:
            logger.error(f"Malware scan analysis failed: {str(e)}")
            return {'url': url, 'working_url': working_url, 'error': str(e)}
    
    async def check_owasp_vulnerabilities(self, url: str) -> Dict[str, Any]:
        """Scan for OWASP Top 10 vulnerabilities"""
        logger.info(f"🔍 Checking OWASP Top 10 vulnerabilities at {url}")
        results = {'url': url, 'vulnerabilities': []}
        
        # Use working URL
        urls_to_try = self._normalize_url(url)
        response, content, working_url = await self._try_request(urls_to_try)
        
        if not response or not content:
            return {'url': url, 'error': 'Could not establish connection'}
            
        try:
            for vuln_type, pattern in OWASP_PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    results['vulnerabilities'].append({
                        'type': vuln_type,
                        'severity': 'MEDIUM',
                        'evidence': f"Pattern matched in content: {pattern[:50]}...",
                        'matches_count': len(matches)
                    })
            
            # Check for insecure forms
            soup = BeautifulSoup(content, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', '').lower()
                
                if method != 'post' and action.startswith('http:'):
                    results['vulnerabilities'].append({
                        'type': 'Insecure Form Submission',
                        'severity': 'HIGH',
                        'evidence': f"Form with action {action} uses HTTP without POST method"
                    })
            
            return results
            
        except Exception as e:
            logger.error(f"OWASP scan analysis failed: {str(e)}")
            return {'url': url, 'working_url': working_url, 'error': str(e)}
    
    async def check_config_weaknesses(self, url: str, cms: str) -> Dict[str, Any]:
        """Check for configuration weaknesses"""
        logger.info(f"🔍 Checking configuration weaknesses at {url}")
        results = {'url': url, 'weaknesses': [], 'admin_exposed': False}
        
        # Use working URL
        urls_to_try = self._normalize_url(url)
        response, content, working_url = await self._try_request(urls_to_try)
        
        if not response or not content:
            return {'url': url, 'error': 'Could not establish connection'}
        
        if cms not in CMS_FINGERPRINTS:
            logger.warning(f"Unknown CMS type for config check: {cms}")
            return results
        
        # Skip config checks for SaaS platforms
        if cms in ['Wix', 'Shopify', 'Squarespace']:
            logger.info(f"Skipping config check for SaaS platform: {cms}")
            return results
        
        admin_path = CMS_FINGERPRINTS[cms]['admin_path']
        config_files = ['wp-config.php', 'configuration.php', 'settings.php', '.env']
        
        async def check_path(path: str):
            full_url = urljoin(working_url, path)
            try:
                async with self.session.get(full_url, timeout=5) as response:
                    if response.status == 200:
                        content = await response.text()
                        if '404' not in content and 'not found' not in content.lower():
                            return {'path': path, 'status': response.status, 'url': full_url}
                    return None
            except Exception:
                return None
        
        # Check admin panel
        admin_result = await check_path(admin_path)
        if admin_result:
            results['admin_exposed'] = True
            results['weaknesses'].append({
                'type': 'Exposed Admin Panel',
                'severity': 'HIGH',
                'evidence': f"Admin panel accessible at {admin_result['url']}"
            })
            logger.critical(f"🚨 Exposed admin panel found at {admin_result['url']}")
        
        # Check config files
        tasks = [check_path(file) for file in config_files]
        config_results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in config_results:
            if result and isinstance(result, dict):
                results['weaknesses'].append({
                    'type': 'Exposed Config File',
                    'severity': 'CRITICAL',
                    'evidence': f"Config file accessible at {result['url']}"
                })
                logger.critical(f"🚨 Exposed config file found at {result['url']}")
        
        # Check SSL/TLS configuration
        parsed_url = urlparse(working_url)
        if parsed_url.scheme == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((parsed_url.hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        if cipher and ('RC4' in cipher[0] or 'MD5' in cipher[0]):
                            results['weaknesses'].append({
                                'type': 'Weak SSL/TLS Cipher',
                                'severity': 'HIGH',
                                'evidence': f"Using weak cipher: {cipher[0]}"
                            })
            except Exception as e:
                results['weaknesses'].append({
                    'type': 'SSL/TLS Check Failed',
                    'severity': 'LOW',
                    'evidence': f"SSL/TLS check failed: {str(e)[:100]}"
                })
        
        return results
    
    async def check_brute_force(self, url: str, cms: str) -> Dict[str, Any]:
        """Check for brute-force attack vulnerability"""
        logger.info(f"🔍 Checking brute-force vulnerability at {url}")
        results = {'url': url, 'vulnerable': False, 'details': []}
        
        # Use working URL
        urls_to_try = self._normalize_url(url)
        response, content, working_url = await self._try_request(urls_to_try)
        
        if not response or not content:
            return {'url': url, 'error': 'Could not establish connection'}
        
        if cms not in CMS_FINGERPRINTS:
            return results
        
        # Skip brute force checks for SaaS platforms (they handle this internally)
        if cms in ['Wix', 'Shopify', 'Squarespace']:
            logger.info(f"Skipping brute force check for SaaS platform: {cms}")
            return results
        
        login_path = CMS_FINGERPRINTS[cms]['login_path']
        full_url = urljoin(working_url, login_path)
        
        try:
            async with self.session.get(full_url, timeout=5) as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    if not soup.find('input', {'name': re.compile('captcha|recaptcha', re.IGNORECASE)}):
                        results['vulnerable'] = True
                        results['details'].append({
                            'type': 'Missing CAPTCHA',
                            'severity': 'MEDIUM',
                            'evidence': f"No CAPTCHA found on login page: {full_url}"
                        })
                        logger.warning(f"⚠ No CAPTCHA protection on login page: {full_url}")
        except Exception:
            pass
        
        return results
    
    async def content_change_monitoring(self, url: str) -> Dict[str, Any]:
        """Monitor for unexpected content changes"""
        logger.info(f"🔍 Monitoring content changes at {url}")
        results = {'url': url, 'changes': [], 'baseline_hash': None, 'current_hash': None}
        
        # Use working URL
        urls_to_try = self._normalize_url(url)
        response, content, working_url = await self._try_request(urls_to_try)
        
        if not response or not content:
            return {'url': url, 'error': 'Could not establish connection'}
            
        try:
            results['current_hash'] = hashlib.sha256(content.encode()).hexdigest()
            results['working_url'] = working_url
            
            # Check against baseline (if exists)
            safe_hostname = urlparse(working_url).hostname.replace('.', '_')
            baseline_file = f"baseline_{safe_hostname}.txt"
            
            if os.path.exists(baseline_file):
                with open(baseline_file, 'r') as f:
                    baseline_hash = f.read().strip()
                results['baseline_hash'] = baseline_hash
                
                if baseline_hash != results['current_hash']:
                    results['changes'].append({
                        'type': 'Content Change',
                        'severity': 'MEDIUM',
                        'evidence': 'Content hash mismatch detected'
                    })
                    logger.warning(f"⚠ Content change detected at {working_url}")
            else:
                with open(baseline_file, 'w') as f:
                    f.write(results['current_hash'])
                results['baseline_hash'] = results['current_hash']
                logger.info(f"Created baseline for {working_url}")
            
            return results
            
        except Exception as e:
            logger.error(f"Content monitoring failed: {str(e)}")
            return {'url': url, 'working_url': working_url, 'error': str(e)}
    
    async def domain_reputation(self, url: str) -> Dict[str, Any]:
        """Check domain reputation and phishing risks"""
        logger.info(f"🔍 Checking domain reputation for {url}")
        
        # Initialize results with safe defaults
        results = {
            'domain': None,
            'reputation': {
                'malicious': 0,
                'suspicious': 0,
                'clean': 0,
                'total_scans': 0
            },
            'blacklisted': False,
            'error': None,
            'working_url': url  # Add working_url to prevent NoneType error
        }
        
        try:
            # Use working URL
            urls_to_try = self._normalize_url(url)
            response, content, working_url = await self._try_request(urls_to_try)
            
            if working_url:
                results['working_url'] = working_url
                # Safely get domain
                domain = urlparse(working_url).hostname
                results['domain'] = domain
            
            if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "your_virustotal_key_here":
                results['error'] = 'VirusTotal API key not configured'
                logger.info("VirusTotal API key not configured, skipping domain reputation check")
                return results
                
            try:
                async with self.session.get(
                    f"https://www.virustotal.com/vtapi/v2/domain/report",
                    params={'apikey': VIRUSTOTAL_API_KEY, 'domain': domain},
                    timeout=30
                ) as vt_response:
                    if vt_response.status == 200:
                        data = await vt_response.json()
                        if data and data.get('response_code') == 1:
                            detected_urls = data.get('detected_urls', [])
                            undetected_urls = data.get('undetected_urls', [])
                            
                            results['reputation'].update({
                                'malicious': len(detected_urls),
                                'suspicious': 0,
                                'clean': len(undetected_urls),
                                'total_scans': len(detected_urls) + len(undetected_urls)
                            })
                            
                            if results['reputation']['malicious'] > 0:
                                results['blacklisted'] = True
                                logger.critical(f"🚨 Domain {domain} flagged as malicious by VirusTotal")
                        else:
                            logger.info(f"No VirusTotal data available for domain: {domain}")
                    elif vt_response.status == 403:
                        results['error'] = 'VirusTotal API access forbidden - check API key'
                        logger.warning(f"VirusTotal API returned status {vt_response.status}")
                    else:
                        results['error'] = f'VirusTotal API returned status {vt_response.status}'
                        logger.warning(f"VirusTotal API returned status {vt_response.status}")
                        
            except asyncio.TimeoutError:
                results['error'] = 'VirusTotal API request timed out'
                logger.error("VirusTotal API request timed out")
            except Exception as e:
                results['error'] = f'VirusTotal API error: {str(e)}'
                logger.error(f"Domain reputation check failed: {str(e)}")
                
        except Exception as e:
            results['error'] = f'General error: {str(e)}'
            logger.error(f"Domain reputation check failed: {str(e)}")
        
        return results
    
    async def virustotal_plugin_check(self, component: str, version: str) -> Dict[str, Any]:
        """Check plugins/themes for known vulnerabilities using VirusTotal"""
        results = {'component': component, 'version': version, 'vulnerabilities': []}
        
        if VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "your_virustotal_key_here":
            try:
                # Note: This is a simplified example; actual plugin vulnerability checks may require specialized databases
                async with self.session.get(
                    f"https://www.virustotal.com/vtapi/v2/file/report",
                    params={'apikey': VIRUSTOTAL_API_KEY, 'resource': component},
                    timeout=30
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('response_code') == 1 and data.get('positives', 0) > 0:
                            results['vulnerabilities'].append({
                                'type': 'Known Vulnerability',
                                'severity': 'HIGH',
                                'evidence': f"Component {component} ({version}) flagged by {data['positives']} scanners"
                            })
            except Exception:
                pass
        
        return results
    
    async def close(self):
        """Close the aiohttp session"""
        await self.session.close()

# ============================================================================
# CMS SCANNER AGENT
# ============================================================================

class CMSScannerAgent:
    """Comprehensive CMS Scanner Agent"""
    
    def __init__(self):
        self.cms_recon = CMSRecon()
        self.scan_throttle = 0.5  # Seconds between requests
        self.report_file = None
    
    async def run_cms_scan(self, target: str) -> Dict[str, Any]:
        """Execute comprehensive CMS scan"""
        logger.banner()
        console.print(f"\n[bold red]🎯 TARGET: {target}[/bold red]")
        console.print(f"[bold cyan]📋 MISSION: CMS Security Scan[/bold cyan]\n")
        
        # Ensure target has scheme
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        start_time = datetime.now()
        report = {
            'target': target,
            'start_time': start_time.isoformat(),
            'findings': {},
            'vulnerabilities': [],
            'recommendations': [],
            'status': 'RUNNING'
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("🔍 Scanning CMS...", total=8)
            
            # CMS Detection
            progress.update(task, description="🔍 Detecting CMS...")
            cms_info = await self.cms_recon.detect_cms(target)
            report['findings']['cms_detection'] = cms_info
            progress.advance(task)
            
            cms_type = cms_info.get('cms', 'Unknown')
            working_url = cms_info.get('working_url', target)
            
            # Only continue with other scans if we have a working URL
            if cms_info.get('error') or not working_url:
                logger.error(f"Could not establish connection to {target}")
                report['status'] = 'FAILED'
                report['error'] = cms_info.get('error', 'Could not establish connection')
                # Skip remaining scans
                progress.update(task, completed=8)
            else:
                # Plugins and Themes
                progress.update(task, description="🔍 Scanning Plugins/Themes...")
                plugins_themes = await self.cms_recon.scan_plugins_themes(working_url, cms_type)
                report['findings']['plugins_themes'] = plugins_themes
                progress.advance(task)
                
                # User Enumeration
                progress.update(task, description="🔍 Checking User Enumeration...")
                user_enum = await self.cms_recon.user_enumeration(working_url)
                report['findings']['user_enumeration'] = user_enum
                progress.advance(task)
                
                # Malware Scan
                progress.update(task, description="🔍 Scanning for Malware...")
                malware_scan = await self.cms_recon.malware_scan(working_url)
                report['findings']['malware_scan'] = malware_scan
                progress.advance(task)
                
                # OWASP Vulnerabilities
                progress.update(task, description="🔍 Checking OWASP Top 10...")
                owasp_scan = await self.cms_recon.check_owasp_vulnerabilities(working_url)
                report['findings']['owasp_vulnerabilities'] = owasp_scan
                progress.advance(task)
                
                # Configuration Weaknesses
                progress.update(task, description="🔍 Checking Configuration...")
                config_scan = await self.cms_recon.check_config_weaknesses(working_url, cms_type)
                report['findings']['config_weaknesses'] = config_scan
                progress.advance(task)
                
                # Brute Force Vulnerability
                progress.update(task, description="🔍 Checking Brute Force...")
                brute_force = await self.cms_recon.check_brute_force(working_url, cms_type)
                report['findings']['brute_force'] = brute_force
                progress.advance(task)
                
                # Content Change Monitoring
                progress.update(task, description="🔍 Monitoring Content Changes...")
                content_monitor = await self.cms_recon.content_change_monitoring(working_url)
                report['findings']['content_monitoring'] = content_monitor
                progress.advance(task)
                
                # Domain Reputation
                progress.update(task, description="🔍 Checking Domain Reputation...")
                try:
                    domain_rep = await self.cms_recon.domain_reputation(working_url)
                    if domain_rep:
                        report['findings']['domain_reputation'] = domain_rep
                    else:
                        report['findings']['domain_reputation'] = {
                            'domain': urlparse(working_url).hostname,
                            'error': 'Domain reputation check failed',
                            'reputation': {
                                'malicious': 0,
                                'suspicious': 0,
                                'clean': 0,
                                'total_scans': 0
                            },
                            'blacklisted': False
                        }
                except Exception as e:
                    logger.error(f"Domain reputation check failed: {str(e)}")
                    report['findings']['domain_reputation'] = {
                        'error': f'Domain reputation check failed: {str(e)}',
                        'reputation': {
                            'malicious': 0,
                            'suspicious': 0,
                            'clean': 0,
                            'total_scans': 0
                        },
                        'blacklisted': False
                    }
                progress.advance(task)
                
                # Analyze vulnerabilities
                report['vulnerabilities'] = self._analyze_vulnerabilities(report['findings'])
                report['recommendations'] = self._generate_recommendations(report['findings'], report['vulnerabilities'])
                report['status'] = 'COMPLETED'
        
        end_time = datetime.now()
        report['end_time'] = end_time.isoformat()
        report['duration'] = str(end_time - start_time)
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace('://', '_').replace('/', '_').replace('.', '_')

        # Create the results/domain directory
        domain_name = urlparse(target).hostname
        results_dir = os.path.join("results", domain_name)
        os.makedirs(results_dir, exist_ok=True)

        # Save the report in the directory
        self.report_file = os.path.join(results_dir, f"cms_scan_report_{safe_target}_{timestamp}.json")
        
        with open(self.report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        await self.cms_recon.close()
        self._display_results(report)
        return report
    
    def _analyze_vulnerabilities(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze findings for vulnerabilities"""
        vulnerabilities = []
        
        # CMS Detection
        if 'cms_detection' in findings and findings['cms_detection'].get('cms'):
            cms_info = findings['cms_detection']
            if cms_info.get('version'):
                vulnerabilities.append({
                    'type': 'CMS Version Exposed',
                    'severity': 'MEDIUM',
                    'description': f"{cms_info['cms']} version {cms_info['version']} detected",
                    'evidence': {'cms': cms_info['cms'], 'version': cms_info['version']},
                    'recommendation': 'Hide CMS version information and keep updated'
                })
        
        # Plugins/Themes Vulnerabilities
        if 'plugins_themes' in findings:
            for vuln in findings['plugins_themes'].get('vulnerabilities', []):
                vulnerabilities.append({
                    'type': 'Vulnerable Component',
                    'severity': 'HIGH',
                    'description': f"Vulnerable {vuln['component']} (version {vuln['version']})",
                    'evidence': vuln,
                    'recommendation': 'Update or remove vulnerable component'
                })
        
        # User Enumeration
        if 'user_enumeration' in findings and findings['user_enumeration'].get('vulnerable'):
            vulnerabilities.append({
                'type': 'User Enumeration',
                'severity': 'MEDIUM',
                'description': f"User enumeration possible: {len(findings['user_enumeration']['users'])} users found",
                'evidence': {'users': findings['user_enumeration']['users'][:5]},
                'recommendation': 'Disable user enumeration endpoints'
            })
        
        # Malware
        if 'malware_scan' in findings:
            malware_scan = findings['malware_scan']
            if malware_scan.get('malware') or malware_scan.get('suspicious_scripts') or malware_scan.get('defaced'):
                severity = 'CRITICAL' if malware_scan.get('defaced') else 'HIGH'
                vulnerabilities.append({
                    'type': 'Malware Detected',
                    'severity': severity,
                    'description': 'Potential malware or defacement detected',
                    'evidence': {
                        'malware': malware_scan.get('malware'),
                        'suspicious_scripts': malware_scan.get('suspicious_scripts'),
                        'defaced': malware_scan.get('defaced')
                    },
                    'recommendation': 'Remove malicious code and investigate compromise'
                })
        
        # OWASP Vulnerabilities
        if 'owasp_vulnerabilities' in findings:
            for vuln in findings['owasp_vulnerabilities'].get('vulnerabilities', []):
                vulnerabilities.append({
                    'type': vuln['type'],
                    'severity': vuln['severity'],
                    'description': vuln.get('description', vuln['evidence']),
                    'evidence': vuln['evidence'],
                    'recommendation': f"Mitigate {vuln['type']} vulnerability"
                })
        
        # Configuration Weaknesses
        if 'config_weaknesses' in findings:
            for weakness in findings['config_weaknesses'].get('weaknesses', []):
                vulnerabilities.append({
                    'type': weakness['type'],
                    'severity': weakness['severity'],
                    'description': weakness['evidence'],
                    'evidence': {'path': weakness.get('path')},
                    'recommendation': f"Secure {weakness['type'].lower()}"
                })
        
        # Brute Force
        if 'brute_force' in findings and findings['brute_force'].get('vulnerable'):
            for detail in findings['brute_force']['details']:
                vulnerabilities.append({
                    'type': detail['type'],
                    'severity': detail['severity'],
                    'description': detail['evidence'],
                    'evidence': {'url': findings['brute_force']['url']},
                    'recommendation': 'Implement CAPTCHA or rate limiting on login endpoints'
                })
        
        # Content Changes
        if 'content_monitoring' in findings and findings['content_monitoring'].get('changes'):
            vulnerabilities.append({
                'type': 'Unexpected Content Change',
                'severity': 'MEDIUM',
                'description': 'Content changes detected since last scan',
                'evidence': findings['content_monitoring']['changes'],
                'recommendation': 'Investigate content changes for potential compromise'
            })
        
        # Domain Reputation
        if 'domain_reputation' in findings and findings['domain_reputation'].get('blacklisted'):
            reputation_details = findings['domain_reputation'].get('reputation', {}) 
            vulnerabilities.append({
                'type': 'Poor Domain Reputation',
                'severity': 'HIGH',
                'description': f"Domain flagged as malicious by {findings['domain_reputation']['reputation']['malicious']} scanners",
                'evidence': findings['domain_reputation']['reputation'],
                'recommendation': 'Investigate and remediate domain reputation issues'
            })
        
        return vulnerabilities
    
    def _generate_recommendations(self, findings: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # General CMS recommendations
        recommendations.extend([
            "Keep CMS core, plugins, and themes updated to latest secure versions",
            "Implement strong access controls for admin panels",
            "Regularly backup CMS data and configurations",
            "Enable logging and monitoring for security events"
        ])
        
        # Specific recommendations based on vulnerabilities
        for vuln in vulnerabilities:
            if vuln.get('recommendation') and vuln['recommendation'] not in recommendations:
                recommendations.append(vuln['recommendation'])
        
        # CMS-specific recommendations
        if 'cms_detection' in findings and findings['cms_detection'].get('cms'):
            cms_name = findings['cms_detection']['cms']
            recommendations.append(f"Regularly check {cms_name} security advisories")
            
            # SaaS-specific recommendations
            if cms_name in ['Wix', 'Shopify', 'Squarespace']:
                recommendations.extend([
                    f"Review {cms_name} security settings in admin panel",
                    f"Enable two-factor authentication for {cms_name} account",
                    f"Regularly review {cms_name} app permissions and integrations"
                ])
        
        # Configuration recommendations
        if 'config_weaknesses' in findings and findings['config_weaknesses'].get('admin_exposed'):
            recommendations.append("Implement IP whitelisting for admin access")
        
        return list(dict.fromkeys(recommendations))[:15]  # Limit to top 15, remove duplicates
    
    def _display_results(self, report: Dict[str, Any]):
        """Display scan results with improved error handling"""
        
        # Handle failed scans
        if report.get('status') == 'FAILED':
            console.print(f"\n[bold red]❌ SCAN FAILED[/bold red]")
            console.print(f"[red]Error: {report.get('error', 'Unknown error')}[/red]")
            console.print(f"\n[bold yellow]💡 TROUBLESHOOTING TIPS:[/bold yellow]")
            console.print("1. Check if the target URL is accessible in your browser")
            console.print("2. Try adding 'www.' prefix to the domain")
            console.print("3. Verify the domain name is correct")
            console.print("4. Check if the site is behind a firewall or CDN")
            console.print("5. Some government sites may block automated requests")
            return
        
        # Safe access to findings with defaults
        cms_detection = report.get('findings', {}).get('cms_detection', {})
        working_url = cms_detection.get('working_url', report.get('target', 'N/A'))
        cms_name = cms_detection.get('cms', 'Unknown')
        cms_version = cms_detection.get('version', 'Unknown')
        server_info = cms_detection.get('server', 'Unknown')
        
        table = Table(title="🎯 CMS SCAN RESULTS", border_style="red")
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Target", report.get('target', 'N/A'))
        table.add_row("Working URL", working_url)
        table.add_row("CMS", cms_name)
        table.add_row("Version", cms_version)
        table.add_row("Server", server_info)
        table.add_row("Duration", report.get('duration', 'N/A'))
        table.add_row("Vulnerabilities Found", str(len(report.get('vulnerabilities', []))))
        
        # Add SaaS-specific info if detected
        if cms_detection.get('saas_details'):
            saas_details = cms_detection['saas_details']
            table.add_row("Platform Type", "SaaS (Software as a Service)")
            table.add_row("Confidence", f"{saas_details.get('confidence', 0)}%")
            if saas_details.get('theme'):
                table.add_row("Theme", saas_details['theme'])
            if saas_details.get('shop_domain'):
                table.add_row("Shop Domain", saas_details['shop_domain'])
        
        table.add_row("Status", f"[green]{report.get('status', 'UNKNOWN')}[/green]")
        
        console.print(table)
        
        # Display vulnerabilities
        if report.get('vulnerabilities'):
            console.print(f"\n[bold red]🚨 VULNERABILITIES FOUND:[/bold red]")
            vuln_table = Table(border_style="red")
            vuln_table.add_column("Type", style="cyan")
            vuln_table.add_column("Severity", style="red")
            vuln_table.add_column("Description", style="white")
            
            for vuln in report['vulnerabilities']:
                severity_color = "red" if vuln['severity'] in ['HIGH', 'CRITICAL'] else "yellow"
                vuln_table.add_row(
                    vuln['type'],
                    f"[{severity_color}]{vuln['severity']}[/{severity_color}]",
                    vuln['description'][:80] + "..." if len(vuln['description']) > 80 else vuln['description']
                )
            
            console.print(vuln_table)
        else:
            console.print(f"\n[bold green]✅ No major vulnerabilities detected[/bold green]")
        
        # Display key findings
        console.print(f"\n[bold cyan]📋 DETAILED FINDINGS:[/bold cyan]")
        
        if cms_detection:
            console.print(f"\n[bold blue]🌐 CMS Detection:[/bold blue]")
            console.print(f"  CMS: {cms_name}")
            console.print(f"  Version: {cms_version}")
            console.print(f"  Confidence: {cms_detection.get('confidence', 0)}%")
            console.print(f"  Server: {server_info}")
            if cms_detection.get('powered_by'):
                console.print(f"  Powered By: {cms_detection['powered_by']}")
            
            # Show SaaS-specific details
            if cms_detection.get('saas_details'):
                saas_details = cms_detection['saas_details']
                console.print(f"  Platform Type: SaaS")
                console.print(f"  Indicators Found: {saas_details.get('indicators_found', 0)}")
                if saas_details.get('theme'):
                    console.print(f"  Theme: {saas_details['theme']}")
                if saas_details.get('shop_domain'):
                    console.print(f"  Shop Domain: {saas_details['shop_domain']}")
                if saas_details.get('site_id'):
                    console.print(f"  Site ID: {saas_details['site_id']}")
        
        findings = report.get('findings', {})
        
        if 'plugins_themes' in findings and findings['plugins_themes']:
            pt_data = findings['plugins_themes']
            if not pt_data.get('error'):
                console.print(f"\n[bold blue]🔌 Plugins/Themes:[/bold blue]")
                console.print(f"  Plugins: {len(pt_data.get('plugins', []))}")
                console.print(f"  Themes: {len(pt_data.get('themes', []))}")
                if pt_data.get('plugins'):
                    console.print("  Found Plugins:")
                    for plugin in pt_data['plugins'][:3]:  # Show first 3
                        console.print(f"    - {plugin.get('path', 'Unknown')} ({plugin.get('version', 'Unknown version')})")
        
        if 'user_enumeration' in findings and findings['user_enumeration'].get('vulnerable'):
            ue_data = findings['user_enumeration']
            console.print(f"\n[bold blue]👤 User Enumeration:[/bold blue]")
            console.print(f"  Vulnerable: [red]Yes[/red]")
            console.print(f"  Users Found: {len(ue_data.get('users', []))}")
            if ue_data.get('users'):
                console.print(f"  Sample Users: {', '.join(ue_data['users'][:3])}")
        
        if 'malware_scan' in findings and findings['malware_scan']:
            malware_data = findings['malware_scan']
            if not malware_data.get('error'):
                console.print(f"\n[bold blue]🛡️ Malware Scan:[/bold blue]")
                console.print(f"  Malware Patterns: {len(malware_data.get('malware', []))}")
                console.print(f"  Suspicious Scripts: {len(malware_data.get('suspicious_scripts', []))}")
                console.print(f"  Defaced: {'[red]Yes[/red]' if malware_data.get('defaced') else '[green]No[/green]'}")
        
        if 'domain_reputation' in findings and findings['domain_reputation']:
            dr_data = findings['domain_reputation']
            console.print(f"\n[bold blue]🌍 Domain Reputation:[/bold blue]")
            console.print(f"  Domain: {dr_data.get('domain', 'Unknown')}")
            if 'error' in dr_data:
                console.print(f"  Status: [yellow]Could not check ({dr_data['error']})[/yellow]")
            else:
                rep = dr_data.get('reputation', {})
                console.print(f"  Malicious Flags: {rep.get('malicious', 0)}")
                console.print(f"  Clean Flags: {rep.get('clean', 0)}")
                console.print(f"  Blacklisted: {'[red]Yes[/red]' if dr_data.get('blacklisted') else '[green]No[/green]'}")
        
        # Display security analysis for SaaS platforms
        if cms_detection.get('security_analysis'):
            sec_data = cms_detection['security_analysis']
            console.print(f"\n[bold blue]🔒 Security Analysis:[/bold blue]")
            console.print(f"  Platform: {sec_data.get('platform', 'Unknown')}")
            
            headers = sec_data.get('security_headers', {})
            if headers:
                console.print("  Security Headers Found:")
                for header, value in headers.items():
                    console.print(f"    - {header}: {value[:50]}{'...' if len(value) > 50 else ''}")
            
            vulns = sec_data.get('vulnerabilities', [])
            if vulns:
                console.print(f"  Security Issues: {len(vulns)}")
                for vuln in vulns[:3]:  # Show first 3
                    console.print(f"    - {vuln.get('type', 'Unknown')}: {vuln.get('evidence', 'No details')}")
        
        # Display recommendations
        if report.get('recommendations'):
            console.print(f"\n[bold yellow]💡 RECOMMENDATIONS:[/bold yellow]")
            for i, rec in enumerate(report['recommendations'][:12], 1):
                console.print(f"{i}. {rec}")
        
        console.print(f"\n[bold green]📄 Report saved to: {self.report_file}[/bold green]")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

async def main():
    """Main execution function"""
    if len(sys.argv) < 2:
        logger.banner()
        console.print("""
[bold cyan]USAGE:[/bold cyan]
  python cms_scanner.py <target>

[bold cyan]EXAMPLES:[/bold cyan]
  python cms_scanner.py example.com
  python cms_scanner.py https://example.com
  python cms_scanner.py www.example.com

[bold cyan]SUPPORTED PLATFORMS:[/bold cyan]
  • WordPress, Joomla, Drupal (Traditional CMS)
  • Wix, Shopify, Squarespace (SaaS Platforms)
  • Custom and unknown platforms

[bold cyan]TROUBLESHOOTING:[/bold cyan]
  • If SSL errors occur, the scanner will try HTTP fallback automatically
  • If 'example.com' fails, try 'www.example.com' 
  • Some sites block automated requests - this is normal
  • Government sites may have strict security policies

[bold red]⚠️ WARNING: FOR AUTHORIZED SECURITY TESTING ONLY ⚠️[/bold red]
""")
        sys.exit(1)
    
    target = sys.argv[1]
    agent = CMSScannerAgent()
    
    try:
        console.print(f"[bold cyan]🚀 Starting comprehensive scan of: {target}[/bold cyan]")
        report = await agent.run_cms_scan(target)
        
        if report.get('status') == 'COMPLETED':
            logger.success(f"CMS scan completed successfully")
        else:
            logger.error(f"CMS scan completed with issues")
            
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        await agent.cms_recon.close()
        sys.exit(1)
    except Exception as e:
        logger.error(f"CMS scan failed: {str(e)}")
        await agent.cms_recon.close()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())