import asyncio
import aiohttp
import re
import os
import ssl
import socket
import hashlib
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Dict, List, Any
from rich.console import Console
from logger import logger
from config import CMS_FINGERPRINTS, USER_ENUMERATION_PATHS, OWASP_PATTERNS, VIRUSTOTAL_API_KEY
import random

class CMSRecon:
    """CMS-specific reconnaissance module"""
    
    def __init__(self):
        # Create SSL context that's more permissive
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create virustotal_results directory if it doesn't exist
        self.virustotal_results_dir = "virustotal_results"
        os.makedirs(self.virustotal_results_dir, exist_ok=True)
        
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
        # Active scan output wiring (set by caller)
        self.scan_output_dir = None
        self.scan_timestamp = None
        self._closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()
    
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
                candidate_version = None  # track version per-CMS; assign only if this CMS wins
                
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
                            # fallback generic for non-WP CMS
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
                                    # Prefer extracting from wp-includes/version.php; fallback to readme with explicit label
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
            
            # Extract social media links
            social_links = self._extract_social_media_links(soup)
            if social_links:
                cms_info['social_media'] = social_links
            
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

            # Prepare domain-specific results directory and baseline paths
            domain = urlparse(working_url).hostname or "unknown"
            domain_results_dir = os.path.join("results", domain)
            os.makedirs(domain_results_dir, exist_ok=True)

            # New baseline location inside results/{domain}/
            new_baseline_path = os.path.join(domain_results_dir, "baseline.txt")

            # Legacy baseline path (root-level)
            safe_hostname = domain.replace('.', '_')
            legacy_baseline_path = f"baseline_{safe_hostname}.txt"

            # Read baseline (prefer new location; migrate legacy if present)
            baseline_hash = None
            if os.path.exists(new_baseline_path):
                with open(new_baseline_path, 'r', encoding='utf-8') as f:
                    baseline_hash = f.read().strip()
            elif os.path.exists(legacy_baseline_path):
                with open(legacy_baseline_path, 'r', encoding='utf-8') as f:
                    baseline_hash = f.read().strip()
                # Migrate legacy file into results/{domain}/baseline.txt
                try:
                    with open(new_baseline_path, 'w', encoding='utf-8') as nf:
                        nf.write(baseline_hash)
                    os.remove(legacy_baseline_path)
                    logger.info(f"Migrated legacy baseline to {new_baseline_path}")
                except Exception as e:
                    logger.warning(f"Could not migrate legacy baseline: {e}")

            results['baseline_path'] = new_baseline_path

            if baseline_hash:
                results['baseline_hash'] = baseline_hash
                if baseline_hash != results['current_hash']:
                    results['changes'].append({
                        'type': 'Content Change',
                        'severity': 'MEDIUM',
                        'evidence': 'Content hash mismatch detected'
                    })
                    logger.warning(f"⚠ Content change detected at {working_url}")
            else:
                # Create initial baseline in the new location
                with open(new_baseline_path, 'w', encoding='utf-8') as f:
                    f.write(results['current_hash'])
                results['baseline_hash'] = results['current_hash']
                logger.info(f"Created baseline for {working_url} at {new_baseline_path}")
            
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
            
            if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY in ["your_virustotal_key_here", "dbcf0bc793c51a5a851d3a60142dc1164aae72aa98a9380de8ef21ff7745474e"]:
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
                        
                        # Save VirusTotal results to file
                        await self._save_virustotal_results(domain, data, 'domain_reputation')
                        
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
        
        if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY in ["your_virustotal_key_here", "dbcf0bc793c51a5a851d3a60142dc1164aae72aa98a9380de8ef21ff7745474e"]:
            results['error'] = 'VirusTotal API key not configured'
            return results
            
        try:
            # Note: This is a simplified example; actual plugin vulnerability checks may require specialized databases
            async with self.session.get(
                f"https://www.virustotal.com/vtapi/v2/file/report",
                params={'apikey': VIRUSTOTAL_API_KEY, 'resource': component},
                timeout=30
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Save VirusTotal results to file
                    await self._save_virustotal_results(component, data, 'plugin_check')
                    
                    if data.get('response_code') == 1 and data.get('positives', 0) > 0:
                        results['vulnerabilities'].append({
                            'type': 'Known Vulnerability',
                            'severity': 'HIGH',
                            'evidence': f"Component {component} ({version}) flagged by {data['positives']} scanners"
                        })
        except Exception as e:
            results['error'] = f'VirusTotal plugin check failed: {str(e)}'
        
        return results
    
    async def _save_virustotal_results(self, identifier: str, data: dict, scan_type: str):
        """Save VirusTotal results to the virustotal_results folder"""
        try:
            # Prefer the scan timestamp (ensures grouping per scan)
            timestamp = self.scan_timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_identifier = identifier.replace('.', '_').replace('/', '_')
            filename = f"virustotal_{scan_type}_{safe_identifier}_{timestamp}.json"
            # Save inside the current scan directory if set; else fallback to central folder
            dest_dir = self.scan_output_dir if self.scan_output_dir else self.virustotal_results_dir
            os.makedirs(dest_dir, exist_ok=True)
            filepath = os.path.join(dest_dir, filename)
            
            # Add metadata to the results
            result_data = {
                'timestamp': timestamp,
                'scan_type': scan_type,
                'identifier': identifier,
                'virustotal_data': data
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(result_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"VirusTotal results saved to: {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to save VirusTotal results: {str(e)}")
    
    def _extract_social_media_links(self, soup: BeautifulSoup) -> Dict[str, List[str]]:
        """Extract social media links from the page, focusing on footer area"""
        social_links = {
            'facebook': [],
            'twitter': [],
            'instagram': [],
            'linkedin': [],
            'youtube': [],
            'tiktok': [],
            'discord': [],
            'telegram': [],
            'whatsapp': [],
            'other': []
        }
        
        # Social media patterns
        patterns = {
            'facebook': [r'facebook\.com', r'fb\.com', r'fb\.me'],
            'twitter': [r'twitter\.com', r'x\.com'],
            'instagram': [r'instagram\.com', r'instagr\.am'],
            'linkedin': [r'linkedin\.com'],
            'youtube': [r'youtube\.com', r'youtu\.be'],
            'tiktok': [r'tiktok\.com'],
            'discord': [r'discord\.gg', r'discord\.com'],
            'telegram': [r'telegram\.me', r't\.me'],
            'whatsapp': [r'wa\.me', r'whatsapp\.com']
        }
        
        # Look for links in footer, nav, and general page
        target_areas = soup.find_all(['footer', 'nav']) + soup.find_all(class_=re.compile(r'footer|social|contact', re.I))
        if not target_areas:
            target_areas = [soup]  # fallback to whole page
        
        for area in target_areas:
            links = area.find_all('a', href=True)
            for link in links:
                href = link.get('href', '').lower()
                
                # Check each social media pattern
                found = False
                for platform, platform_patterns in patterns.items():
                    for pattern in platform_patterns:
                        if re.search(pattern, href):
                            if href not in social_links[platform]:
                                social_links[platform].append(href)
                            found = True
                            break
                    if found:
                        break
                
                # If it's a social-looking link but not in known patterns
                if not found and any(word in href for word in ['social', 'follow', 'connect']):
                    if href not in social_links['other']:
                        social_links['other'].append(href)
        
        # Remove empty categories and limit results
        filtered_links = {}
        for platform, urls in social_links.items():
            if urls:
                filtered_links[platform] = urls[:3]  # Limit to 3 per platform
        
        return filtered_links
    
    async def close(self):
        """Close the aiohttp session"""
        if not self._closed:
            try:
                await self.session.close()
            finally:
                self._closed = True
