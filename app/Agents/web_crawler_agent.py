#!/usr/bin/env python3
"""
Advanced Web Crawler - Similar to OWASP ZAP
Intelligent crawling with hidden file discovery and categorized results
"""

import httpx
import asyncio
import urllib.parse
import urllib.robotparser
import re
import json
import time
import threading
import queue
import hashlib
import os
import sys
from datetime import datetime
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, parse_qs
import random
import string
import base64
from collections import defaultdict
import mimetypes
import subprocess
import aiofiles

# Color output support
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

@dataclass
class CrawlResult:
    """Data class to store crawl results"""
    url: str
    status_code: int
    content_type: str
    content_length: int
    response_time: float
    title: str = ""
    forms: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    inputs: List[Dict] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict] = field(default_factory=list)
    redirect_chain: List[str] = field(default_factory=list)
    error_details: str = ""
    file_category: str = ""
    sensitivity_level: str = "low"

class IntelligentWebCrawler:
    """Advanced Web Crawler with OWASP ZAP-like capabilities"""
    
    def __init__(self, target_domain: str, max_threads: int = 10, max_depth: int = 3):
        self.target_domain = self._normalize_domain(target_domain)
        self.base_url = f"https://{self.target_domain}"
        self.max_threads = max_threads
        self.max_depth = max_depth
        
        # Crawling state
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.url_queue = queue.Queue()
        self.results: List[CrawlResult] = []
        self.lock = threading.Lock()
        
        # HTTP client configuration
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 AdvancedWebCrawler/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # HTTP client limits for better performance
        self.limits = httpx.Limits(max_keepalive_connections=100, max_connections=200)
        self.timeout = httpx.Timeout(10.0, connect=5.0)
        
        # Configuration
        self.request_timeout = 10
        self.request_delay = 0.1
        self.max_redirects = 5
        self.max_file_size = 10 * 1024 * 1024  # 10MB
        
        # Intelligence patterns
        self.load_intelligence_patterns()
        
        # Statistics
        self.stats = {
            'urls_discovered': 0,
            'urls_crawled': 0,
            'files_found': 0,
            'forms_found': 0,
            'errors_encountered': 0,
            'hidden_files_found': 0,
            'sensitive_files_found': 0,
            'start_time': None,
            'end_time': None
        }
    
    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain name"""
        domain = domain.strip()
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        return domain.lower()
    
    def load_intelligence_patterns(self):
        """Load intelligence patterns for smart crawling"""
        # Hidden directories and files to discover
        self.hidden_paths = [
            # Common admin paths
            '/admin', '/administrator', '/admin.php', '/admin.html', '/admin.asp',
            '/admin.aspx', '/admin.jsp', '/admin/', '/administrator/', '/admin/login',
            '/admin/admin', '/admin/index', '/administrator/index', '/admin/login.php',
            '/admin/login.html', '/admin/cp', '/admin/panel', '/administrator/login',
            '/admin/account', '/admin/admin.html', '/administrator.html', '/admin.htm',
            '/administrator.htm', '/admin/controlpanel', '/admincp', '/adminpanel',
            '/fileadmin', '/sysadmin', '/adm', '/admin/account.html', '/admin/index.html',
            '/admin/home', '/admin/controlpanel.html', '/admin/cp.html', '/cp.html',
            '/administrator/account.html', '/administrator.php', '/administrator/admin',
            '/admin/manage', '/management', '/webadmin', '/admin/admin.asp',
            '/admin/admin-login', '/admin-login', '/admin/admin_login', '/admin_login',
            
            # Configuration files
            '/.env', '/.env.local', '/.env.production', '/.env.staging', '/.env.development',
            '/config.php', '/config.inc.php', '/config.inc', '/config.xml', '/config.yml',
            '/config.yaml', '/configuration.php', '/settings.php', '/settings.ini',
            '/app.config', '/web.config', '/application.properties', '/config.properties',
            '/database.yml', '/database.php', '/db.php', '/database.inc.php',
            '/wp-config.php', '/wp-config-sample.php', '/configuration.php-dist',
            
            # Backup files
            '/backup', '/backups', '/backup.sql', '/backup.zip', '/backup.tar.gz',
            '/backup.tar', '/site.zip', '/website.zip', '/backup.rar', '/backup.7z',
            '/db_backup.sql', '/database.sql', '/dump.sql', '/backup.sql.gz',
            '/backup.sql.bz2', '/backup.sql.zip', '/backup.sql.tar.gz',
            
            # Version control
            '/.git', '/.git/', '/.git/HEAD', '/.git/config', '/.git/index',
            '/.gitignore', '/.gitmodules', '/.git/logs/HEAD', '/.git/refs/heads/master',
            '/.svn', '/.svn/', '/.svn/entries', '/.svn/wc.db', '/.svn/all-wcprops',
            '/.hg', '/.hg/', '/.hgignore', '/.bzr', '/.cvs',
            
            # Documentation and info
            '/readme', '/README', '/readme.txt', '/README.txt', '/readme.md',
            '/README.md', '/docs', '/documentation', '/doc', '/help', '/manual',
            '/info.php', '/phpinfo.php', '/info', '/test.php', '/test', '/demo',
            '/example', '/examples', '/sample', '/samples', '/tutorial', '/guide',
            
            # Development files
            '/dev', '/development', '/test', '/testing', '/stage', '/staging',
            '/debug', '/temp', '/tmp', '/temporary', '/cache', '/logs', '/log',
            '/error_log', '/access_log', '/error.log', '/access.log', '/debug.log',
            '/console', '/shell', '/cmd', '/terminal', '/phpmyadmin', '/pma',
            '/adminer', '/adminer.php', '/sqlmanager', '/mysql', '/database',
            
            # Common files
            '/robots.txt', '/sitemap.xml', '/sitemap.txt', '/humans.txt', '/security.txt',
            '/crossdomain.xml', '/clientaccesspolicy.xml', '/.well-known',
            '/.htaccess', '/.htpasswd', '/web.config', '/WEB-INF', '/META-INF',
            '/server-status', '/server-info', '/status', '/health', '/ping',
            '/favicon.ico', '/apple-touch-icon.png', '/browserconfig.xml',
            
            # API endpoints
            '/api', '/api/', '/api/v1', '/api/v2', '/rest', '/rest/', '/graphql',
            '/swagger', '/swagger.json', '/swagger.yaml', '/openapi.json',
            '/api-docs', '/docs/api', '/redoc', '/api/swagger', '/api/docs',
            
            # Upload directories
            '/uploads', '/upload', '/files', '/file', '/documents', '/docs',
            '/attachments', '/media', '/images', '/img', '/pics', '/pictures',
            '/assets', '/static', '/resources', '/content', '/data',
            
            # Error pages
            '/404', '/403', '/500', '/error', '/errors', '/404.html', '/403.html',
            '/500.html', '/error.html', '/not_found', '/forbidden', '/unauthorized',
        ]
        
        # File extensions to look for
        self.file_extensions = [
            # Web files
            '.php', '.asp', '.aspx', '.jsp', '.jspx', '.html', '.htm', '.xhtml',
            '.xml', '.json', '.js', '.css', '.txt', '.md', '.pdf', '.doc', '.docx',
            '.xls', '.xlsx', '.ppt', '.pptx', '.rtf', '.csv', '.log',
            
            # Archives
            '.zip', '.rar', '.7z', '.tar', '.tar.gz', '.tar.bz2', '.gz', '.bz2',
            
            # Databases
            '.sql', '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb',
            
            # Configuration
            '.config', '.conf', '.cfg', '.ini', '.properties', '.yml', '.yaml',
            '.env', '.htaccess', '.htpasswd',
            
            # Backup files
            '.bak', '.backup', '.old', '.orig', '.copy', '.tmp', '.temp',
            '.save', '.swp', '.swo', '.~', '.backup~',
            
            # Source code
            '.java', '.py', '.rb', '.go', '.c', '.cpp', '.cs', '.vb', '.pl',
            '.sh', '.bat', '.ps1', '.sql',
        ]
        
        # Technology fingerprints
        self.tech_patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'wp-admin', r'wordpress'],
            'Drupal': [r'sites/default', r'modules/', r'drupal'],
            'Joomla': [r'components/', r'modules/', r'joomla'],
            'Apache': [r'Server: Apache', r'apache'],
            'Nginx': [r'Server: nginx', r'nginx'],
            'PHP': [r'\.php', r'PHP/', r'X-Powered-By: PHP'],
            'ASP.NET': [r'\.aspx?', r'X-AspNet-Version', r'X-Powered-By: ASP.NET'],
            'Java': [r'\.jsp', r'jsessionid', r'X-Powered-By: Servlet'],
            'Python': [r'\.py', r'Django', r'Flask'],
            'Ruby': [r'\.rb', r'Ruby on Rails'],
            'Node.js': [r'X-Powered-By: Express', r'node.js'],
            'IIS': [r'Server: Microsoft-IIS', r'X-Powered-By: ASP.NET'],
            'Cloudflare': [r'cf-ray', r'cloudflare'],
            'AWS': [r'amazonaws.com', r'x-amz-'],
        }
        
        # Security headers to check
        self.security_headers = [
            'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
            'Strict-Transport-Security', 'Content-Security-Policy',
            'X-Permitted-Cross-Domain-Policies', 'Referrer-Policy',
            'Feature-Policy', 'X-Download-Options', 'X-DNS-Prefetch-Control'
        ]
        
        # Sensitive patterns in content
        self.sensitive_patterns = {
            'passwords': [r'password\s*[:=]\s*["\']?[^"\'\s]+', r'pwd\s*[:=]\s*["\']?[^"\'\s]+'],
            'api_keys': [r'api[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}', r'apikey\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}'],
            'tokens': [r'token\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}', r'access[_-]?token\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}'],
            'secrets': [r'secret\s*[:=]\s*["\']?[^"\'\s]+', r'private[_-]?key\s*[:=]\s*["\']?[^"\'\s]+'],
            'database': [r'mysql://[^"\'\s]+', r'postgres://[^"\'\s]+', r'mongodb://[^"\'\s]+'],
            'emails': [r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'],
            'ip_addresses': [r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'],
            'urls': [r'https?://[^\s<>"\']+'],
        }
    
    def print_status(self, message: str, level: str = "info"):
        """Print colored status messages"""
        if not COLORS_AVAILABLE:
            print(f"[{level.upper()}] {message}")
            return
        
        colors = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "debug": Fore.MAGENTA
        }
        
        color = colors.get(level, Fore.WHITE)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] {message}{Style.RESET_ALL}")
    
    def print_banner(self):
        """Print crawler banner"""
        banner = f"""
{Fore.CYAN if COLORS_AVAILABLE else ''}
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🕷️  Advanced Web Crawler v1.0 🕷️                         ║
║                         OWASP ZAP-like Capabilities                          ║
║                 Live URL Filtering - 200 OK Responses Only                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL if COLORS_AVAILABLE else ''}
        """
        print(banner)
        self.print_status(f"Target Domain: {self.target_domain}", "info")
        self.print_status(f"Max Threads: {self.max_threads}", "info")
        self.print_status(f"Max Depth: {self.max_depth}", "info")
    
    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid and within scope"""
        try:
            parsed = urlparse(url)
            
            # Must be HTTP/HTTPS
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Must be same domain or subdomain
            if not (parsed.netloc == self.target_domain or 
                   parsed.netloc.endswith(f'.{self.target_domain}')):
                return False
            
            # Skip certain file types
            skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', 
                             '.svg', '.webp', '.mp4', '.avi', '.mov', '.mp3', 
                             '.wav', '.flac', '.pdf', '.doc', '.docx', '.xls', 
                             '.xlsx', '.ppt', '.pptx']
            
            path = parsed.path.lower()
            if any(path.endswith(ext) for ext in skip_extensions):
                return False
            
            return True
            
        except Exception:
            return False
    
    def normalize_url(self, url: str, base_url: str = None) -> str:
        """Normalize and resolve relative URLs"""
        if base_url:
            url = urljoin(base_url, url)
        
        parsed = urlparse(url)
        # Remove fragment
        normalized = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, 
            parsed.params, parsed.query, ''
        ))
        
        return normalized
    
    def extract_links(self, content: str, base_url: str) -> List[str]:
        """Extract all links from HTML content"""
        links = []
        
        # HTML links
        link_patterns = [
            r'href\s*=\s*["\']([^"\']+)["\']',
            r'src\s*=\s*["\']([^"\']+)["\']',
            r'action\s*=\s*["\']([^"\']+)["\']',
            r'url\s*=\s*["\']([^"\']+)["\']',
            r'content\s*=\s*["\'][^"\']*url=([^"\']+)["\']',
        ]
        
        for pattern in link_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                try:
                    normalized_url = self.normalize_url(match, base_url)
                    if self.is_valid_url(normalized_url):
                        links.append(normalized_url)
                except:
                    continue
        
        # JavaScript URLs
        js_patterns = [
            r'["\']([^"\']*\.(?:php|asp|aspx|jsp|html|htm)(?:\?[^"\']*)?)["\']',
            r'["\']([^"\']*\/[^"\']*)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                try:
                    if '/' in match and not match.startswith('http'):
                        normalized_url = self.normalize_url(match, base_url)
                        if self.is_valid_url(normalized_url):
                            links.append(normalized_url)
                except:
                    continue
        
        return list(set(links))
    
    def extract_forms(self, content: str) -> List[Dict]:
        """Extract form information from HTML"""
        forms = []
        
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms_matches = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for form_content in forms_matches:
            # Extract form attributes
            action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            method_match = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else ""
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Extract input fields
            inputs = []
            input_pattern = r'<input[^>]*>'
            input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            for input_tag in input_matches:
                name_match = re.search(r'name\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                type_match = re.search(r'type\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                
                if name_match:
                    inputs.append({
                        'name': name_match.group(1),
                        'type': type_match.group(1) if type_match else 'text',
                        'value': value_match.group(1) if value_match else ''
                    })
            
            forms.append({
                'action': action,
                'method': method,
                'inputs': inputs
            })
        
        return forms
    
    def extract_scripts(self, content: str) -> List[str]:
        """Extract JavaScript sources"""
        scripts = []
        
        # External scripts
        script_pattern = r'<script[^>]*src\s*=\s*["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(script_pattern, content, re.IGNORECASE)
        scripts.extend(matches)
        
        # Inline scripts
        inline_pattern = r'<script[^>]*>(.*?)</script>'
        inline_matches = re.findall(inline_pattern, content, re.DOTALL | re.IGNORECASE)
        for script in inline_matches:
            if script.strip():
                scripts.append(f"inline:{script[:100]}...")
        
        return scripts
    
    def extract_comments(self, content: str) -> List[str]:
        """Extract HTML comments"""
        comment_pattern = r'<!--(.*?)-->'
        comments = re.findall(comment_pattern, content, re.DOTALL)
        return [comment.strip() for comment in comments if comment.strip()]
    
    def detect_technologies(self, content: str, headers: Dict) -> List[str]:
        """Detect technologies used"""
        technologies = []
        
        # Check headers and content for technology fingerprints
        text_to_check = content.lower() + str(headers).lower()
        
        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_to_check, re.IGNORECASE):
                    technologies.append(tech)
                    break
        
        return list(set(technologies))
    
    def analyze_security_headers(self, headers: Dict) -> Dict[str, str]:
        """Analyze security headers"""
        security_headers = {}
        
        for header in self.security_headers:
            if header.lower() in [h.lower() for h in headers.keys()]:
                # Find the actual header name (case-insensitive)
                actual_header = next(h for h in headers.keys() if h.lower() == header.lower())
                security_headers[header] = headers[actual_header]
        
        return security_headers
    
    def extract_sensitive_data(self, content: str) -> Dict[str, List[str]]:
        """Extract potentially sensitive data from content"""
        sensitive_data = {}
        
        for data_type, patterns in self.sensitive_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE)
                matches.extend(found)
            
            if matches:
                sensitive_data[data_type] = list(set(matches))
        
        return sensitive_data
    
    def categorize_file(self, url: str, content_type: str, content: str) -> Tuple[str, str]:
        """Categorize discovered files and determine sensitivity"""
        path = urlparse(url).path.lower()
        
        # Admin/Management files
        admin_indicators = ['admin', 'administrator', 'manage', 'control', 'panel']
        if any(indicator in path for indicator in admin_indicators):
            return "Admin/Management", "high"
        
        # Configuration files
        config_indicators = ['config', 'settings', '.env', 'database', 'db']
        if any(indicator in path for indicator in config_indicators):
            return "Configuration", "critical"
        
        # Backup files
        backup_indicators = ['backup', '.bak', '.old', '.zip', '.sql']
        if any(indicator in path for indicator in backup_indicators):
            return "Backup/Archive", "high"
        
        # Version control
        vcs_indicators = ['.git', '.svn', '.hg', '.bzr']
        if any(indicator in path for indicator in vcs_indicators):
            return "Version Control", "critical"
        
        # API endpoints
        api_indicators = ['api', 'rest', 'graphql', 'swagger']
        if any(indicator in path for indicator in api_indicators):
            return "API Endpoint", "medium"
        
        # Documentation
        doc_indicators = ['readme', 'docs', 'documentation', 'help', 'manual']
        if any(indicator in path for indicator in doc_indicators):
            return "Documentation", "low"
        
        # Upload directories
        upload_indicators = ['upload', 'files', 'media', 'attachments']
        if any(indicator in path for indicator in upload_indicators):
            return "Upload Directory", "medium"
        
        # Development files
        dev_indicators = ['test', 'debug', 'dev', 'staging', 'console']
        if any(indicator in path for indicator in dev_indicators):
            return "Development", "medium"
        
        # Check for sensitive content
        if content:
            sensitive_data = self.extract_sensitive_data(content)
            if any(sensitive_data.values()):
                return "Sensitive Content", "critical"
        
        # Default categorization based on content type
        if 'text/html' in content_type:
            return "Web Page", "low"
        elif 'application/json' in content_type:
            return "JSON Data", "medium"
        elif 'text/xml' in content_type or 'application/xml' in content_type:
            return "XML Data", "medium"
        elif 'text/plain' in content_type:
            return "Text File", "low"
        else:
            return "Other", "low"
    
    async def check_url_alive(self, client: httpx.AsyncClient, url: str) -> Tuple[str, bool, int, str]:
        """Check if a URL is alive and return basic info"""
        try:
            response = await client.head(url, follow_redirects=True)
            return url, True, response.status_code, response.headers.get('content-type', '')
        except httpx.RequestError:
            try:
                # Try GET request if HEAD fails
                response = await client.get(url, follow_redirects=True)
                return url, True, response.status_code, response.headers.get('content-type', '')
            except:
                return url, False, 0, ''
        except Exception:
            return url, False, 0, ''
    
    async def filter_live_urls(self, urls: List[str]) -> List[Tuple[str, int, str]]:
        """Filter URLs to only include ones with 200 OK status using async httpx"""
        live_urls = []
        
        async with httpx.AsyncClient(
            headers=self.headers,
            timeout=self.timeout,
            limits=self.limits,
            verify=False  # Skip SSL verification for broader compatibility
        ) as client:
            
            self.print_status(f"🔍 Checking {len(urls)} URLs for 200 OK responses...", "info")
            
            # Create semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(self.max_threads * 2)
            
            async def check_with_semaphore(url):
                async with semaphore:
                    return await self.check_url_alive(client, url)
            
            # Check all URLs concurrently
            tasks = [check_with_semaphore(url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, tuple):
                    url, is_alive, status_code, content_type = result
                    if is_alive and status_code == 200:
                        live_urls.append((url, status_code, content_type))
                        self.print_status(f"✅ Live (200): {url}", "success")
                    elif is_alive and status_code != 200:
                        self.print_status(f"⚠️  Skipping {url} [{status_code}] - Not 200 OK", "warning")
        
        self.print_status(f"📊 Found {len(live_urls)} URLs with 200 OK status out of {len(urls)}", "info")
        return live_urls

    def crawl_url(self, url: str, depth: int = 0) -> Optional[CrawlResult]:
        """Crawl a single URL and extract information"""
        if depth > self.max_depth or url in self.visited_urls:
            return None
        
        with self.lock:
            if url in self.visited_urls:
                return None
            self.visited_urls.add(url)
        
        try:
            self.print_status(f"Crawling: {url} (depth: {depth})", "debug")
            
            start_time = time.time()
            
            # Use httpx for the request
            with httpx.Client(
                headers=self.headers,
                timeout=self.timeout,
                limits=self.limits,
                verify=False,
                follow_redirects=True
            ) as client:
                response = client.get(url)
            
            # Only process 200 OK responses
            if response.status_code != 200:
                self.print_status(f"⚠️  Skipping {url} [{response.status_code}] - Not 200 OK", "warning")
                with self.lock:
                    self.stats['errors_encountered'] += 1
                return None
            
            # Check content length
            content_length = int(response.headers.get('content-length', 0))
            if content_length > self.max_file_size:
                self.print_status(f"Skipping large file: {url} ({content_length} bytes)", "warning")
                return None
            
            # Get content safely
            content = ""
            try:
                content = response.text
            except UnicodeDecodeError:
                try:
                    content = response.content.decode('utf-8', errors='ignore')
                except:
                    content = response.content.decode('latin-1', errors='ignore')
            except Exception as e:
                self.print_status(f"⚠️ Content extraction failed: {str(e)}", "warning")
                content = ""
            
            response_time = time.time() - start_time
            
            # Extract page title
            title = ""
            try:
                title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip() if title_match else ""
            except Exception as e:
                self.print_status(f"⚠️ Title extraction failed: {str(e)}", "warning")
                title = ""
            
            # Extract information
            try:
                links = self.extract_links(content, url)
            except Exception as e:
                self.print_status(f"⚠️ Link extraction failed: {str(e)}", "warning")
                links = []
            
            try:
                forms = self.extract_forms(content)
            except Exception as e:
                self.print_status(f"⚠️ Form extraction failed: {str(e)}", "warning")
                forms = []
            
            try:
                scripts = self.extract_scripts(content)
            except Exception as e:
                self.print_status(f"⚠️ Script extraction failed: {str(e)}", "warning")
                scripts = []
            
            try:
                comments = self.extract_comments(content)
            except Exception as e:
                self.print_status(f"⚠️ Comment extraction failed: {str(e)}", "warning")
                comments = []
            
            try:
                technologies = self.detect_technologies(content, dict(response.headers))
            except Exception as e:
                self.print_status(f"⚠️ Technology detection failed: {str(e)}", "warning")
                technologies = []
            
            try:
                security_headers = self.analyze_security_headers(dict(response.headers))
            except Exception as e:
                self.print_status(f"⚠️ Security header analysis failed: {str(e)}", "warning")
                security_headers = {}
            
            # Extract cookies
            cookies = []
            try:
                if hasattr(response, 'cookies') and response.cookies:
                    # Try different methods to extract cookies
                    try:
                        # Method 1: Direct cookie jar access
                        if hasattr(response.cookies, 'jar'):
                            for cookie in response.cookies.jar:
                                cookies.append({
                                    'name': getattr(cookie, 'name', str(cookie)),
                                    'value': getattr(cookie, 'value', ''),
                                    'domain': getattr(cookie, 'domain', ''),
                                    'path': getattr(cookie, 'path', '/'),
                                    'secure': getattr(cookie, 'secure', False),
                                    'httponly': getattr(cookie, 'httponly', False)
                                })
                    except Exception:
                        # Method 2: Iterate over cookies directly
                        try:
                            for cookie in response.cookies:
                                if hasattr(cookie, 'name') and hasattr(cookie, 'value'):
                                    cookies.append({
                                        'name': cookie.name,
                                        'value': cookie.value,
                                        'domain': getattr(cookie, 'domain', ''),
                                        'path': getattr(cookie, 'path', '/'),
                                        'secure': getattr(cookie, 'secure', False),
                                        'httponly': getattr(cookie, 'httponly', False)
                                    })
                                else:
                                    # Handle string representation
                                    cookie_str = str(cookie)
                                    if '=' in cookie_str:
                                        name, value = cookie_str.split('=', 1)
                                        cookies.append({
                                            'name': name.strip(),
                                            'value': value.strip(),
                                            'domain': '',
                                            'path': '/',
                                            'secure': False,
                                            'httponly': False
                                        })
                        except Exception:
                            # Method 3: Parse from headers
                            set_cookie_headers = response.headers.get_list('set-cookie')
                            for header in set_cookie_headers:
                                if '=' in header:
                                    cookie_part = header.split(';')[0]  # Get main name=value part
                                    if '=' in cookie_part:
                                        name, value = cookie_part.split('=', 1)
                                        cookies.append({
                                            'name': name.strip(),
                                            'value': value.strip(),
                                            'domain': '',
                                            'path': '/',
                                            'secure': 'Secure' in header,
                                            'httponly': 'HttpOnly' in header
                                        })
            except Exception as e:
                # If cookie extraction fails, just continue with empty list
                self.print_status(f"⚠️ Cookie extraction failed: {str(e)}", "warning")
                cookies = []
            
            # Get redirect chain
            redirect_chain = []
            try:
                if hasattr(response, 'history'):
                    redirect_chain = [str(resp.url) for resp in response.history if hasattr(resp, 'url')]
            except Exception as e:
                self.print_status(f"⚠️ Redirect chain extraction failed: {str(e)}", "warning")
                redirect_chain = []
            
            # Categorize file
            try:
                file_category, sensitivity_level = self.categorize_file(
                    url, 
                    response.headers.get('content-type', ''), 
                    content
                )
            except Exception as e:
                self.print_status(f"⚠️ File categorization failed: {str(e)}", "warning")
                file_category = "Unknown"
                sensitivity_level = "low"
            
            # Create result object
            try:
                result = CrawlResult(
                    url=url,
                    status_code=response.status_code,
                    content_type=response.headers.get('content-type', ''),
                    content_length=len(content),
                    response_time=response_time,
                    title=title,
                    forms=forms,
                    links=links,
                    scripts=scripts,
                    comments=comments,
                    technologies=technologies,
                    security_headers=security_headers,
                    cookies=cookies,
                    redirect_chain=redirect_chain,
                    file_category=file_category,
                    sensitivity_level=sensitivity_level
                )
            except Exception as e:
                self.print_status(f"❌ Failed to create result object: {str(e)}", "error")
                return None
            
            # Filter new links for 200 OK responses before adding to queue
            new_links = [link for link in links if link not in self.visited_urls and link not in self.discovered_urls]
            
            if new_links and depth < self.max_depth:
                try:
                    # Quick async check for new links (200 OK only)
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    live_links = loop.run_until_complete(self.filter_live_urls(new_links[:20]))  # Limit to 20 new links per page
                    loop.close()
                    
                    # Add 200 OK links to queue
                    with self.lock:
                        for link_info in live_links:
                            link = link_info[0] if isinstance(link_info, tuple) else link_info
                            if link not in self.discovered_urls:
                                self.discovered_urls.add(link)
                                self.url_queue.put((link, depth + 1))
                except Exception as e:
                    # Fallback: add first 10 links without filtering
                    with self.lock:
                        for link in new_links[:10]:
                            self.discovered_urls.add(link)
                            self.url_queue.put((link, depth + 1))
            
            # Update statistics
            with self.lock:
                self.stats['urls_crawled'] += 1
                self.stats['forms_found'] += len(forms)
                if file_category != "Web Page":
                    self.stats['files_found'] += 1
                if sensitivity_level in ['high', 'critical']:
                    self.stats['sensitive_files_found'] += 1
            
            self.print_status(f"✅ Crawled (200): {url} - {file_category} ({sensitivity_level})", "success")
            
            return result
            
        except httpx.TimeoutException:
            self.print_status(f"⏰ Timeout: {url}", "warning")
            with self.lock:
                self.stats['errors_encountered'] += 1
        except httpx.ConnectError:
            self.print_status(f"🔌 Connection error: {url}", "warning")
            with self.lock:
                self.stats['errors_encountered'] += 1
        except httpx.RequestError:
            self.print_status(f"🌐 Request error: {url}", "warning")
            with self.lock:
                self.stats['errors_encountered'] += 1
        except Exception as e:
            self.print_status(f"❌ Error crawling {url}: {str(e)}", "error")
            with self.lock:
                self.stats['errors_encountered'] += 1
        
        return None
    
    def discover_hidden_files(self):
        """Discover hidden files and directories, filtering for 200 OK responses only"""
        self.print_status("🔍 Starting hidden file discovery...", "info")
        
        hidden_urls = []
        
        # Test common hidden paths
        for path in self.hidden_paths:
            test_url = f"{self.base_url.rstrip('/')}{path}"
            if test_url not in self.visited_urls:
                hidden_urls.append(test_url)
        
        # Test common file extensions
        base_paths = ['/', '/admin/', '/api/', '/uploads/', '/files/']
        common_names = ['index', 'login', 'admin', 'config', 'test', 'backup', 'data']
        
        for base_path in base_paths:
            for name in common_names:
                for ext in self.file_extensions[:15]:  # Reduced to prevent too many requests
                    test_url = f"{self.base_url.rstrip('/')}{base_path}{name}{ext}"
                    if test_url not in self.visited_urls:
                        hidden_urls.append(test_url)
        
        self.print_status(f"🎯 Generated {len(hidden_urls)} potential hidden URLs", "info")
        
        # Filter for 200 OK URLs using async httpx
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            live_urls = loop.run_until_complete(self.filter_live_urls(hidden_urls))
            loop.close()
        except Exception as e:
            self.print_status(f"❌ Error filtering URLs for 200 OK: {str(e)}", "error")
            # Fallback to adding all URLs if filtering fails
            live_urls = [(url, 0, '') for url in hidden_urls]
        
        # Add only 200 OK URLs to discovery set and queue
        with self.lock:
            for url_info in live_urls:
                url = url_info[0] if isinstance(url_info, tuple) else url_info
                if url not in self.discovered_urls:
                    self.discovered_urls.add(url)
                    self.url_queue.put((url, 0))
                    self.stats['urls_discovered'] += 1
                    self.stats['hidden_files_found'] += 1
    
    def worker_thread(self):
        """Worker thread for crawling URLs"""
        while True:
            try:
                url, depth = self.url_queue.get(timeout=5)
                result = self.crawl_url(url, depth)
                if result:
                    with self.lock:
                        self.results.append(result)
                self.url_queue.task_done()
                time.sleep(self.request_delay)
            except queue.Empty:
                break
            except Exception as e:
                self.print_status(f"Worker error: {str(e)}", "error")
                continue
    
    def start_crawling(self):
        """Start the crawling process with live URL filtering"""
        self.print_banner()
        self.stats['start_time'] = datetime.now()
        
        # Check if base URL returns 200 OK first
        self.print_status("🔍 Checking base URL for 200 OK response...", "info")
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            base_check = loop.run_until_complete(self.filter_live_urls([self.base_url]))
            loop.close()
            
            if not base_check:
                self.print_status(f"❌ Base URL {self.base_url} does not return 200 OK", "error")
                return
            else:
                self.print_status(f"✅ Base URL returns 200 OK", "success")
        except Exception as e:
            self.print_status(f"⚠️ Could not verify base URL, proceeding anyway: {str(e)}", "warning")
        
        # Add initial URL
        self.url_queue.put((self.base_url, 0))
        self.discovered_urls.add(self.base_url)
        self.stats['urls_discovered'] = 1
        
        # Discover hidden files (now filters for live URLs)
        self.discover_hidden_files()
        
        self.print_status(f"🚀 Starting crawl with {self.max_threads} threads on 200 OK URLs only...", "info")
        
        # Start worker threads
        threads = []
        for i in range(self.max_threads):
            thread = threading.Thread(target=self.worker_thread)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all tasks to complete
        self.url_queue.join()
        
        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=1)
        
        self.stats['end_time'] = datetime.now()
        self.print_status("✅ Crawling completed!", "success")
    
    def categorize_results(self) -> Dict[str, List[CrawlResult]]:
        """Categorize crawl results for easy understanding"""
        categories = defaultdict(list)
        
        for result in self.results:
            categories[result.file_category].append(result)
        
        return dict(categories)
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive crawl report"""
        categorized_results = self.categorize_results()
        
        # Calculate statistics
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds() if self.stats['start_time'] and self.stats['end_time'] else 0
        
        # Sensitivity analysis
        sensitivity_counts = defaultdict(int)
        for result in self.results:
            sensitivity_counts[result.sensitivity_level] += 1
        
        # Technology analysis
        all_technologies = []
        for result in self.results:
            all_technologies.extend(result.technologies)
        tech_counts = defaultdict(int)
        for tech in all_technologies:
            tech_counts[tech] += 1
        
        # Form analysis
        all_forms = []
        for result in self.results:
            all_forms.extend(result.forms)
        
        # Security headers analysis
        header_coverage = defaultdict(int)
        for result in self.results:
            for header in result.security_headers:
                header_coverage[header] += 1
        
        report = {
            'crawl_summary': {
                'target_domain': self.target_domain,
                'crawl_duration': duration,
                'urls_discovered': len(self.discovered_urls),
                'urls_successfully_crawled': len(self.results),
                'errors_encountered': self.stats['errors_encountered'],
                'start_time': self.stats['start_time'].isoformat() if self.stats['start_time'] else None,
                'end_time': self.stats['end_time'].isoformat() if self.stats['end_time'] else None,
            },
            'discovery_statistics': {
                'total_files_found': self.stats['files_found'],
                'total_forms_found': self.stats['forms_found'],
                'sensitive_files_found': self.stats['sensitive_files_found'],
                'hidden_files_discovered': len([r for r in self.results if 'hidden' in r.url.lower() or r.status_code == 200]),
            },
            'categorized_findings': {},
            'sensitivity_analysis': dict(sensitivity_counts),
            'technology_fingerprints': dict(tech_counts),
            'security_analysis': {
                'security_headers_coverage': dict(header_coverage),
                'forms_discovered': len(all_forms),
                'cookies_found': sum(len(result.cookies) for result in self.results),
            },
            'detailed_results': []
        }
        
        # Add categorized findings with details
        for category, results in categorized_results.items():
            category_data = {
                'count': len(results),
                'sensitivity_breakdown': defaultdict(int),
                'urls': []
            }
            
            for result in results:
                category_data['sensitivity_breakdown'][result.sensitivity_level] += 1
                category_data['urls'].append({
                    'url': result.url,
                    'status_code': result.status_code,
                    'content_type': result.content_type,
                    'sensitivity_level': result.sensitivity_level,
                    'title': result.title,
                    'forms_count': len(result.forms),
                    'technologies': result.technologies,
                    'response_time': result.response_time
                })
            
            category_data['sensitivity_breakdown'] = dict(category_data['sensitivity_breakdown'])
            report['categorized_findings'][category] = category_data
        
        # Add detailed results for critical/high sensitivity items
        for result in self.results:
            if result.sensitivity_level in ['critical', 'high']:
                detailed_result = {
                    'url': result.url,
                    'category': result.file_category,
                    'sensitivity_level': result.sensitivity_level,
                    'status_code': result.status_code,
                    'content_type': result.content_type,
                    'content_length': result.content_length,
                    'response_time': result.response_time,
                    'title': result.title,
                    'forms': result.forms,
                    'technologies': result.technologies,
                    'security_headers': result.security_headers,
                    'cookies': result.cookies,
                    'comments_count': len(result.comments),
                    'scripts_count': len(result.scripts),
                    'redirect_chain': result.redirect_chain
                }
                report['detailed_results'].append(detailed_result)
        
        return report
    
    def print_summary(self):
        """Print crawl summary"""
        categorized = self.categorize_results()
        
        print(f"\n{Fore.GREEN if COLORS_AVAILABLE else ''}🎯 CRAWL SUMMARY{Style.RESET_ALL if COLORS_AVAILABLE else ''}")
        print("=" * 60)
        
        print(f"Target Domain: {self.target_domain}")
        print(f"URLs Discovered: {len(self.discovered_urls)}")
        print(f"URLs Successfully Crawled: {len(self.results)}")
        print(f"Errors Encountered: {self.stats['errors_encountered']}")
        
        if self.stats['start_time'] and self.stats['end_time']:
            duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
            print(f"Crawl Duration: {duration:.2f} seconds")
        
        print(f"\n{Fore.YELLOW if COLORS_AVAILABLE else ''}📂 CATEGORIZED FINDINGS{Style.RESET_ALL if COLORS_AVAILABLE else ''}")
        print("-" * 40)
        
        for category, results in categorized.items():
            sensitivity_counts = defaultdict(int)
            for result in results:
                sensitivity_counts[result.sensitivity_level] += 1
            
            sensitivity_str = ", ".join([f"{level}: {count}" for level, count in sensitivity_counts.items()])
            print(f"{category}: {len(results)} items ({sensitivity_str})")
        
        # Print high-priority findings
        high_priority = [r for r in self.results if r.sensitivity_level in ['critical', 'high']]
        if high_priority:
            print(f"\n{Fore.RED if COLORS_AVAILABLE else ''}🚨 HIGH PRIORITY FINDINGS{Style.RESET_ALL if COLORS_AVAILABLE else ''}")
            print("-" * 40)
            for result in high_priority[:10]:  # Show top 10
                print(f"[{result.sensitivity_level.upper()}] {result.url} - {result.file_category}")
    
    def save_report(self, filename: str = None):
        """Save detailed report to JSON file in Reports/Web crawler/ folder"""
        # Create Reports/Web crawler directory if it doesn't exist
        reports_dir = os.path.join("Reports", "Web crawler")
        try:
            os.makedirs(reports_dir, exist_ok=True)
        except Exception as e:
            self.print_status(f"⚠️ Could not create reports directory: {str(e)}", "warning")
            # Fall back to current directory
            reports_dir = "."
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"crawl_report_{self.target_domain}_{timestamp}.json"
        
        # Ensure filename doesn't have a path (just the filename)
        filename = os.path.basename(filename)
        
        # Create full path
        full_path = os.path.join(reports_dir, filename)
        
        report = self.generate_report()
        
        try:
            with open(full_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            
            self.print_status(f"📄 Report saved to: {full_path}", "success")
            return full_path
        except Exception as e:
            self.print_status(f"❌ Failed to save report: {str(e)}", "error")
            return None

def main():
    """Main function to run the crawler"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Web Crawler - OWASP ZAP-like capabilities")
    parser.add_argument("domain", help="Target domain to crawl")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Maximum crawl depth (default: 3)")
    parser.add_argument("-o", "--output", help="Output file for report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    try:
        crawler = IntelligentWebCrawler(
            target_domain=args.domain,
            max_threads=args.threads,
            max_depth=args.depth
        )
        
        # Start crawling
        crawler.start_crawling()
        
        # Print summary
        crawler.print_summary()
        
        # Save report
        if args.output:
            crawler.save_report(args.output)
        else:
            crawler.save_report()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW if COLORS_AVAILABLE else ''}⚠️  Crawl interrupted by user{Style.RESET_ALL if COLORS_AVAILABLE else ''}")
    except Exception as e:
        print(f"\n{Fore.RED if COLORS_AVAILABLE else ''}❌ Error: {str(e)}{Style.RESET_ALL if COLORS_AVAILABLE else ''}")

if __name__ == "__main__":
    main()
