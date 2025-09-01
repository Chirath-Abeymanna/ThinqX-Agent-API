# --- Service Integration Wrapper ---
class IntelligentWebCrawler:
    def __init__(self, target_domain, max_threads=10, max_depth=3, max_urls=100, openai_api_key=None):
        self.target_domain = target_domain
        self.max_threads = max_threads
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.openai_api_key = openai_api_key
        self.report = None

    def print_status(self, message: str, level: str = "info"):
        # Default: do nothing or log
        pass

    def start_crawling(self):
        import asyncio
        self.report = asyncio.run(self._run_crawl())

    async def _run_crawl(self):
        agent = WebCrawlingAgent(openai_api_key=self.openai_api_key)
        report = await agent.crawl_domain(
            target_domain=self.target_domain,
            max_depth=self.max_depth,
            max_urls=self.max_urls
        )
        await agent.close()
        return report

    def generate_report(self):
        return self.report

    def save_report(self, output_dir="Reports/Web crawler"):
        import os, json
        from datetime import datetime
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_clean = self.target_domain.replace('://', '_').replace('/', '_').replace('.', '_')
        filename = f"crawl_report_{domain_clean}_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        return filepath
#!/usr/bin/env python3
"""
Comprehensive Web Crawling Agent using LangChain
Mimics OWASP ZAP Spidering with Hidden File Discovery

This agent performs intelligent web crawling to discover:
- Hidden files and directories
- Unlinked URLs
- Common web vulnerabilities
- Technology fingerprints
- Security misconfigurations
"""

import asyncio
import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import logging

# Core dependencies
import httpx
from bs4 import BeautifulSoup
import urllib3
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import colorama
from colorama import Fore, Style

# LangChain imports
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.schema import BaseMessage, HumanMessage, AIMessage
from langchain.tools import BaseTool
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.memory import ConversationBufferMemory
from langchain.schema.runnable import RunnablePassthrough

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize colorama for cross-platform colored output
colorama.init()

@dataclass
class CrawlResult:
    """Represents a single crawl result with metadata"""
    url: str
    status_code: int
    content_type: str
    content_length: int
    response_time: float
    headers: Dict[str, str]
    title: Optional[str] = None
    forms: List[Dict] = None
    links: List[str] = None
    scripts: List[str] = None
    technologies: List[str] = None
    security_headers: Dict[str, str] = None
    is_hidden: bool = False
    is_sensitive: bool = False
    error: Optional[str] = None

    def __post_init__(self):
        if self.forms is None:
            self.forms = []
        if self.links is None:
            self.links = []
        if self.scripts is None:
            self.scripts = []
        if self.technologies is None:
            self.technologies = []
        if self.security_headers is None:
            self.security_headers = {}

@dataclass
class CrawlSummary:
    """Summary statistics for the crawl session"""
    target_domain: str
    crawl_duration: float
    urls_discovered: int
    urls_successfully_crawled: int
    errors_encountered: int
    start_time: str
    end_time: Optional[str] = None

class WebCrawlerTool(BaseTool):
    """LangChain tool for web crawling operations"""
    
    name: str = "web_crawler"
    description: str = "Crawls a specific URL and returns detailed information about the response"
    client: httpx.AsyncClient
    
    def __init__(self, client: httpx.AsyncClient):
        super().__init__(client=client)
    
    def _run(self, url: str) -> str:
        """Sync implementation of the tool"""
        import asyncio
        return asyncio.run(self._arun(url))
    
    async def _arun(self, url: str) -> str:
        """Async implementation of the tool"""
        try:
            start_time = time.time()
            response = await self.client.get(url, timeout=30.0, follow_redirects=True)
            response_time = time.time() - start_time
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract information
            title = soup.title.string if soup.title else None
            forms = self._extract_forms(soup, url)
            links = self._extract_links(soup, url)
            scripts = self._extract_scripts(soup, url)
            technologies = self._detect_technologies(response.headers, response.text)
            security_headers = self._extract_security_headers(response.headers)
            
            result = CrawlResult(
                url=url,
                status_code=response.status_code,
                content_type=response.headers.get('content-type', ''),
                content_length=len(response.content),
                response_time=response_time,
                headers=dict(response.headers),
                title=title,
                forms=forms,
                links=links,
                scripts=scripts,
                technologies=technologies,
                security_headers=security_headers
            )
            
            return json.dumps(asdict(result), default=str)
            
        except Exception as e:
            return json.dumps({
                "url": url,
                "error": str(e),
                "status_code": None
            })
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract form information from HTML"""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET'),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith(('http://', 'https://', '//')):
                links.append(href)
            elif href.startswith('/'):
                links.append(urljoin(base_url, href))
        
        return links
    
    def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract script sources from HTML"""
        scripts = []
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.startswith(('http://', 'https://', '//')):
                scripts.append(src)
            elif src.startswith('/'):
                scripts.append(urljoin(base_url, src))
        
        return scripts
    
    def _detect_technologies(self, headers: Dict[str, str], content: str) -> List[str]:
        """Detect technologies based on headers and content"""
        technologies = []
        
        # Server detection
        server = headers.get('server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # Framework detection
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
            elif 'express' in powered_by:
                technologies.append('Express.js')
        
        # Content-based detection
        if 'wordpress' in content.lower():
            technologies.append('WordPress')
        if 'jquery' in content.lower():
            technologies.append('jQuery')
        if 'bootstrap' in content.lower():
            technologies.append('Bootstrap')
        if 'react' in content.lower():
            technologies.append('React')
        if 'angular' in content.lower():
            technologies.append('Angular')
        
        return technologies
    
    def _extract_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract security-related headers"""
        security_headers = {}
        security_header_names = [
            'x-frame-options', 'x-content-type-options', 'x-xss-protection',
            'strict-transport-security', 'content-security-policy',
            'referrer-policy', 'permissions-policy'
        ]
        
        for header in security_header_names:
            if header in headers:
                security_headers[header] = headers[header]
        
        return security_headers

class HiddenFileDiscoveryTool(BaseTool):
    """LangChain tool for discovering hidden files and directories"""
    
    name: str = "hidden_file_discovery"
    description: str = "Discovers hidden files and directories using common patterns"
    client: httpx.AsyncClient
    common_paths: List[str] = []
    
    def __init__(self, client: httpx.AsyncClient):
        super().__init__(client=client)
        # Initialize common paths after super().__init__
        self.common_paths = [
            # Common hidden files
            '.htaccess', '.htpasswd', '.env', '.git/config', '.gitignore',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'security.txt', '.well-known/security.txt',
            
            # Backup files
            'backup/', 'backups/', 'bak/', 'old/', 'archive/',
            'backup.zip', 'backup.tar.gz', 'backup.sql',
            
            # Configuration files
            'config.php', 'config.js', 'config.json', 'config.xml',
            'wp-config.php', 'configuration.php',
            
            # Admin panels
            'admin/', 'administrator/', 'admin.php', 'admin.html',
            'login/', 'login.php', 'login.html',
            'wp-admin/', 'wp-login.php',
            
            # API endpoints
            'api/', 'api/v1/', 'api/v2/', 'rest/', 'graphql',
            
            # Development files
            'test/', 'dev/', 'development/', 'staging/',
            'phpinfo.php', 'info.php', 'test.php',
            
            # Common directories
            'images/', 'img/', 'css/', 'js/', 'assets/',
            'uploads/', 'files/', 'downloads/', 'media/',
            
            # CMS specific
            'wp-content/', 'wp-includes/', 'wp-json/',
            'joomla/', 'drupal/', 'magento/',
            
            # Server files
            'server-status', 'server-info', 'status',
            
            # Log files
            'logs/', 'log/', 'error.log', 'access.log',
            
            # Database files
            'db/', 'database/', 'sql/', 'mysql/',
            
            # Cache and temp
            'cache/', 'temp/', 'tmp/', 'sessions/',
        ]
    
    def _run(self, base_url: str) -> str:
        """Sync implementation for hidden file discovery"""
        import asyncio
        return asyncio.run(self._arun(base_url))
    
    async def _arun(self, base_url: str) -> str:
        """Async implementation for hidden file discovery"""
        discovered_files = []
        
        async def check_path(path: str) -> Optional[Dict]:
            """Check if a specific path exists"""
            try:
                url = urljoin(base_url, path)
                response = await self.client.head(url, timeout=10.0, follow_redirects=True)
                
                # Only include URLs with 200 status code
                if response.status_code == 200:
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', ''),
                        'content_length': response.headers.get('content-length', ''),
                        'is_hidden': path.startswith('.') or 'hidden' in path.lower(),
                        'is_sensitive': self._is_sensitive_file(path)
                    }
            except Exception:
                pass
            return None
        
        # Check common paths
        tasks = [check_path(path) for path in self.common_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, dict) and result:
                discovered_files.append(result)
        
        return json.dumps(discovered_files)

    def _is_sensitive_file(self, path: str) -> bool:
        """Determine if a file is potentially sensitive"""
        sensitive_patterns = [
            r'\.env', r'\.htpasswd', r'config\.', r'\.git', r'backup',
            r'\.sql', r'\.log', r'admin', r'login', r'password',
            r'secret', r'private', r'key', r'credential'
        ]
        
        path_lower = path.lower()
        return any(re.search(pattern, path_lower) for pattern in sensitive_patterns)

class WebCrawlingAgent:
    """Main web crawling agent using LangChain"""
    
    def __init__(self, openai_api_key: Optional[str] = None):
        self.console = Console()
        self.openai_api_key = openai_api_key
        self.client = httpx.AsyncClient(
            headers={
                'User-Agent': 'Mozilla/5.0 (compatible; WebCrawlerAgent/1.0; +https://github.com/your-repo)'
            },
            verify=False  # Allow self-signed certificates
        )
        
        # Initialize tools
        self.crawler_tool = WebCrawlerTool(self.client)
        self.discovery_tool = HiddenFileDiscoveryTool(self.client)
        
        # Initialize LangChain components
        if openai_api_key:
            self.llm = ChatOpenAI(
                model="gpt-3.5-turbo",
                temperature=0,
                openai_api_key=openai_api_key
            )
            self._setup_langchain_agent()
        else:
            self.llm = None
            self.agent = None
    
    def _setup_langchain_agent(self):
        """Setup the LangChain agent with tools and prompts"""
        tools = [self.crawler_tool, self.discovery_tool]
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an expert web security analyst and penetration tester. 
            Your goal is to comprehensively crawl and analyze web applications to discover:
            
            1. Hidden files and directories
            2. Unlinked URLs and endpoints
            3. Security vulnerabilities and misconfigurations
            4. Technology fingerprints
            5. Sensitive information exposure
            
            Use the available tools to perform thorough reconnaissance. Always prioritize
            security and ethical testing practices."""),
            MessagesPlaceholder(variable_name="chat_history"),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])
        
        self.agent = create_openai_functions_agent(self.llm, tools, prompt)
        self.agent_executor = AgentExecutor(
            agent=self.agent,
            tools=tools,
            verbose=True,
            handle_parsing_errors=True
        )
    
    async def crawl_domain(self, target_domain: str, max_depth: int = 3, max_urls: int = 100) -> Dict:
        """Main crawling method"""
        start_time = datetime.now()
        self.console.print(f"[bold blue]Starting comprehensive crawl of: {target_domain}[/bold blue]")
        
        # Ensure target has protocol
        if not target_domain.startswith(('http://', 'https://')):
            target_domain = f"https://{target_domain}"
        
        discovered_urls: Set[str] = set()
        crawled_urls: Set[str] = set()
        crawl_results: List[CrawlResult] = []
        errors: List[str] = []
        
        # Start with the main domain
        queue = [(target_domain, 0)]  # (url, depth)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Crawling...", total=None)
            
            while queue and len(crawled_urls) < max_urls:
                current_url, depth = queue.pop(0)
                
                if current_url in crawled_urls or depth > max_depth:
                    continue
                
                progress.update(task, description=f"Crawling: {current_url}")
                
                try:
                    # Crawl the current URL
                    result = await self._crawl_url(current_url)
                    if result:
                        crawl_results.append(result)
                        crawled_urls.add(current_url)
                        
                        # Add discovered links to queue
                        if result.links and depth < max_depth:
                            for link in result.links:
                                if self._should_crawl_link(link, target_domain):
                                    discovered_urls.add(link)
                                    if link not in crawled_urls:
                                        queue.append((link, depth + 1))
                
                except Exception as e:
                    error_msg = f"Error crawling {current_url}: {str(e)}"
                    errors.append(error_msg)
                    logger.error(error_msg)
        
        # Perform hidden file discovery
        self.console.print("[bold yellow]Performing hidden file discovery...[/bold yellow]")
        hidden_files = await self._discover_hidden_files(target_domain)
        
        # Generate comprehensive report
        end_time = datetime.now()
        crawl_duration = (end_time - start_time).total_seconds()
        
        summary = CrawlSummary(
            target_domain=target_domain,
            crawl_duration=crawl_duration,
            urls_discovered=len(discovered_urls),
            urls_successfully_crawled=len(crawled_urls),
            errors_encountered=len(errors),
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat()
        )
        
        report = self._generate_report(summary, crawl_results, hidden_files, errors)
        
        # Display results
        self._display_results(report)
        
        # Print JSON file information
        self.console.print(f"\n[bold blue]📄 JSON Report Structure:[/bold blue]")
        self.console.print(f"  • crawl_summary: Overall crawl statistics")
        self.console.print(f"  • discovery_statistics: Discovery metrics")
        self.console.print(f"  • categorized_findings: URLs categorized by sensitivity level")
        self.console.print(f"    - Other: Low sensitivity content")
        self.console.print(f"    - Sensitive Content: Medium/High/Critical sensitivity content")
        
        return report
    
    async def _crawl_url(self, url: str) -> Optional[CrawlResult]:
        """Crawl a single URL and return detailed results"""
        try:
            start_time = time.time()
            response = await self.client.get(url, timeout=30.0, follow_redirects=True)
            response_time = time.time() - start_time
            
            # Only process URLs with 200 status code
            if response.status_code != 200:
                logger.info(f"Skipping {url} - Status: {response.status_code}")
                return None
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract information
            title = soup.title.string if soup.title else None
            forms = self._extract_forms(soup, url)
            links = self._extract_links(soup, url)
            scripts = self._extract_scripts(soup, url)
            technologies = self._detect_technologies(response.headers, response.text)
            security_headers = self._extract_security_headers(response.headers)
            
            result = CrawlResult(
                url=url,
                status_code=response.status_code,
                content_type=response.headers.get('content-type', ''),
                content_length=len(response.content),
                response_time=response_time,
                headers=dict(response.headers),
                title=title,
                forms=forms,
                links=links,
                scripts=scripts,
                technologies=technologies,
                security_headers=security_headers
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error crawling {url}: {str(e)}")
            return None
    
    async def _discover_hidden_files(self, base_url: str) -> List[Dict]:
        """Discover hidden files and directories"""
        if self.agent:
            # Use LangChain agent for intelligent discovery
            result = await self.agent_executor.ainvoke({
                "input": f"Discover hidden files and directories on {base_url}. Focus on sensitive files like .env, config files, backup files, and admin panels."
            })
            return json.loads(result.get("output", "[]"))
        else:
            # Fallback to direct tool usage
            result = await self.discovery_tool._arun(base_url)
            return json.loads(result)
    
    def _should_crawl_link(self, link: str, base_domain: str) -> bool:
        """Determine if a link should be crawled"""
        try:
            parsed_link = urlparse(link)
            parsed_base = urlparse(base_domain)
            
            # Only crawl same domain
            if parsed_link.netloc and parsed_link.netloc != parsed_base.netloc:
                return False
            
            # Skip common non-content URLs
            skip_extensions = {'.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico'}
            if any(link.lower().endswith(ext) for ext in skip_extensions):
                return False
            
            # Skip common non-content paths
            skip_paths = {'/mailto:', '/tel:', '/javascript:', '/#'}
            if any(link.lower().startswith(path) for path in skip_paths):
                return False
            
            return True
        except Exception:
            return False
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract form information from HTML"""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET'),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith(('http://', 'https://', '//')):
                links.append(href)
            elif href.startswith('/'):
                links.append(urljoin(base_url, href))
        
        return links
    
    def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract script sources from HTML"""
        scripts = []
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.startswith(('http://', 'https://', '//')):
                scripts.append(src)
            elif src.startswith('/'):
                scripts.append(urljoin(base_url, src))
        
        return scripts
    
    def _detect_technologies(self, headers: Dict[str, str], content: str) -> List[str]:
        """Detect technologies based on headers and content"""
        technologies = []
        
        # Server detection
        server = headers.get('server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # Framework detection
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'php' in powered_by:
                technologies.append('PHP')
            elif 'asp.net' in powered_by:
                technologies.append('ASP.NET')
            elif 'express' in powered_by:
                technologies.append('Express.js')
        
        # Content-based detection
        if 'wordpress' in content.lower():
            technologies.append('WordPress')
        if 'jquery' in content.lower():
            technologies.append('jQuery')
        if 'bootstrap' in content.lower():
            technologies.append('Bootstrap')
        if 'react' in content.lower():
            technologies.append('React')
        if 'angular' in content.lower():
            technologies.append('Angular')
        
        return technologies
    
    def _extract_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract security-related headers"""
        security_headers = {}
        security_header_names = [
            'x-frame-options', 'x-content-type-options', 'x-xss-protection',
            'strict-transport-security', 'content-security-policy',
            'referrer-policy', 'permissions-policy'
        ]
        
        for header in security_header_names:
            if header in headers:
                security_headers[header] = headers[header]
        
        return security_headers
    
    def _generate_report(self, summary: CrawlSummary, crawl_results: List[CrawlResult], 
                        hidden_files: List[Dict], errors: List[str]) -> Dict:
        """Generate comprehensive crawl report"""
        
        # Initialize categorized findings with new structure
        categorized_findings = {
            'Other': {'count': 0, 'sensitivity_breakdown': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}, 'urls': []},
            'Sensitive Content': {'count': 0, 'sensitivity_breakdown': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}, 'urls': []}
        }
        
        # Process all successful crawl results
        for result in crawl_results:
            if result.status_code == 200:
                # Determine sensitivity level
                sensitivity_level = self._determine_sensitivity_level(result.url, result.content_type, result.title)
                
                # Create URL entry
                url_entry = {
                    'url': result.url,
                    'status_code': result.status_code,
                    'content_type': result.content_type,
                    'sensitivity_level': sensitivity_level,
                    'title': result.title or '',
                    'forms_count': len(result.forms),
                    'technologies': result.technologies,
                    'response_time': result.response_time
                }
                
                # Categorize based on sensitivity
                if sensitivity_level == 'low':
                    categorized_findings['Other']['urls'].append(url_entry)
                    categorized_findings['Other']['count'] += 1
                    categorized_findings['Other']['sensitivity_breakdown']['low'] += 1
                else:
                    categorized_findings['Sensitive Content']['urls'].append(url_entry)
                    categorized_findings['Sensitive Content']['count'] += 1
                    categorized_findings['Sensitive Content']['sensitivity_breakdown'][sensitivity_level] += 1
        
        # Process hidden files
        for hidden_file in hidden_files:
            if hidden_file.get('status_code') == 200:
                sensitivity_level = self._determine_sensitivity_level(
                    hidden_file.get('url', ''), 
                    hidden_file.get('content_type', ''), 
                    ''
                )
                
                url_entry = {
                    'url': hidden_file.get('url', ''),
                    'status_code': hidden_file.get('status_code', 200),
                    'content_type': hidden_file.get('content_type', ''),
                    'sensitivity_level': sensitivity_level,
                    'title': '',
                    'forms_count': 0,
                    'technologies': [],  # Hidden files typically don't have technology detection
                    'response_time': 0.0
                }
                
                if sensitivity_level == 'low':
                    categorized_findings['Other']['urls'].append(url_entry)
                    categorized_findings['Other']['count'] += 1
                    categorized_findings['Other']['sensitivity_breakdown']['low'] += 1
                else:
                    categorized_findings['Sensitive Content']['urls'].append(url_entry)
                    categorized_findings['Sensitive Content']['count'] += 1
                    categorized_findings['Sensitive Content']['sensitivity_breakdown'][sensitivity_level] += 1
        
        # Calculate statistics
        successful_urls_count = len([r for r in crawl_results if r.status_code == 200])
        total_forms_found = sum(len(r.forms) for r in crawl_results if r.status_code == 200)
        
        discovery_stats = {
            'total_files_found': successful_urls_count + len([f for f in hidden_files if f.get('status_code') == 200]),
            'total_forms_found': total_forms_found,
            'sensitive_files_found': categorized_findings['Sensitive Content']['count'],
            'hidden_files_discovered': len([f for f in hidden_files if f.get('status_code') == 200])
        }
        
        return {
            'crawl_summary': asdict(summary),
            'discovery_statistics': discovery_stats,
            'categorized_findings': categorized_findings
        }
    
    def _determine_sensitivity_level(self, url: str, content_type: str, title: str) -> str:
        """Determine the sensitivity level of a URL based on various factors"""
        url_lower = url.lower()
        content_type_lower = content_type.lower()
        title_lower = (title or '').lower()
        
        # Critical sensitivity indicators
        critical_indicators = [
            'admin', 'login', 'dashboard', 'control', 'manage', 'config',
            'password', 'secret', 'key', 'credential', 'token', 'api',
            'database', 'db', 'backup', '.env', '.htpasswd', 'wp-config',
            'robots.txt', 'sitemap.xml', 'security.txt', '.git',
            'bank', 'financial', 'payment', 'transaction', 'account',
            'personal', 'private', 'sensitive', 'confidential'
        ]
        
        # High sensitivity indicators
        high_indicators = [
            'user', 'profile', 'account', 'settings', 'preferences',
            'form', 'submit', 'upload', 'download', 'file',
            'search', 'query', 'filter', 'sort', 'export'
        ]
        
        # Medium sensitivity indicators
        medium_indicators = [
            'contact', 'about', 'help', 'support', 'faq',
            'news', 'blog', 'article', 'press', 'media',
            'service', 'product', 'catalog', 'listing'
        ]
        
        # Check for critical indicators
        for indicator in critical_indicators:
            if indicator in url_lower or indicator in title_lower:
                return 'critical'
        
        # Check for high indicators
        for indicator in high_indicators:
            if indicator in url_lower or indicator in title_lower:
                return 'high'
        
        # Check for medium indicators
        for indicator in medium_indicators:
            if indicator in url_lower or indicator in title_lower:
                return 'medium'
        
        # Default to low sensitivity
        return 'low'
    
    def _display_results(self, report: Dict):
        """Display crawl results in a formatted way"""
        self.console.print("\n" + "="*80)
        self.console.print("[bold green]CRAWL COMPLETED SUCCESSFULLY[/bold green]")
        self.console.print("="*80)
        
        # Summary table
        summary_table = Table(title="Crawl Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="magenta")
        
        summary = report['crawl_summary']
        summary_table.add_row("Target Domain", summary['target_domain'])
        summary_table.add_row("Duration", f"{summary['crawl_duration']:.2f} seconds")
        summary_table.add_row("URLs Discovered", str(summary['urls_discovered']))
        summary_table.add_row("URLs Crawled", str(summary['urls_successfully_crawled']))
        summary_table.add_row("Errors", str(summary['errors_encountered']))
        
        self.console.print(summary_table)
        
        # Discovery statistics
        stats = report['discovery_statistics']
        self.console.print(f"\n[bold yellow]Discovery Statistics:[/bold yellow]")
        self.console.print(f"  • Total Files Found: {stats['total_files_found']}")
        self.console.print(f"  • Forms Discovered: {stats['total_forms_found']}")
        self.console.print(f"  • Sensitive Files: {stats['sensitive_files_found']}")
        self.console.print(f"  • Hidden Files: {stats['hidden_files_discovered']}")
        
        # Categorized findings
        categorized = report['categorized_findings']
        
        # Other category
        if categorized['Other']['count'] > 0:
            self.console.print(f"\n[bold blue]Other Content:[/bold blue]")
            self.console.print(f"  • Total: {categorized['Other']['count']} URLs")
            breakdown = categorized['Other']['sensitivity_breakdown']
            for level, count in breakdown.items():
                if count > 0:
                    self.console.print(f"    - {level.capitalize()}: {count}")
            
            # Show first few URLs
            self.console.print(f"\n[bold yellow]Sample Other URLs:[/bold yellow]")
            for i, url_info in enumerate(categorized['Other']['urls'][:3]):
                self.console.print(f"  {i+1}. {url_info['url']}")
                self.console.print(f"     Sensitivity: {url_info['sensitivity_level']}")
                if url_info['title']:
                    self.console.print(f"     Title: {url_info['title']}")
        
        # Sensitive Content category
        if categorized['Sensitive Content']['count'] > 0:
            self.console.print(f"\n[bold red]Sensitive Content:[/bold red]")
            self.console.print(f"  • Total: {categorized['Sensitive Content']['count']} URLs")
            breakdown = categorized['Sensitive Content']['sensitivity_breakdown']
            for level, count in breakdown.items():
                if count > 0:
                    self.console.print(f"    - {level.capitalize()}: {count}")
            
            # Show first few URLs
            self.console.print(f"\n[bold yellow]Sample Sensitive URLs:[/bold yellow]")
            for i, url_info in enumerate(categorized['Sensitive Content']['urls'][:3]):
                self.console.print(f"  {i+1}. {url_info['url']}")
                self.console.print(f"     Sensitivity: {url_info['sensitivity_level']}")
                if url_info['title']:
                    self.console.print(f"     Title: {url_info['title']}")
        
        self.console.print("\n" + "="*80)
    
    async def close(self):
        """Clean up resources"""
        await self.client.aclose()

async def main():
    """Main function to run the web crawler"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive Web Crawling Agent")
    parser.add_argument("target", help="Target domain to crawl")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum crawl depth")
    parser.add_argument("--max-urls", type=int, default=100, help="Maximum URLs to crawl")
    parser.add_argument("--openai-key", help="OpenAI API key for enhanced crawling")
    parser.add_argument("--output", help="Output file for the report")
    parser.add_argument("--no-save", action="store_true", help="Don't save JSON report automatically")
    
    args = parser.parse_args()
    
    # Create and run the crawler
    crawler = WebCrawlingAgent(openai_api_key=args.openai_key)
    
    try:
        report = await crawler.crawl_domain(
            target_domain=args.target,
            max_depth=args.max_depth,
            max_urls=args.max_urls
        )
        
        # Always save JSON report unless --no-save is specified
        if not args.no_save:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = args.target.replace('://', '_').replace('/', '_').replace('.', '_')
            filename = f"crawl_report_{target_clean}_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            print(f"\n📄 JSON report automatically saved to: {filename}")
            print(f"   Contains categorized findings with sensitivity analysis")
        
        # Save to custom filename if specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            print(f"📄 Report also saved to custom location: {args.output}")
        
    finally:
        await crawler.close()

if __name__ == "__main__":
    asyncio.run(main())
