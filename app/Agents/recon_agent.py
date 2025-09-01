#!/usr/bin/env python3
"""
🔥 ULTIMATE RECON AGENT 🔥
Advanced AI-Powered Offensive Security Reconnaissance Tool
=========================================================

A comprehensive, single-file reconnaissance agent that leverages AI and multiple
attack vectors for maximum intelligence gathering.

⚠️  WARNING: FOR AUTHORIZED PENETRATION TESTING ONLY ⚠️

Author: Elite Recon Team
Version: 2.0 (Ultimate Edition)
"""

import os
import sys
import json
import time
import socket
import ssl
import subprocess
import threading
import asyncio
import aiohttp
import requests
import dns.resolver
import whois
from datetime import datetime
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import random
import re
import base64
from app.models.recon_models import ReconReport

# Removed LangChain imports - standalone reconnaissance tool

# Rich for beautiful output
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

# ============================================================================
# CONFIGURATION & GLOBAL VARIABLES
# ============================================================================

# API Configuration - SET YOUR KEYS HERE
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "6BrmR2E4kUhjGf3lG273TWKZYVouKppu") 
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "409076748abffb92e8cce95805ec187b1f620fecae95e60feb0d1b80ec3ed42e")

# Advanced Configuration
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
]

DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "149.112.112.112"]

# Offensive Wordlists
SUBDOMAIN_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn", "m", "shop", "ftp",
    "mail2", "test", "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "squirrelmail", "src",
    "ssl", "web2", "ns3", "img", "pop", "mysql", "beta", "ntp", "staging", "admin", "demo", "api", "app", "git",
    "old", "new", "backup", "mobile", "cdn", "static", "assets", "forum", "help", "docs", "status", "monitor",
    "intranet", "extranet", "sharepoint", "wiki", "crm", "erp", "jira", "confluence", "jenkins", "gitlab", "svn",
    "cpanel", "webdisk", "whm", "autodiscover", "lyncdiscover", "msoid", "enterpriseregistration", "enterpriseenrollment",
    "training", "prod", "production", "uat", "qa", "staging2", "dev2", "test2", "sandbox", "lab", "research",
    "edge", "firewall", "gateway", "proxy", "load-balancer", "lb", "cluster", "node1", "node2", "worker",
    "kubernetes", "docker", "container", "microservice", "service", "internal", "private", "public", "external",
    "dmz", "lan", "wan", "vpn2", "ssl-vpn", "citrix", "terminal", "rds", "rdp", "ssh", "sftp", "ftps"
]

DIRECTORY_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "phpmyadmin", "mysql", "backup", "backups", "config", "configs",
    "test", "tests", "staging", "dev", "development", "prod", "production", "api", "v1", "v2", "docs", "documentation",
    "help", "support", "uploads", "files", "images", "img", "css", "js", "assets", "static", "public", "private",
    "secret", "hidden", "old", "new", "temp", "tmp", "cache", "logs", "log", "data", "db", "database", "sql",
    "includes", "include", "lib", "libs", "vendor", "node_modules", "bower_components", "src", "source", "build",
    "dist", "release", "debug", "cgi-bin", "bin", "sbin", "usr", "var", "etc", "opt", "home", "root", "www",
    "html", "htdocs", "public_html", "web", "webroot", "wwwroot", "inetpub", "xampp", "wamp", "mamp", "lamp"
]

PORTS_TO_SCAN = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8888, 9000, 9001, 9090, 27017, 5984, 6379, 11211, 50070, 50030, 9200, 9300, 5601, 3000,
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8020, 8030, 8040, 8050, 8060, 8070,
    8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8100, 8200, 8300, 8400, 8500, 8600, 8700,
    8800, 8900, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010, 9020, 9030, 9040, 9050, 9060
]

# Initialize Rich Console
console = Console()

# ============================================================================
# UTILITY CLASSES & FUNCTIONS
# ============================================================================

class Logger:
    """Advanced logging with Rich styling"""
    
    @staticmethod
    def banner():
        banner_text = Text("🔥 ULTIMATE RECON AGENT 🔥", style="bold red")
        subtitle_text = Text("Advanced AI-Powered Offensive Security Tool", style="cyan")
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
# CORE RECONNAISSANCE MODULES
# ============================================================================

class DomainRecon:
    """Advanced Domain Reconnaissance"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    
    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Enhanced WHOIS lookup with additional intelligence"""
        logger.info(f"🔍 WHOIS lookup for {domain}")
        
        try:
            w = whois.whois(domain)
            
            whois_data = {
                'domain': domain,
                'registrar': getattr(w, 'registrar', None),
                'creation_date': str(getattr(w, 'creation_date', None)),
                'expiration_date': str(getattr(w, 'expiration_date', None)),
                'updated_date': str(getattr(w, 'updated_date', None)),
                'name_servers': getattr(w, 'name_servers', []),
                'status': getattr(w, 'status', []),
                'emails': getattr(w, 'emails', []),
                'registrant_country': getattr(w, 'country', None),
                'registrant_org': getattr(w, 'org', None),
                'admin_email': getattr(w, 'admin_email', None),
                'tech_email': getattr(w, 'tech_email', None),
                'dnssec': getattr(w, 'dnssec', None)
            }
            
            # Calculate domain age
            if whois_data['creation_date'] != 'None':
                try:
                    creation = datetime.strptime(whois_data['creation_date'].split(' ')[0], '%Y-%m-%d')
                    age_days = (datetime.now() - creation).days
                    whois_data['domain_age_days'] = age_days
                    whois_data['domain_age_years'] = round(age_days / 365.25, 2)
                except:
                    pass
            
            logger.success(f"WHOIS data retrieved for {domain}")
            return whois_data
            
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {str(e)}")
            return {
                    'domain': domain,
                    'registrar': None,
                    'creation_date': None,
                    'expiration_date': None,
                    'updated_date': None,
                    'name_servers': None,
                    'status': None,
                    'emails': None,
                    'registrant_country': None,
                    'registrant_org': None,
                    'admin_email': None,
                    'tech_email': None,
                    'dnssec': None,
                    'domain_age_days': None,
                    'domain_age_years': None,
                    'error': str(e)
                }
    
    def dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Comprehensive DNS enumeration"""
        logger.info(f"🔍 DNS enumeration for {domain}")
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'PTR', 'SRV', 'CAA']
        dns_records = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except:
                dns_records[record_type] = []
        
        # Advanced DNS analysis
        dns_analysis = {
            'spf_record': None,
            'dmarc_record': None,
            'dkim_records': [],
            'mx_priority': [],
            'subdomain_takeover_risk': False
        }
        
        # Analyze TXT records for SPF/DMARC
        for txt in dns_records.get('TXT', []):
            if 'v=spf1' in txt:
                dns_analysis['spf_record'] = txt
            elif 'v=DMARC1' in txt:
                dns_analysis['dmarc_record'] = txt
        
        # Check for DMARC record specifically
        try:
            dmarc_answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for rdata in dmarc_answers:
                if 'v=DMARC1' in str(rdata):
                    dns_analysis['dmarc_record'] = str(rdata)
        except:
            pass
        
        # Analyze MX records
        for mx in dns_records.get('MX', []):
            parts = mx.split()
            if len(parts) >= 2:
                dns_analysis['mx_priority'].append({
                    'priority': parts[0],
                    'server': parts[1]
                })
        
        dns_records['analysis'] = dns_analysis
        logger.success(f"DNS enumeration completed for {domain}")
        return dns_records
    
    def subdomain_discovery(self, domain: str, wordlist: Optional[List[str]] = None) -> List[str]:
        """Aggressive subdomain discovery"""
        logger.info(f"🔍 Subdomain discovery for {domain}")
        
        if not wordlist:
            wordlist = SUBDOMAIN_WORDLIST
        
        found_subdomains = []
        
        def check_subdomain(subdomain_name: str) -> Optional[str]:
            full_domain = f"{subdomain_name}.{domain}"
            try:
                dns.resolver.resolve(full_domain, 'A')
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(check_subdomain, wordlist))
        
        found_subdomains = [sub for sub in results if sub is not None]
        
        # Certificate transparency search
        try:
            ct_subdomains = self.certificate_transparency_search(domain)
            found_subdomains.extend(ct_subdomains)
            found_subdomains = list(set(found_subdomains))  # Remove duplicates
        except:
            pass
        
        logger.success(f"Found {len(found_subdomains)} subdomains for {domain}")
        return found_subdomains
    
    def certificate_transparency_search(self, domain: str) -> List[str]:
        """Search certificate transparency logs"""
        logger.info(f"🔍 Certificate transparency search for {domain}")
        
        subdomains = set()
        
        try:
            # Search crt.sh
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                certificates = response.json()
                
                for cert in certificates:
                    name_value = cert.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip()
                        if name and domain in name and not name.startswith('*'):
                            subdomains.add(name)
        except:
            pass
        
        return list(subdomains)
    
    def zone_transfer_test(self, domain: str) -> Dict[str, Any]:
        """Test for DNS zone transfer vulnerability"""
        logger.info(f"🔍 Testing zone transfer for {domain}")
        
        zone_transfer_results = {
            'domain': domain,
            'vulnerable': False,
            'records': [],
            'name_servers': []
        }
        
        try:
            # Get name servers
            ns_answers = dns.resolver.resolve(domain, 'NS')
            name_servers = [str(ns) for ns in ns_answers]
            zone_transfer_results['name_servers'] = name_servers
            
            for ns in name_servers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                    zone_transfer_results['vulnerable'] = True
                    zone_transfer_results['vulnerable_ns'] = ns
                    
                    for name, node in zone.nodes.items():
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            for rdata in rdataset:
                                zone_transfer_results['records'].append({
                                    'name': str(name),
                                    'type': dns.rdatatype.to_text(rdataset.rdtype),
                                    'data': str(rdata)
                                })
                    break
                except:
                    continue
                    
            if zone_transfer_results['vulnerable']:
                logger.critical(f"🚨 ZONE TRANSFER VULNERABILITY FOUND for {domain}!")
            else:
                logger.info(f"Zone transfer not possible for {domain}")
                
        except Exception as e:
            logger.error(f"Zone transfer test failed: {str(e)}")
        
        return zone_transfer_results

class NetworkRecon:
    """Advanced Network Reconnaissance"""
    
    def port_scan(self, host: str, ports: List[int] = None) -> Dict[str, Any]:
        """High-speed port scanning"""
        if not ports:
            ports = PORTS_TO_SCAN
        
        logger.info(f"🔍 Port scanning {host} ({len(ports)} ports)")
        
        scan_results = {
            'host': host,
            'open_ports': [],
            'services': {},
            'scan_duration': 0,
            'banners': {}
        }
        
        start_time = time.time()
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    # Try to grab banner
                    try:
                        banner = self.grab_banner(host, port)
                        return {'port': port, 'open': True, 'banner': banner}
                    except:
                        return {'port': port, 'open': True, 'banner': None}
                
                sock.close()
                return {'port': port, 'open': False, 'banner': None}
                
            except:
                return {'port': port, 'open': False, 'banner': None}
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = list(executor.map(scan_port, ports))
        
        for result in results:
            if result['open']:
                port = result['port']
                scan_results['open_ports'].append(port)
                scan_results['services'][port] = self.identify_service(port)
                if result['banner']:
                    scan_results['banners'][port] = result['banner']
        
        scan_results['scan_duration'] = round(time.time() - start_time, 2)
        
        logger.success(f"Port scan completed: {len(scan_results['open_ports'])} open ports found")
        return scan_results
    
    def grab_banner(self, host: str, port: int, timeout: int = 5) -> Optional[str]:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send appropriate probe
            if port == 80:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner immediately
            elif port == 22:
                pass  # SSH sends banner immediately
            elif port == 25:
                pass  # SMTP sends banner immediately
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except:
            return None
    
    def identify_service(self, port: int) -> str:
        """Identify service running on port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MS-RPC', 139: 'NetBIOS',
            143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            9000: 'HTTP-Alt', 27017: 'MongoDB', 5984: 'CouchDB', 11211: 'Memcached',
            50070: 'Hadoop', 9200: 'Elasticsearch', 5601: 'Kibana'
        }
        return services.get(port, 'Unknown')

class WebRecon:
    """Advanced Web Application Reconnaissance"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    
    def web_crawl(self, url: str, max_pages: int = 50) -> Dict[str, Any]:
        """Aggressive web crawling"""
        logger.info(f"🔍 Web crawling {url}")
        
        crawl_results = {
            'base_url': url,
            'discovered_urls': set(),
            'forms': [],
            'emails': set(),
            'phone_numbers': set(),
            'technologies': set(),
            'sensitive_files': [],
            'admin_panels': [],
            'error_pages': []
        }
        
        visited_urls = set()
        urls_to_visit = [url]
        
        while urls_to_visit and len(visited_urls) < max_pages:
            current_url = urls_to_visit.pop(0)
            if current_url in visited_urls:
                continue
                
            try:
                response = self.session.get(current_url, timeout=10, allow_redirects=True)
                visited_urls.add(current_url)
                
                if response.status_code == 200:
                    crawl_results['discovered_urls'].add(current_url)
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Extract forms
                    forms = self.extract_forms(soup, current_url)
                    crawl_results['forms'].extend(forms)
                    
                    # Extract emails and phone numbers
                    emails = self.extract_emails(response.text)
                    phones = self.extract_phone_numbers(response.text)
                    crawl_results['emails'].update(emails)
                    crawl_results['phone_numbers'].update(phones)
                    
                    # Detect technologies
                    technologies = self.detect_technologies(response, soup)
                    crawl_results['technologies'].update(technologies)
                    
                    # Find new URLs
                    new_urls = self.extract_urls(soup, current_url, url)
                    urls_to_visit.extend(new_urls)
                
                elif response.status_code in [403, 404, 500, 502, 503]:
                    crawl_results['error_pages'].append({
                        'url': current_url,
                        'status_code': response.status_code
                    })
                    
                time.sleep(0.5)  # Rate limiting
                
            except:
                continue
        
        # Convert sets to lists
        crawl_results['discovered_urls'] = list(crawl_results['discovered_urls'])
        crawl_results['emails'] = list(crawl_results['emails'])
        crawl_results['phone_numbers'] = list(crawl_results['phone_numbers'])
        crawl_results['technologies'] = list(crawl_results['technologies'])
        
        logger.success(f"Web crawl completed: {len(crawl_results['discovered_urls'])} pages discovered")
        return crawl_results
    
    def directory_bruteforce(self, base_url: str, wordlist: Optional[List[str]] = None) -> Dict[str, Any]:
        """Aggressive directory bruteforcing"""
        logger.info(f"🔍 Directory bruteforce on {base_url}")
        
        if not wordlist:
            wordlist = DIRECTORY_WORDLIST
        
        results = {
            'base_url': base_url,
            'found_directories': [],
            'found_files': [],
            'interesting_responses': [],
            'admin_panels': [],
            'backup_files': []
        }
        
        def check_path(path):
            full_url = urljoin(base_url, path)
            try:
                response = self.session.head(full_url, timeout=5, allow_redirects=False)
                return {
                    'path': path,
                    'url': full_url,
                    'status_code': response.status_code,
                    'size': response.headers.get('content-length', 'Unknown'),
                    'content_type': response.headers.get('content-type', 'Unknown')
                }
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            path_results = list(executor.map(check_path, wordlist))
        
        for result in path_results:
            if result and result['status_code'] in [200, 301, 302, 403]:
                if 'admin' in result['path'] or 'login' in result['path']:
                    results['admin_panels'].append(result)
                elif result['path'].endswith(('.bak', '.backup', '.old', '.orig')):
                    results['backup_files'].append(result)
                elif result['status_code'] == 200:
                    if '.' in result['path']:
                        results['found_files'].append(result)
                    else:
                        results['found_directories'].append(result)
                
                results['interesting_responses'].append(result)
        
        logger.success(f"Directory bruteforce completed: {len(results['interesting_responses'])} interesting paths found")
        return results
    
    def security_headers_check(self, url: str) -> Dict[str, Any]:
        """Comprehensive security headers analysis"""
        logger.info(f"🔍 Security headers check for {url}")
        
        security_headers = {
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'X-XSS-Protection',
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy',
            'cross-origin-opener-policy': 'COOP',
            'cross-origin-embedder-policy': 'COEP'
        }
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            security_analysis = {
                'url': url,
                'present_headers': {},
                'missing_headers': [],
                'security_score': 0,
                'vulnerabilities': [],
                'recommendations': []
            }
            
            for header, name in security_headers.items():
                if header in headers:
                    security_analysis['present_headers'][name] = headers[header]
                    security_analysis['security_score'] += 10
                else:
                    security_analysis['missing_headers'].append(name)
                    security_analysis['recommendations'].append(f"Implement {name} header")
            
            # Check for dangerous headers
            dangerous_headers = ['server', 'x-powered-by', 'x-aspnet-version']
            for header in dangerous_headers:
                if header in headers:
                    security_analysis['vulnerabilities'].append(f"Information disclosure: {header} header present")
            
            # Calculate final score
            max_score = len(security_headers) * 10
            security_analysis['security_score'] = (security_analysis['security_score'] / max_score) * 100
            
            return security_analysis
            
        except Exception as e:
            return {'url': url, 'error': str(e)}
    
    def extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms for potential attack vectors"""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'page_url': base_url
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required')
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def extract_emails(self, text: str) -> set:
        """Extract email addresses"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return set(re.findall(email_pattern, text))
    
    def extract_phone_numbers(self, text: str) -> set:
        """Extract phone numbers"""
        phone_patterns = [
            r'\b\d{3}-\d{3}-\d{4}\b',
            r'\b\(\d{3}\)\s*\d{3}-\d{4}\b',
            r'\b\d{3}\.\d{3}\.\d{4}\b',
            r'\b\+\d{1,3}\s*\d{3,4}\s*\d{3,4}\s*\d{3,4}\b'
        ]
        
        phones = set()
        for pattern in phone_patterns:
            phones.update(re.findall(pattern, text))
        
        return phones
    
    def extract_urls(self, soup: BeautifulSoup, current_url: str, base_domain: str) -> List[str]:
        """Extract URLs from page"""
        urls = []
        base_parsed = urlparse(base_domain)
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(current_url, href)
            parsed_url = urlparse(full_url)
            
            if parsed_url.netloc == base_parsed.netloc:
                clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                if clean_url not in urls and clean_url != current_url:
                    urls.append(clean_url)
        
        return urls
    
    def detect_technologies(self, response: requests.Response, soup: BeautifulSoup) -> set:
        """Detect web technologies"""
        technologies = set()
        content = response.text.lower()
        headers = response.headers
        
        # Server detection
        server = headers.get('Server', '').lower()
        if server:
            technologies.add(f"Server: {server}")
        
        # Framework detection
        frameworks = {
            'wordpress': ['wp-content', 'wp-includes', '/wp-admin/'],
            'drupal': ['drupal', 'sites/default'],
            'joomla': ['joomla', 'option=com_'],
            'magento': ['magento', '/skin/frontend/'],
            'django': ['csrfmiddlewaretoken', 'django'],
            'rails': ['rails', 'csrf-token'],
            'laravel': ['laravel_session', 'csrf-token'],
            'angular': ['ng-app', 'angular'],
            'react': ['react', '_reactInternalInstance'],
            'vue': ['vue.js', '__vue__']
        }
        
        for framework, indicators in frameworks.items():
            if any(indicator in content for indicator in indicators):
                technologies.add(f"Framework: {framework}")
        
        return technologies

class OSINTRecon:
    """OSINT Reconnaissance using Shodan and VirusTotal"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    
    def shodan_lookup(self, query: str, query_type: str = 'host') -> Dict[str, Any]:
        """Enhanced Shodan lookup"""
        if not SHODAN_API_KEY or SHODAN_API_KEY == "your_shodan_key_here":
            return {'error': 'Shodan API key not configured'}
        
        logger.info(f"🔍 Shodan lookup for {query}")
        
        try:
            import shodan
            api = shodan.Shodan(SHODAN_API_KEY)
            
            shodan_results = {
                'query': query,
                'query_type': query_type,
                'results': [],
                'total_results': 0,
                'vulnerabilities': [],
                'exposed_services': [],
                'geolocation': {},
                'timestamp': datetime.now().isoformat()
            }
            
            if query_type == 'host':
                try:
                    host_info = api.host(query)
                    shodan_results['results'] = [host_info]
                    shodan_results['total_results'] = 1
                    
                    # Extract vulnerabilities
                    if 'vulns' in host_info:
                        shodan_results['vulnerabilities'] = list(host_info['vulns'])
                    
                    # Extract services
                    if 'data' in host_info:
                        for service in host_info['data']:
                            service_info = {
                                'port': service.get('port'),
                                'service': service.get('_shodan', {}).get('module'),
                                'product': service.get('product'),
                                'version': service.get('version'),
                                'banner': service.get('data', '')[:200]
                            }
                            shodan_results['exposed_services'].append(service_info)
                    
                    # Geolocation
                    shodan_results['geolocation'] = {
                        'country': host_info.get('country_name'),
                        'city': host_info.get('city'),
                        'org': host_info.get('org'),
                        'asn': host_info.get('asn'),
                        'isp': host_info.get('isp')
                    }
                    
                except shodan.APIError as e:
                    shodan_results['error'] = str(e)
            
            elif query_type == 'search':
                try:
                    search_results = api.search(query, limit=100)
                    shodan_results['results'] = search_results['matches']
                    shodan_results['total_results'] = search_results['total']
                    
                    # Aggregate vulnerabilities and services
                    all_vulns = set()
                    all_services = []
                    
                    for result in search_results['matches']:
                        if 'vulns' in result:
                            all_vulns.update(result['vulns'])
                        
                        service_info = {
                            'ip': result.get('ip_str'),
                            'port': result.get('port'),
                            'service': result.get('_shodan', {}).get('module'),
                            'product': result.get('product', None),
                            'location': f"{result.get('city', '')}, {result.get('country_name', '')}"
                        }
                        all_services.append(service_info)
                    
                    shodan_results['vulnerabilities'] = list(all_vulns)
                    shodan_results['exposed_services'] = all_services
                except shodan.APIError as e:
                    shodan_results['error'] = str(e)
                except Exception as e:
                    shodan_results['error'] = str(e)
            
            if shodan_results['vulnerabilities']:
                logger.critical(f"🚨 {len(shodan_results['vulnerabilities'])} vulnerabilities found!")
            
            logger.success(f"Shodan lookup completed: {shodan_results['total_results']} results")
            return shodan_results
            
        except ImportError:
            return {'error': 'Shodan library not installed. Run: pip install shodan'}
        except Exception as e:
            logger.error(f"Shodan lookup failed: {str(e)}")
            return {'error': str(e)}
    
    def virustotal_lookup(self, target: str, lookup_type: str = 'domain') -> Dict[str, Any]:
        """Enhanced VirusTotal lookup"""
        if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "your_virustotal_key_here":
            return {'error': 'VirusTotal API key not configured'}
        
        logger.info(f"🔍 VirusTotal lookup for {target}")
        
        vt_results = {
            'target': target,
            'lookup_type': lookup_type,
            'reputation': {
                'malicious': 0,
                'suspicious': 0,
                'clean': 0,
                'total_scans': 0
            },
            'detected_urls': [],
            'detected_samples': [],
            'resolutions': [],
            'subdomains': [],
            'whois_info': {},
            'ssl_certificates': [],
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            if lookup_type == 'domain':
                # Domain report
                url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                params = {'apikey': VIRUSTOTAL_API_KEY, 'domain': target}
                
                response = requests.get(url, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get('response_code') == 1:
                        # Reputation scores
                        if 'Forcepoint ThreatSeeker' in data:
                            for scanner, result in data.items():
                                if isinstance(result, str):
                                    if 'malicious' in result.lower():
                                        vt_results['reputation']['malicious'] += 1
                                    elif 'suspicious' in result.lower():
                                        vt_results['reputation']['suspicious'] += 1
                                    elif 'clean' in result.lower():
                                        vt_results['reputation']['clean'] += 1
                                    vt_results['reputation']['total_scans'] += 1
                        
                        # URLs and samples
                        vt_results['detected_urls'] = data.get('detected_urls', [])[:20]
                        vt_results['detected_samples'] = data.get('detected_samples', [])[:20]
                        vt_results['resolutions'] = data.get('resolutions', [])[:50]
                        vt_results['subdomains'] = data.get('subdomains', [])[:100]
                        
                        # WHOIS
                        vt_results['whois_info'] = {
                            'creation_date': data.get('whois_timestamp'),
                            'registrar': data.get('whois', '')[:200]
                        }
                        
                    else:
                        vt_results['error'] = 'No information available'
                else:
                    vt_results['error'] = f"API request failed: {response.status_code}"
            
            elif lookup_type == 'ip':
                # IP report
                url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
                params = {'apikey': VIRUSTOTAL_API_KEY, 'ip': target}
                
                response = requests.get(url, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get('response_code') == 1:
                        vt_results['detected_urls'] = data.get('detected_urls', [])[:20]
                        vt_results['resolutions'] = data.get('resolutions', [])[:50]
                        
                        # Country and ASN info
                        vt_results['geolocation'] = {
                            'country': data.get('country'),
                            'asn': data.get('asn'),
                            'as_owner': data.get('as_owner')
                        }
            
            if vt_results['reputation']['malicious'] > 0:
                logger.critical(f"🚨 {vt_results['reputation']['malicious']} scanners flagged as malicious!")
            elif vt_results['reputation']['suspicious'] > 0:
                logger.warning(f"⚠ {vt_results['reputation']['suspicious']} scanners flagged as suspicious")
            
            logger.success(f"VirusTotal lookup completed for {target}")
            return vt_results
            
        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {str(e)}")
            return {'error': str(e)}
    
    def passive_dns_lookup(self, target: str) -> Dict[str, Any]:
        """Passive DNS lookup using multiple sources"""
        logger.info(f"🔍 Passive DNS lookup for {target}")
        
        passive_dns = {
            'target': target,
            'historical_ips': [],
            'historical_domains': [],
            'first_seen': None,
            'last_seen': None
        }
        
        # Use VirusTotal's passive DNS data
        vt_data = self.virustotal_lookup(target, 'domain' if not target.replace('.', '').isdigit() else 'ip')
        
        if 'resolutions' in vt_data:
            for resolution in vt_data['resolutions']:
                if 'ip_address' in resolution:
                    passive_dns['historical_ips'].append({
                        'ip': resolution['ip_address'],
                        'last_resolved': resolution.get('last_resolved')
                    })
                elif 'hostname' in resolution:
                    passive_dns['historical_domains'].append({
                        'domain': resolution['hostname'],
                        'last_resolved': resolution.get('last_resolved')
                    })
        
        logger.success(f"Passive DNS lookup completed for {target}")
        return passive_dns

# ============================================================================
# STANDALONE RECONNAISSANCE ENGINE
# ============================================================================

class UltimateReconAgent:
    """The Ultimate Standalone Reconnaissance Agent"""
    
    def __init__(self):
        # Initialize reconnaissance modules
        self.domain_recon = DomainRecon()
        self.network_recon = NetworkRecon()
        self.web_recon = WebRecon()
        self.osint_recon = OSINTRecon()
    
    def run_reconnaissance(self, target: str, mission_type: str = "comprehensive") -> Dict[str, Any]:
        """Execute comprehensive reconnaissance mission"""
        
        logger.banner()
        console.print(f"\n[bold red]🎯 TARGET: {target}[/bold red]")
        console.print(f"[bold cyan]📋 MISSION: {mission_type.upper()}[/bold cyan]\n")
        
        # Validate API keys
        api_status = self._validate_apis()
        
        # Determine target type
        target_info = self._analyze_target(target)
        
        try:
            start_time = datetime.now()
            
            # Initialize comprehensive report
            intelligence_report = {
                "target": target,
                "target_classification": target_info,
                "mission_type": mission_type,
                "start_time": start_time.isoformat(),
                "findings": {},
                "vulnerabilities": [],
                "recommendations": [],
                "classification": "RESTRICTED"
            }
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                
                # Phase 1: Passive Intelligence Gathering
                task1 = progress.add_task("🔍 Phase 1: Passive Intelligence Gathering...", total=5)
                
                # WHOIS Analysis
                progress.update(task1, description="🔍 WHOIS Analysis...")
                whois_data = self.domain_recon.whois_lookup(target)
                intelligence_report["findings"]["whois"] = whois_data
                progress.advance(task1)
                
                # DNS Enumeration
                progress.update(task1, description="🔍 DNS Enumeration...")
                dns_data = self.domain_recon.dns_enumeration(target)
                intelligence_report["findings"]["dns"] = dns_data
                progress.advance(task1)
                
                # VirusTotal Check
                progress.update(task1, description="🔍 VirusTotal Reputation Check...")
                vt_data = self.osint_recon.virustotal_lookup(target, 'domain' if target_info['type'] == 'domain' else 'ip')
                intelligence_report["findings"]["virustotal"] = vt_data
                progress.advance(task1)
                
                # Shodan Intelligence
                progress.update(task1, description="🔍 Shodan Intelligence Gathering...")
                shodan_data = self.osint_recon.shodan_lookup(target, 'host')
                intelligence_report["findings"]["shodan"] = shodan_data
                progress.advance(task1)
                
                # Passive DNS
                progress.update(task1, description="🔍 Passive DNS Analysis...")
                passive_dns = self.osint_recon.passive_dns_lookup(target)
                intelligence_report["findings"]["passive_dns"] = passive_dns
                progress.advance(task1)
                
                # Phase 2: Active Reconnaissance
                task2 = progress.add_task("🔍 Phase 2: Active Reconnaissance...", total=4)
                
                # Subdomain Discovery
                progress.update(task2, description="🔍 Subdomain Discovery...")
                subdomains = self.domain_recon.subdomain_discovery(target)
                intelligence_report["findings"]["subdomains"] = subdomains
                progress.advance(task2)
                
                # Zone Transfer Test
                progress.update(task2, description="🔍 Zone Transfer Vulnerability Test...")
                zone_transfer = self.domain_recon.zone_transfer_test(target)
                intelligence_report["findings"]["zone_transfer"] = zone_transfer
                progress.advance(task2)
                
                # Port Scanning
                progress.update(task2, description="🔍 Port Scanning...")
                port_scan = self.network_recon.port_scan(target)
                intelligence_report["findings"]["port_scan"] = port_scan
                progress.advance(task2)
                
                # Web Analysis (if applicable)
                if target_info['type'] in ['domain', 'url']:
                    progress.update(task2, description="🔍 Web Application Analysis...")
                    web_url = target if target.startswith('http') else f"http://{target}"
                    web_crawl = self.web_recon.web_crawl(web_url)
                    intelligence_report["findings"]["web_crawl"] = web_crawl
                    
                    # Directory Bruteforce
                    dir_brute = self.web_recon.directory_bruteforce(web_url)
                    intelligence_report["findings"]["directory_bruteforce"] = dir_brute
                    
                    # Security Headers
                    security_headers = self.web_recon.security_headers_check(web_url)
                    intelligence_report["findings"]["security_headers"] = security_headers
                
                progress.advance(task2)
                
                # Phase 3: Vulnerability Assessment
                task3 = progress.add_task("🔍 Phase 3: Vulnerability Assessment...", total=1)
                progress.update(task3, description="🔍 Analyzing findings for vulnerabilities...")
                
                # Analyze findings for vulnerabilities
                vulnerabilities = self._analyze_vulnerabilities(intelligence_report["findings"])
                intelligence_report["vulnerabilities"] = vulnerabilities
                
                # Generate recommendations
                recommendations = self._generate_recommendations(intelligence_report["findings"], vulnerabilities)
                intelligence_report["recommendations"] = recommendations
                
                progress.advance(task3)
            
            end_time = datetime.now()
            intelligence_report["end_time"] = end_time.isoformat()
            intelligence_report["mission_duration"] = str(end_time - start_time)
            intelligence_report["mission_status"] = "COMPLETED"
            
            # Display mission results
            self._display_mission_results(intelligence_report)
            
            return intelligence_report
            
        except Exception as e:
            logger.error(f"Mission failed: {str(e)}")
            return {
                "target": target,
                "mission_status": "FAILED",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _validate_apis(self) -> Dict[str, bool]:
        """Validate API keys"""
        return {
            'shodan': bool(SHODAN_API_KEY and SHODAN_API_KEY != "your_shodan_key_here"),
            'virustotal': bool(VIRUSTOTAL_API_KEY and VIRUSTOTAL_API_KEY != "your_virustotal_key_here")
        }
    
    def _analyze_target(self, target: str) -> Dict[str, str]:
        """Analyze target type"""
        import re
        
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
            return {"type": "ip_address", "classification": "network_host"}
        elif re.match(r'^https?://', target):
            return {"type": "url", "classification": "web_application"}
        elif '/' in target:
            return {"type": "network_range", "classification": "network_subnet"}
        else:
            return {"type": "domain", "classification": "domain_target"}
    
    def _analyze_vulnerabilities(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze findings for security vulnerabilities with enhanced accuracy"""
        vulnerabilities = []
        
        # Check for zone transfer vulnerability
        if 'zone_transfer' in findings and findings['zone_transfer'].get('vulnerable'):
            vulnerabilities.append({
                'type': 'DNS Zone Transfer',
                'severity': 'HIGH',
                'description': 'DNS zone transfer is possible, exposing all DNS records',
                'evidence': findings['zone_transfer'],
                'recommendation': 'Restrict zone transfers to authorized name servers only',
                'cve': 'CWE-200',  # Information Exposure
                'impact': 'Complete DNS zone information disclosure'
            })
        
        # Enhanced exposed services analysis
        if 'port_scan' in findings and findings['port_scan'].get('open_ports'):
            open_ports = findings['port_scan']['open_ports']
            services = findings['port_scan'].get('services', {})
            
            # Critical services that should not be exposed
            critical_ports = {
                21: {'service': 'FTP', 'severity': 'HIGH', 'cve': 'CWE-287'},
                23: {'service': 'Telnet', 'severity': 'HIGH', 'cve': 'CWE-287'},
                3389: {'service': 'RDP', 'severity': 'HIGH', 'cve': 'CWE-287'},
                5900: {'service': 'VNC', 'severity': 'HIGH', 'cve': 'CWE-287'},
                22: {'service': 'SSH', 'severity': 'MEDIUM', 'cve': 'CWE-287'},
                3306: {'service': 'MySQL', 'severity': 'MEDIUM', 'cve': 'CWE-287'},
                5432: {'service': 'PostgreSQL', 'severity': 'MEDIUM', 'cve': 'CWE-287'},
                27017: {'service': 'MongoDB', 'severity': 'MEDIUM', 'cve': 'CWE-287'},
                6379: {'service': 'Redis', 'severity': 'MEDIUM', 'cve': 'CWE-287'},
                11211: {'service': 'Memcached', 'severity': 'MEDIUM', 'cve': 'CWE-287'}
            }
            
            for port in open_ports:
                if port in critical_ports:
                    port_info = critical_ports[port]
                    vulnerabilities.append({
                        'type': f'Exposed {port_info["service"]} Service',
                        'severity': port_info['severity'],
                        'description': f'{port_info["service"]} service exposed on port {port}',
                        'evidence': {
                            'port': port,
                            'service': services.get(port, port_info['service']),
                            'banner': findings['port_scan'].get('banners', {}).get(port)
                        },
                        'recommendation': f'Restrict access to port {port} or implement strong authentication',
                        'cve': port_info['cve'],
                        'impact': f'Potential unauthorized access to {port_info["service"]} service'
                    })
            
            # Check for excessive port exposure
            if len(open_ports) > 20:
                vulnerabilities.append({
                    'type': 'Excessive Port Exposure',
                    'severity': 'MEDIUM',
                    'description': f'Large number of ports ({len(open_ports)}) exposed to the internet',
                    'evidence': {'open_ports': open_ports, 'count': len(open_ports)},
                    'recommendation': 'Implement firewall rules to restrict unnecessary port access',
                    'cve': 'CWE-200',
                    'impact': 'Increased attack surface and potential service enumeration'
                })
        
        # Enhanced security headers analysis
        if 'security_headers' in findings:
            security_headers = findings['security_headers']
            missing_headers = security_headers.get('missing_headers', [])
            present_headers = security_headers.get('present_headers', {})
            
            # Critical missing headers
            critical_headers = ['HSTS', 'CSP', 'X-Frame-Options']
            missing_critical = [h for h in missing_headers if h in critical_headers]
            
            if missing_critical:
                vulnerabilities.append({
                    'type': 'Missing Critical Security Headers',
                    'severity': 'HIGH',
                    'description': f'Missing critical security headers: {", ".join(missing_critical)}',
                    'evidence': {
                        'missing_headers': missing_critical,
                        'present_headers': list(present_headers.keys()),
                        'security_score': security_headers.get('security_score', 0)
                    },
                    'recommendation': 'Implement missing critical security headers immediately',
                    'cve': 'CWE-693',
                    'impact': 'Increased risk of XSS, clickjacking, and other web attacks'
                })
            elif missing_headers:
                vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'severity': 'MEDIUM',
                    'description': f'Missing security headers: {", ".join(missing_headers)}',
                    'evidence': {
                        'missing_headers': missing_headers,
                        'present_headers': list(present_headers.keys()),
                        'security_score': security_headers.get('security_score', 0)
                    },
                    'recommendation': 'Implement missing security headers to improve application security',
                    'cve': 'CWE-693',
                    'impact': 'Reduced protection against common web vulnerabilities'
                })
            
            # Check for dangerous headers
            dangerous_headers = ['server', 'x-powered-by', 'x-aspnet-version']
            found_dangerous = []
            for header in dangerous_headers:
                if header in present_headers:
                    found_dangerous.append(header)
            
            if found_dangerous:
                vulnerabilities.append({
                    'type': 'Information Disclosure Headers',
                    'severity': 'MEDIUM',
                    'description': f'Dangerous headers exposing system information: {", ".join(found_dangerous)}',
                    'evidence': {'dangerous_headers': found_dangerous},
                    'recommendation': 'Remove or modify dangerous headers to prevent information disclosure',
                    'cve': 'CWE-200',
                    'impact': 'System and technology information disclosure'
                })
        
        # Enhanced VirusTotal analysis
        if 'virustotal' in findings and not findings['virustotal'].get('error'):
            vt = findings['virustotal']
            reputation = vt.get('reputation', {})
            malicious = reputation.get('malicious', 0)
            suspicious = reputation.get('suspicious', 0)
            
            if malicious > 0:
                vulnerabilities.append({
                    'type': 'Malicious Reputation',
                    'severity': 'HIGH',
                    'description': f'Target flagged as malicious by {malicious} security scanners',
                    'evidence': {
                        'malicious_count': malicious,
                        'suspicious_count': suspicious,
                        'total_scans': reputation.get('total_scans', 0),
                        'detected_urls': len(vt.get('detected_urls', [])),
                        'detected_samples': len(vt.get('detected_samples', []))
                    },
                    'recommendation': 'Investigate and remediate security issues identified by security scanners',
                    'cve': 'CWE-200',
                    'impact': 'Target may be compromised or hosting malicious content'
                })
            elif suspicious > 0:
                vulnerabilities.append({
                    'type': 'Suspicious Reputation',
                    'severity': 'MEDIUM',
                    'description': f'Target flagged as suspicious by {suspicious} security scanners',
                    'evidence': {
                        'suspicious_count': suspicious,
                        'total_scans': reputation.get('total_scans', 0)
                    },
                    'recommendation': 'Monitor target for suspicious activity and investigate scanner reports',
                    'cve': 'CWE-200',
                    'impact': 'Target may have security concerns requiring attention'
                })
        
        # Enhanced admin panel analysis
        if 'directory_bruteforce' in findings:
            dir_brute = findings['directory_bruteforce']
            admin_panels = dir_brute.get('admin_panels', [])
            backup_files = dir_brute.get('backup_files', [])
            
            if admin_panels:
                vulnerabilities.append({
                    'type': 'Exposed Admin Panels',
                    'severity': 'HIGH',
                    'description': f'Found {len(admin_panels)} potentially exposed admin panels',
                    'evidence': {
                        'admin_panels': admin_panels,
                        'urls': [p.get('url', '') for p in admin_panels[:5]]
                    },
                    'recommendation': 'Secure admin panels with strong authentication and access controls',
                    'cve': 'CWE-287',
                    'impact': 'Potential unauthorized access to administrative functions'
                })
            
            if backup_files:
                vulnerabilities.append({
                    'type': 'Exposed Backup Files',
                    'severity': 'MEDIUM',
                    'description': f'Found {len(backup_files)} backup files exposed',
                    'evidence': {
                        'backup_files': backup_files,
                        'urls': [f.get('url', '') for f in backup_files[:5]]
                    },
                    'recommendation': 'Remove or secure backup files to prevent information disclosure',
                    'cve': 'CWE-200',
                    'impact': 'Potential source code and configuration information disclosure'
                })
        
        # DNS security analysis
        if 'dns' in findings:
            dns = findings['dns']
            analysis = dns.get('analysis', {})
            
            # Check for missing SPF record
            if not analysis.get('spf_record'):
                vulnerabilities.append({
                    'type': 'Missing SPF Record',
                    'severity': 'MEDIUM',
                    'description': 'No SPF record found for domain',
                    'evidence': {'dns_records': list(dns.keys())},
                    'recommendation': 'Implement SPF record to prevent email spoofing',
                    'cve': 'CWE-345',
                    'impact': 'Increased risk of email spoofing and phishing attacks'
                })
            
            # Check for missing DMARC record
            if not analysis.get('dmarc_record'):
                vulnerabilities.append({
                    'type': 'Missing DMARC Record',
                    'severity': 'MEDIUM',
                    'description': 'No DMARC record found for domain',
                    'evidence': {'dns_records': list(dns.keys())},
                    'recommendation': 'Implement DMARC record to improve email security',
                    'cve': 'CWE-345',
                    'impact': 'Reduced protection against email-based attacks'
                })
        
        # Web application specific vulnerabilities
        if 'web_crawl' in findings:
            web_crawl = findings['web_crawl']
            forms = web_crawl.get('forms', [])
            
            # Check for forms without CSRF protection
            forms_without_csrf = []
            for form in forms:
                inputs = form.get('inputs', [])
                has_csrf = any('csrf' in str(input_data.get('name', '')).lower() 
                             or 'token' in str(input_data.get('name', '')).lower() 
                             for input_data in inputs)
                if not has_csrf and form.get('method') == 'POST':
                    forms_without_csrf.append(form)
            
            if forms_without_csrf:
                vulnerabilities.append({
                    'type': 'Forms Without CSRF Protection',
                    'severity': 'MEDIUM',
                    'description': f'Found {len(forms_without_csrf)} forms without CSRF protection',
                    'evidence': {
                        'forms_count': len(forms_without_csrf),
                        'sample_forms': forms_without_csrf[:3]
                    },
                    'recommendation': 'Implement CSRF tokens for all forms',
                    'cve': 'CWE-352',
                    'impact': 'Potential CSRF attacks against form submissions'
                })
        
        # Shodan vulnerability analysis
        if 'shodan' in findings and not findings['shodan'].get('error'):
            shodan = findings['shodan']
            shodan_vulns = shodan.get('vulnerabilities', [])
            
            if shodan_vulns:
                vulnerabilities.append({
                    'type': 'Known Vulnerabilities (Shodan)',
                    'severity': 'HIGH',
                    'description': f'Found {len(shodan_vulns)} known vulnerabilities via Shodan',
                    'evidence': {
                        'vulnerabilities': shodan_vulns,
                        'exposed_services': len(shodan.get('exposed_services', []))
                    },
                    'recommendation': 'Patch identified vulnerabilities immediately',
                    'cve': 'CWE-200',
                    'impact': 'Known vulnerabilities may be exploitable'
                })
        
        return vulnerabilities
    
    def _generate_recommendations(self, findings: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate comprehensive security recommendations based on findings"""
        recommendations = []
        
        # Priority-based recommendations
        high_priority = []
        medium_priority = []
        low_priority = []
        
        # General security recommendations
        general_recommendations = [
            "Implement comprehensive logging and monitoring for all discovered services",
            "Regularly update and patch all identified services and applications",
            "Conduct regular security assessments and penetration testing",
            "Implement a security incident response plan",
            "Establish regular backup and recovery procedures"
        ]
        
        # Specific recommendations based on vulnerabilities
        for vuln in vulnerabilities:
            if vuln.get('recommendation'):
                if vuln['severity'] == 'HIGH':
                    high_priority.append(vuln['recommendation'])
                elif vuln['severity'] == 'MEDIUM':
                    medium_priority.append(vuln['recommendation'])
                else:
                    low_priority.append(vuln['recommendation'])
        
        # DNS-specific recommendations
        if 'dns' in findings:
            dns = findings['dns']
            analysis = dns.get('analysis', {})
            
            if not analysis.get('spf_record'):
                high_priority.append("Implement SPF record to prevent email spoofing attacks")
            
            if not analysis.get('dmarc_record'):
                medium_priority.append("Implement DMARC record to improve email security and monitoring")
            
            if 'zone_transfer' in findings and findings['zone_transfer'].get('vulnerable'):
                high_priority.append("Immediately restrict DNS zone transfers to authorized name servers only")
        
        # Network security recommendations
        if 'port_scan' in findings:
            port_scan = findings['port_scan']
            open_ports = port_scan.get('open_ports', [])
            
            if len(open_ports) > 20:
                medium_priority.append("Implement firewall rules to restrict unnecessary port access and reduce attack surface")
            
            # Check for specific dangerous services
            dangerous_services = [21, 23, 3389, 5900]  # FTP, Telnet, RDP, VNC
            found_dangerous = [p for p in open_ports if p in dangerous_services]
            
            if found_dangerous:
                high_priority.append(f"Immediately secure or remove access to dangerous services on ports: {', '.join(map(str, found_dangerous))}")
            
            # Database services
            db_ports = [3306, 5432, 27017, 6379, 11211]  # MySQL, PostgreSQL, MongoDB, Redis, Memcached
            found_db = [p for p in open_ports if p in db_ports]
            
            if found_db:
                medium_priority.append(f"Secure database services on ports {', '.join(map(str, found_db))} with strong authentication and network restrictions")
        
        # Web application recommendations
        if 'web_crawl' in findings:
            web_crawl = findings['web_crawl']
            
            if web_crawl.get('forms'):
                medium_priority.append("Implement CSRF protection for all web forms")
                medium_priority.append("Add input validation and sanitization for all form inputs")
            
            if web_crawl.get('technologies'):
                medium_priority.append("Keep all identified technologies and frameworks updated to latest secure versions")
        
        # Security headers recommendations
        if 'security_headers' in findings:
            sec_headers = findings['security_headers']
            security_score = sec_headers.get('security_score', 0)
            
            if security_score < 50:
                high_priority.append("Implement missing security headers immediately to improve web application security")
            elif security_score < 80:
                medium_priority.append("Enhance security headers implementation to achieve better protection")
        
        # VirusTotal recommendations
        if 'virustotal' in findings and not findings['virustotal'].get('error'):
            vt = findings['virustotal']
            reputation = vt.get('reputation', {})
            
            if reputation.get('malicious', 0) > 0:
                high_priority.append("Investigate and remediate security issues flagged by VirusTotal scanners")
                high_priority.append("Consider implementing additional security monitoring and detection systems")
            
            if reputation.get('suspicious', 0) > 0:
                medium_priority.append("Monitor target for suspicious activity and investigate scanner reports")
        
        # Shodan recommendations
        if 'shodan' in findings and not findings['shodan'].get('error'):
            shodan = findings['shodan']
            
            if shodan.get('vulnerabilities'):
                high_priority.append("Patch all vulnerabilities identified by Shodan immediately")
                high_priority.append("Implement vulnerability management process for ongoing security")
            
            if shodan.get('exposed_services'):
                medium_priority.append("Review and secure all exposed services identified by Shodan")
        
        # Subdomain recommendations
        if 'subdomains' in findings:
            subdomains = findings['subdomains']
            
            if len(subdomains) > 20:
                medium_priority.append("Implement subdomain monitoring to detect unauthorized subdomains")
                medium_priority.append("Consider implementing wildcard SSL certificates for better subdomain management")
            
            if len(subdomains) > 50:
                high_priority.append("Conduct comprehensive subdomain audit and remove unused subdomains")
        
        # Admin panel recommendations
        if 'directory_bruteforce' in findings:
            dir_brute = findings['directory_bruteforce']
            
            if dir_brute.get('admin_panels'):
                high_priority.append("Secure all discovered admin panels with strong authentication and access controls")
                high_priority.append("Consider implementing IP whitelisting for administrative access")
            
            if dir_brute.get('backup_files'):
                medium_priority.append("Remove or secure all exposed backup files to prevent information disclosure")
                medium_priority.append("Implement proper backup procedures that don't expose files publicly")
        
        # Infrastructure recommendations
        if 'whois' in findings and not findings['whois'].get('error'):
            whois = findings['whois']
            
            if whois.get('domain_age_years', 0) < 1:
                medium_priority.append("New domain detected - implement additional monitoring and security measures")
            
            if whois.get('registrant_country'):
                medium_priority.append("Ensure compliance with data protection regulations for the target jurisdiction")
        
        # Compile final recommendations in priority order
        recommendations.extend(high_priority)
        recommendations.extend(medium_priority)
        recommendations.extend(low_priority)
        recommendations.extend(general_recommendations)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:15]  # Limit to top 15 recommendations
    
    def _display_mission_results(self, report: Dict[str, Any]):
        """Display mission results with enhanced accuracy and detail"""
        
        # Create results table
        table = Table(title="🎯 RECONNAISSANCE MISSION RESULTS", border_style="red")
        table.add_column("Parameter", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        table.add_row("Target", report['target'])
        table.add_row("Mission Type", report['mission_type'].upper())
        table.add_row("Duration", report['mission_duration'])
        table.add_row("Vulnerabilities Found", str(len(report.get('vulnerabilities', []))))
        table.add_row("Status", f"[green]{report['mission_status']}[/green]")
        
        console.print(table)
        
        # Display vulnerabilities with enhanced detail
        if report.get('vulnerabilities'):
            console.print(f"\n[bold red]🚨 VULNERABILITIES FOUND:[/bold red]")
            vuln_table = Table(border_style="red")
            vuln_table.add_column("Type", style="cyan")
            vuln_table.add_column("Severity", style="red")
            vuln_table.add_column("Description", style="white")
            vuln_table.add_column("Evidence", style="yellow")
            
            for vuln in report['vulnerabilities']:
                severity_color = "red" if vuln['severity'] == 'HIGH' else "yellow"
                evidence = str(vuln.get('evidence', 'N/A'))[:50] + "..." if len(str(vuln.get('evidence', 'N/A'))) > 50 else str(vuln.get('evidence', 'N/A'))
                vuln_table.add_row(
                    vuln['type'],
                    f"[{severity_color}]{vuln['severity']}[/{severity_color}]",
                    vuln['description'],
                    evidence
                )
            
            console.print(vuln_table)
        else:
            console.print(f"\n[bold green]✅ No vulnerabilities detected[/bold green]")
        
        # Enhanced key findings summary
        console.print(f"\n[bold cyan]📋 DETAILED FINDINGS SUMMARY:[/bold cyan]")
        
        findings = report.get('findings', {})
        
        # WHOIS Information
        if 'whois' in findings and not findings['whois'].get('error'):
            whois = findings['whois']
            console.print(f"\n[bold blue]🌐 WHOIS Information:[/bold blue]")
            if 'registrar' in whois and whois['registrar']:
                console.print(f"  Registrar: {whois['registrar']}")
            if 'domain_age_years' in whois:
                console.print(f"  Domain Age: {whois['domain_age_years']} years")
            if 'registrant_country' in whois and whois['registrant_country']:
                console.print(f"  Country: {whois['registrant_country']}")
            if 'name_servers' in whois and whois['name_servers']:
                console.print(f"  Name Servers: {', '.join(whois['name_servers'][:3])}{'...' if len(whois['name_servers']) > 3 else ''}")
        elif 'whois' in findings and findings['whois'].get('error'):
            console.print(f"\n[bold red]❌ WHOIS Error: {findings['whois']['error']}[/bold red]")
        
        # DNS Information
        if 'dns' in findings:
            dns = findings['dns']
            console.print(f"\n[bold blue]🔍 DNS Records:[/bold blue]")
            if dns.get('A'):
                console.print(f"  A Records: {', '.join(dns['A'])}")
            if dns.get('AAAA'):
                console.print(f"  AAAA Records: {', '.join(dns['AAAA'])}")
            if dns.get('MX'):
                console.print(f"  MX Records: {len(dns['MX'])} found")
            if dns.get('NS'):
                console.print(f"  NS Records: {', '.join(dns['NS'])}")
            if dns.get('TXT'):
                console.print(f"  TXT Records: {len(dns['TXT'])} found")
            
            # DNS Analysis
            if 'analysis' in dns:
                analysis = dns['analysis']
                if analysis.get('spf_record'):
                    console.print(f"  SPF Record: ✅ Present")
                else:
                    console.print(f"  SPF Record: ❌ Missing")
                if analysis.get('dmarc_record'):
                    console.print(f"  DMARC Record: ✅ Present")
                else:
                    console.print(f"  DMARC Record: ❌ Missing")
        
        # Subdomain Information
        if 'subdomains' in findings:
            subdomains = findings['subdomains']
            console.print(f"\n[bold blue]🔗 Subdomains:[/bold blue]")
            console.print(f"  Total Found: {len(subdomains)}")
            if subdomains:
                console.print(f"  Sample: {', '.join(subdomains[:5])}{'...' if len(subdomains) > 5 else ''}")
        
        # Port Scan Results
        if 'port_scan' in findings:
            port_scan = findings['port_scan']
            console.print(f"\n[bold blue]🔌 Port Scan Results:[/bold blue]")
            open_ports = port_scan.get('open_ports', [])
            console.print(f"  Open Ports: {len(open_ports)}")
            if open_ports:
                # Group ports by service type
                web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443, 3000, 8000, 9000]]
                db_ports = [p for p in open_ports if p in [3306, 5432, 27017, 6379, 5984]]
                admin_ports = [p for p in open_ports if p in [22, 21, 23, 3389, 5900]]
                other_ports = [p for p in open_ports if p not in web_ports + db_ports + admin_ports]
                
                if web_ports:
                    console.print(f"  Web Services: {', '.join(map(str, web_ports))}")
                if db_ports:
                    console.print(f"  Database Services: {', '.join(map(str, db_ports))}")
                if admin_ports:
                    console.print(f"  Admin Services: {', '.join(map(str, admin_ports))}")
                if other_ports:
                    console.print(f"  Other Services: {', '.join(map(str, other_ports[:10]))}{'...' if len(other_ports) > 10 else ''}")
        
        # VirusTotal Results
        if 'virustotal' in findings and not findings['virustotal'].get('error'):
            vt = findings['virustotal']
            console.print(f"\n[bold blue]🛡️ VirusTotal Reputation:[/bold blue]")
            if 'reputation' in vt:
                rep = vt['reputation']
                console.print(f"  Malicious: {rep.get('malicious', 0)}")
                console.print(f"  Suspicious: {rep.get('suspicious', 0)}")
                console.print(f"  Clean: {rep.get('clean', 0)}")
                console.print(f"  Total Scans: {rep.get('total_scans', 0)}")
            
            if vt.get('detected_urls'):
                console.print(f"  Detected URLs: {len(vt['detected_urls'])}")
            if vt.get('detected_samples'):
                console.print(f"  Detected Samples: {len(vt['detected_samples'])}")
        elif 'virustotal' in findings and findings['virustotal'].get('error'):
            console.print(f"\n[bold red]❌ VirusTotal Error: {findings['virustotal']['error']}[/bold red]")
        
        # Shodan Results
        if 'shodan' in findings and not findings['shodan'].get('error'):
            shodan = findings['shodan']
            console.print(f"\n[bold blue]🔍 Shodan Intelligence:[/bold blue]")
            console.print(f"  Total Results: {shodan.get('total_results', 0)}")
            if shodan.get('vulnerabilities'):
                console.print(f"  Vulnerabilities: {len(shodan['vulnerabilities'])}")
            if shodan.get('exposed_services'):
                console.print(f"  Exposed Services: {len(shodan['exposed_services'])}")
            if shodan.get('geolocation', {}).get('country'):
                console.print(f"  Location: {shodan['geolocation']['country']}")
        elif 'shodan' in findings and findings['shodan'].get('error'):
            console.print(f"\n[bold red]❌ Shodan Error: {findings['shodan']['error']}[/bold red]")
        
        # Web Application Results
        if 'web_crawl' in findings:
            web_crawl = findings['web_crawl']
            console.print(f"\n[bold blue]🌐 Web Application Analysis:[/bold blue]")
            console.print(f"  Pages Discovered: {len(web_crawl.get('discovered_urls', []))}")
            console.print(f"  Forms Found: {len(web_crawl.get('forms', []))}")
            console.print(f"  Emails Found: {len(web_crawl.get('emails', []))}")
            console.print(f"  Technologies: {len(web_crawl.get('technologies', []))}")
            if web_crawl.get('technologies'):
                console.print(f"  Tech Stack: {', '.join(list(web_crawl['technologies'])[:5])}{'...' if len(web_crawl['technologies']) > 5 else ''}")
        
        # Directory Bruteforce Results
        if 'directory_bruteforce' in findings:
            dir_brute = findings['directory_bruteforce']
            console.print(f"\n[bold blue]📁 Directory Bruteforce:[/bold blue]")
            console.print(f"  Interesting Paths: {len(dir_brute.get('interesting_responses', []))}")
            console.print(f"  Admin Panels: {len(dir_brute.get('admin_panels', []))}")
            console.print(f"  Backup Files: {len(dir_brute.get('backup_files', []))}")
            if dir_brute.get('admin_panels'):
                console.print(f"  Admin URLs: {', '.join([p['path'] for p in dir_brute['admin_panels'][:3]])}{'...' if len(dir_brute['admin_panels']) > 3 else ''}")
        
        # Security Headers
        if 'security_headers' in findings:
            sec_headers = findings['security_headers']
            console.print(f"\n[bold blue]🔒 Security Headers:[/bold blue]")
            console.print(f"  Security Score: {sec_headers.get('security_score', 0):.1f}%")
            present_headers = sec_headers.get('present_headers', {})
            missing_headers = sec_headers.get('missing_headers', [])
            console.print(f"  Present: {len(present_headers)} headers")
            console.print(f"  Missing: {len(missing_headers)} headers")
            if missing_headers:
                console.print(f"  Missing: {', '.join(missing_headers)}")
        
        # Zone Transfer Results
        if 'zone_transfer' in findings:
            zone_transfer = findings['zone_transfer']
            console.print(f"\n[bold blue]🔄 Zone Transfer Test:[/bold blue]")
            if zone_transfer.get('vulnerable'):
                console.print(f"  Status: [bold red]VULNERABLE[/bold red]")
                console.print(f"  Vulnerable NS: {zone_transfer.get('vulnerable_ns', 'Unknown')}")
                console.print(f"  Records Exposed: {len(zone_transfer.get('records', []))}")
            else:
                console.print(f"  Status: [bold green]SECURE[/bold green]")
        
        # Display recommendations with priority
        if report.get('recommendations'):
            console.print(f"\n[bold yellow]💡 SECURITY RECOMMENDATIONS:[/bold yellow]")
            for i, rec in enumerate(report['recommendations'][:8], 1):  # Show top 8
                console.print(f"{i}. {rec}")
        
        # Display API status
        api_status = self._validate_apis()
        console.print(f"\n[bold blue]🔑 API Status:[/bold blue]")
        for api, status in api_status.items():
            status_color = "green" if status else "red"
            status_text = "✓ Available" if status else "✗ Not configured"
            console.print(f"  {api.title()}: [{status_color}]{status_text}[/{status_color}]")

def run_recon_agent(target: str, mission_type: str = "comprehensive") -> dict:
    """
    Runs the UltimateReconAgent and returns the result as a dict compatible with ReconReport for REST API usage.
    Converts all set() objects in the result to lists for JSON serialization.
    Ensures all dict keys are strings.
    """
    agent = UltimateReconAgent()
    result = agent.run_reconnaissance(target, mission_type)

    def convert_sets_and_keys(obj):
        if isinstance(obj, dict):
            return {str(k): convert_sets_and_keys(v) for k, v in obj.items()}
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, list):
            return [convert_sets_and_keys(v) for v in obj]
        else:
            return obj

    result = convert_sets_and_keys(result)

    # --- Ensure required nested keys for Pydantic compatibility ---
    findings = result.get('findings', {})
    # Ensure virustotal.whois_info.registrar exists
    vt = findings.get('virustotal')
    if vt is not None:
        if 'whois_info' not in vt or vt['whois_info'] is None:
            vt['whois_info'] = {'registrar': None}
        elif isinstance(vt['whois_info'], dict) and 'registrar' not in vt['whois_info']:
            vt['whois_info']['registrar'] = None
    result['findings'] = findings

    return result

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function"""
    
    if len(sys.argv) < 2:
        logger.banner()
        console.print("[bold red]Usage: ./ultimate_recon_agent.py <target> [mission_type][/bold red]")
        console.print("[bold yellow]Example: ./ultimate_recon_agent.py example.com comprehensive[/bold yellow]")
        sys.exit(1)
    
    target = sys.argv[1]
    mission_type = sys.argv[2] if len(sys.argv) > 2 else "comprehensive"
    
    # Run reconnaissance
    result = run_recon_agent(target, mission_type)
    
    # Output result as JSON
    try:
        print(json.dumps(result, indent=4))
    except Exception as e:
        logger.error(f"Failed to serialize result to JSON: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
