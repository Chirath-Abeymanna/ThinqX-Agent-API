import json
from datetime import datetime
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from cms_recon import CMSRecon
from logger import logger
import random
from rich.progress import Progress, SpinnerColumn, TextColumn
import os
from urllib.parse import urlparse


console = Console()
from rich.console import Console
from rich.table import Table
from cms_recon import CMSRecon
from logger import logger
import random
from rich.progress import Progress, SpinnerColumn, TextColumn
import os
from urllib.parse import urlparse


console = Console()


class CMSScannerAgent:
    """Comprehensive CMS Scanner Agent"""
    
    def __init__(self):
        self.cms_recon = CMSRecon()
        self.scan_throttle = 0.5  # Seconds between requests
        self.report_file = None
    
    async def run_cms_scan(self, target: str) -> Dict[str, Any]:
        """Execute comprehensive CMS scan"""
        logger.banner()
        console.print(f"\n[bold bright_red]TARGET SYSTEM:[/bold bright_red] [bright_white]{target}[/bright_white]")
        console.print(f"[bold bright_cyan]SCAN PROFILE:[/bold bright_cyan] [bright_white]CMS Security Assessment[/bright_white]")
        console.print(f"[bold bright_yellow]STATUS:[/bold bright_yellow] [bright_green]INITIALIZING...[/bright_green]\n")
        
        # Ensure target has scheme
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        # Prepare scan folder and wire context for downstream saving (VT, etc.)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_name = urlparse(target).hostname or "unknown"
        scan_dir = os.path.join("results", domain_name, timestamp)
        os.makedirs(scan_dir, exist_ok=True)
        self.cms_recon.scan_output_dir = scan_dir
        self.cms_recon.scan_timestamp = timestamp

        start_time = datetime.now()
        report = {
            'target': target,
            'start_time': start_time.isoformat(),
            'findings': {},
            'vulnerabilities': [],
            'recommendations': [],
            'status': 'RUNNING'
        }
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Initializing security scan...", total=8)
                
                # CMS Detection
                progress.update(task, description="Analyzing CMS platform...")
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
                    progress.update(task, description="Enumerating plugins and themes...")
                    plugins_themes = await self.cms_recon.scan_plugins_themes(working_url, cms_type)
                    report['findings']['plugins_themes'] = plugins_themes
                    progress.advance(task)
                    
                    # User Enumeration
                    progress.update(task, description="Testing user enumeration vectors...")
                    user_enum = await self.cms_recon.user_enumeration(working_url)
                    report['findings']['user_enumeration'] = user_enum
                    progress.advance(task)
                    
                    # Malware Scan
                    progress.update(task, description="Scanning for malware indicators...")
                    malware_scan = await self.cms_recon.malware_scan(working_url)
                    report['findings']['malware_scan'] = malware_scan
                    progress.advance(task)
                    
                    # OWASP Vulnerabilities
                    progress.update(task, description="Assessing OWASP Top 10 vulnerabilities...")
                    owasp_scan = await self.cms_recon.check_owasp_vulnerabilities(working_url)
                    report['findings']['owasp_vulnerabilities'] = owasp_scan
                    progress.advance(task)
                    
                    # Configuration Weaknesses
                    progress.update(task, description="Analyzing configuration security...")
                    config_scan = await self.cms_recon.check_config_weaknesses(working_url, cms_type)
                    report['findings']['config_weaknesses'] = config_scan
                    progress.advance(task)
                    
                    # Brute Force Vulnerability
                    progress.update(task, description="Testing authentication security...")
                    brute_force = await self.cms_recon.check_brute_force(working_url, cms_type)
                    report['findings']['brute_force'] = brute_force
                    progress.advance(task)
                    
                    # Content Change Monitoring
                    progress.update(task, description="Establishing content baseline...")
                    content_monitor = await self.cms_recon.content_change_monitoring(working_url)
                    report['findings']['content_monitoring'] = content_monitor
                    progress.advance(task)
                    
                    # Domain Reputation
                    progress.update(task, description="Verifying domain reputation...")
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
            
            # Save report and all outputs in results/{domain}/{timestamp}/
            safe_target = target.replace('://', '_').replace('/', '_').replace('.', '_')
            # Save the main report
            self.report_file = os.path.join(scan_dir, f"cms_scan_report_{safe_target}.json")
            with open(self.report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)

            # Ensure a copy of baseline sits in this scan folder for provenance
            content_monitor = report['findings'].get('content_monitoring', {})
            baseline_path = content_monitor.get('baseline_path')
            if baseline_path and os.path.exists(baseline_path):
                import shutil
                try:
                    shutil.copy2(baseline_path, os.path.join(scan_dir, 'baseline.txt'))
                except Exception as e:
                    logger.warning(f"Could not copy baseline to scan folder: {e}")

            # No VT copying: recon writes VirusTotal JSONs directly into scan_dir during checks

            self._display_results(report)
            return report
        except Exception as e:
            logger.error(f"Unexpected error during CMS scan: {str(e)}")
            report['status'] = 'FAILED'
            report['error'] = str(e)
            end_time = datetime.now()
            report['end_time'] = end_time.isoformat()
            report['duration'] = str(end_time - start_time)
            # Try to persist the error report
            try:
                safe_target = target.replace('://', '_').replace('/', '_').replace('.', '_')
                self.report_file = os.path.join(scan_dir, f"cms_scan_report_{safe_target}.json")
                with open(self.report_file, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
            except Exception as write_err:
                logger.warning(f"Failed to write error report: {write_err}")
            return report
        finally:
            try:
                await self.cms_recon.close()
            except Exception as close_err:
                logger.warning(f"Failed to close HTTP session: {close_err}")
    
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
        
        # Add social media info if found
        if cms_detection.get('social_media'):
            social_count = sum(len(links) for links in cms_detection['social_media'].values())
            table.add_row("Social Media Links", f"{social_count} found")
        
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
            console.print(f"\n[bold red]🚨 SECURITY VULNERABILITIES DETECTED:[/bold red]")
            vuln_table = Table(border_style="red", show_header=True, header_style="bold red")
            vuln_table.add_column("Type", style="cyan", min_width=20)
            vuln_table.add_column("Severity", style="red", min_width=8)
            vuln_table.add_column("Description", style="white", min_width=40)
            
            for vuln in report['vulnerabilities']:
                severity_color = "red" if vuln['severity'] in ['HIGH', 'CRITICAL'] else "yellow"
                description = vuln['description'][:70] + "..." if len(vuln['description']) > 70 else vuln['description']
                vuln_table.add_row(
                    vuln['type'],
                    f"[{severity_color}]{vuln['severity']}[/{severity_color}]",
                    description
                )
            
            console.print(vuln_table)
        else:
            console.print(f"\n[bold green]✅ NO MAJOR VULNERABILITIES DETECTED[/bold green]")
            console.print(f"[dim]This doesn't guarantee the site is secure - perform additional testing[/dim]")
        
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
            
            # Show social media links
            if cms_detection.get('social_media'):
                console.print(f"\n[bold blue]🔗 Social Media Links:[/bold blue]")
                social_media = cms_detection['social_media']
                for platform, links in social_media.items():
                    if links:
                        console.print(f"  [cyan]{platform.title()}:[/cyan]")
                        for link in links[:2]:  # Show first 2 per platform
                            console.print(f"    • {link}")
                        if len(links) > 2:
                            console.print(f"    • ... and {len(links)-2} more")
            
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
            console.print(f"\n[bold bright_yellow]SECURITY RECOMMENDATIONS:[/bold bright_yellow]")
            for i, rec in enumerate(report['recommendations'][:12], 1):
                console.print(f"  {i:2d}. {rec}")
        
        # Display scan summary
        console.print(f"\n[bold bright_green]SCAN COMPLETED SUCCESSFULLY[/bold bright_green]")
        console.print(f"[bold bright_cyan]Report Location:[/bold bright_cyan] {os.path.dirname(self.report_file)}/")
        console.print(f"[bold bright_cyan]Primary Report:[/bold bright_cyan] {os.path.basename(self.report_file)}")
        
        # Show additional files if present
        scan_dir = os.path.dirname(self.report_file)
        if os.path.exists(scan_dir):
            files = [f for f in os.listdir(scan_dir) if f != os.path.basename(self.report_file)]
            if files:
                console.print(f"[bold bright_cyan]Additional Artifacts:[/bold bright_cyan]")
                for f in files[:5]:  # Show first 5 additional files
                    if 'virustotal' in f:
                        console.print(f"  • {f}")
                    elif 'baseline' in f:
                        console.print(f"  • {f}")
                    else:
                        console.print(f"  • {f}")
                if len(files) > 5:
                    console.print(f"  ... and {len(files)-5} more files")
        
        console.print(f"\n[bold bright_red]NOTICE:[/bold bright_red] [bright_white]Use results responsibly and only on authorized targets[/bright_white]")
