
#!/usr/bin/env python3
"""
SQL Injection Assessment Agent - Main Execution Script
Command-line interface for running SQL injection assessments
"""
import os
import json
import asyncio
import argparse
import sys
import time
from typing import Optional
import colorama
from colorama import Fore, Style

from app.models.sql_inject_model import SQLInjectionReport, AssessmentSummary, InjectionResult, TestResult, TechnicalDetails


try:
    from .agent import SQLInjectionAgent
except ImportError:
    from agent import SQLInjectionAgent

# Initialize colorama
colorama.init()

def print_banner():
    """Print the application banner"""
    banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    SQL INJECTION ASSESSMENT AGENT            ║
║                        Powered by LangGraph                  ║
║                                                              ║
║  A comprehensive AI agent for detecting SQL injection       ║
║  vulnerabilities using advanced techniques and payloads     ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def validate_url(url: str) -> bool:
    """Validate if the provided URL is properly formatted"""
    import re
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return bool(url_pattern.match(url))

async def run_single_assessment(target_url: str, verbose: bool = False) -> bool:
    """Run a single SQL injection assessment"""
    print(f"{Fore.CYAN}[+] Initializing SQL Injection Agent...{Style.RESET_ALL}")
    
    try:
        agent = SQLInjectionAgent()
        
        print(f"{Fore.CYAN}[+] Starting assessment for: {target_url}{Style.RESET_ALL}")
        start_time = time.time()
        
        result = await agent.run_assessment(target_url)
        
        end_time = time.time()
        duration = end_time - start_time
        
        if result['success']:
            print(f"\n{Fore.GREEN}[+] Assessment completed successfully!{Style.RESET_ALL}")
            print(f"Duration: {duration:.2f} seconds")
            
            if verbose:
                print(f"\n{Fore.CYAN}Detailed Results:{Style.RESET_ALL}")
                print(f"Confidence Score: {result['report']['confidence_score']:.2f}")
                print(f"Vulnerable Parameters: {len(result['report']['vulnerable_parameters'])}")
                
                if result['report']['vulnerable_parameters']:
                    print(f"Vulnerable Parameters: {', '.join(result['report']['vulnerable_parameters'])}")
                
                print(f"\nRecommendations:")
                for rec in result['report']['recommendations']:
                    print(f"  - {rec}")
            
            return True
        else:
            print(f"{Fore.RED}[-] Assessment failed: {result.get('error', 'Unknown error')}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[-] Error during assessment: {str(e)}{Style.RESET_ALL}")
        return False

async def run_batch_assessment(targets_file: str, verbose: bool = False) -> None:
    """Run assessments for multiple targets from a file"""
    print(f"{Fore.CYAN}[+] Running batch assessment from file: {targets_file}{Style.RESET_ALL}")
    
    try:
        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"Found {len(targets)} targets to assess")
        
        results = {
            'successful': 0,
            'failed': 0,
            'vulnerable': 0
        }
        
        for i, target in enumerate(targets, 1):
            print(f"\n{Fore.CYAN}[{i}/{len(targets)}] Assessing: {target}{Style.RESET_ALL}")
            
            if not validate_url(target):
                print(f"{Fore.RED}[-] Invalid URL format: {target}{Style.RESET_ALL}")
                results['failed'] += 1
                continue
            
            success = await run_single_assessment(target, verbose)
            
            if success:
                results['successful'] += 1
            else:
                results['failed'] += 1
        
        # Print batch summary
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"BATCH ASSESSMENT SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Total Targets: {len(targets)}")
        print(f"Successful Assessments: {results['successful']}")
        print(f"Failed Assessments: {results['failed']}")
        print(f"Success Rate: {(results['successful']/len(targets))*100:.1f}%")
        
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Targets file not found: {targets_file}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error during batch assessment: {str(e)}{Style.RESET_ALL}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="SQL Injection Assessment Agent using LangGraph",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m SQL_INJECTION.main https://example.com/vulnerable.php?id=1
  python -m SQL_INJECTION.main -f targets.txt
  python -m SQL_INJECTION.main https://example.com -v
        """
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='Target URL to assess for SQL injection vulnerabilities'
    )
    
    parser.add_argument(
        '-f', '--file',
        help='File containing list of target URLs (one per line)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output with detailed results'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='SQL Injection Assessment Agent v1.0.0'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Validate arguments
    if not args.target and not args.file:
        print(f"{Fore.RED}[-] Error: Please provide either a target URL or a targets file{Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)
    
    if args.target and args.file:
        print(f"{Fore.RED}[-] Error: Please provide either a target URL or a targets file, not both{Style.RESET_ALL}")
        sys.exit(1)
    
    # Run assessment
    try:
        if args.file:
            asyncio.run(run_batch_assessment(args.file, args.verbose))
        else:
            if not validate_url(args.target):
                print(f"{Fore.RED}[-] Error: Invalid URL format: {args.target}{Style.RESET_ALL}")
                sys.exit(1)
            
            success = asyncio.run(run_single_assessment(args.target, args.verbose))
            sys.exit(0 if success else 1)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Assessment interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[-] Unexpected error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

def run_sql_injection_agent(target_url: str) -> SQLInjectionReport:
    # Simulate running the agent and finding the latest report for the target_url
    report_dir = os.path.dirname(__file__)
    files = [f for f in os.listdir(report_dir) if f.startswith('sql_injection_report_') and f.endswith('.json')]
    selected_report = None
    for fname in sorted(files, reverse=True):
        with open(os.path.join(report_dir, fname), 'r', encoding='utf-8') as f:
            data = json.load(f)
            if data.get('target_url') == target_url:
                selected_report = data
                break
    if not selected_report:
        # Return an empty report if not found
        return SQLInjectionReport(
            target_url=target_url,
            assessment_summary=AssessmentSummary(
                total_parameters_tested=0,
                vulnerable_parameters=0,
                total_injection_tests=0,
                successful_injections=0,
                confidence_score=0.0,
                risk_level=""
            ),
            vulnerable_parameters=[],
            successful_injections=[],
            recommendations=[],
            technical_details=TechnicalDetails(
                discovered_parameters=[],
                all_test_results=[]
            )
        )
    # Fill missing fields with null/empty values
    summary = selected_report.get('assessment_summary', {})
    assessment_summary = AssessmentSummary(
        total_parameters_tested=summary.get('total_parameters_tested', 0),
        vulnerable_parameters=summary.get('vulnerable_parameters', 0),
        total_injection_tests=summary.get('total_injection_tests', 0),
        successful_injections=summary.get('successful_injections', 0),
        confidence_score=summary.get('confidence_score', 0.0),
        risk_level=summary.get('risk_level', "")
    )
    vulnerable_parameters = selected_report.get('vulnerable_parameters', [])
    successful_injections = [
        InjectionResult(
            parameter=inj.get('parameter'),
            payload=inj.get('payload', ""),
            type=inj.get('type', ""),
            confidence=inj.get('confidence', 0.0),
            extracted_data=inj.get('extracted_data'),
            error_message=inj.get('error_message')
        ) for inj in selected_report.get('successful_injections', [])
    ]
    recommendations = selected_report.get('recommendations', [])
    tech = selected_report.get('technical_details', {})
    discovered_parameters = tech.get('discovered_parameters', [])
    all_test_results = [
        TestResult(
            payload=tr.get('payload', ""),
            type=tr.get('type', ""),
            success=tr.get('success', False),
            response_time=tr.get('response_time', 0.0),
            confidence=tr.get('confidence', 0.0)
        ) for tr in tech.get('all_test_results', [])
    ]
    technical_details = TechnicalDetails(
        discovered_parameters=discovered_parameters,
        all_test_results=all_test_results
    )
    return SQLInjectionReport(
        target_url=selected_report.get('target_url', target_url),
        assessment_summary=assessment_summary,
        vulnerable_parameters=vulnerable_parameters,
        successful_injections=successful_injections,
        recommendations=recommendations,
        technical_details=technical_details
    )


if __name__ == "__main__":
    main() 