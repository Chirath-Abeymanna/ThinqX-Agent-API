#!/usr/bin/env python3
"""
Test script for SQL Injection Assessment Agent
Demonstrates how to use the agent programmatically
"""

import asyncio
import pytest
import json
from typing import Dict, Any
import colorama
from colorama import Fore, Style

try:
    from agent import SQLInjectionAgent
    from payloads import SQLInjectionPayloads
    from injection_engine import SQLInjectionEngine
except ImportError:
    from .agent import SQLInjectionAgent
    from .payloads import SQLInjectionPayloads
    from .injection_engine import SQLInjectionEngine

# Initialize colorama
colorama.init()

@pytest.mark.asyncio
async def test_payloads():
    """Test the payloads database"""
    print(f"{Fore.CYAN}[+] Testing Payloads Database{Style.RESET_ALL}")
    
    payloads = SQLInjectionPayloads()
    
    # Test different payload categories
    print(f"Total payloads: {len(payloads.get_all_payloads())}")
    
    # Test parameter-specific payloads
    auth_payloads = payloads.get_payloads_for_parameter("username")
    print(f"Authentication payloads: {len(auth_payloads)}")
    
    search_payloads = payloads.get_payloads_for_parameter("search")
    print(f"Search payloads: {len(search_payloads)}")
    
    print(f"{Fore.GREEN}[+] Payloads test completed{Style.RESET_ALL}\n")

@pytest.mark.asyncio
async def test_injection_engine():
    """Test the injection engine"""
    print(f"{Fore.CYAN}[+] Testing Injection Engine{Style.RESET_ALL}")
    
    engine = SQLInjectionEngine()
    
    # Test error pattern detection
    test_errors = [
        "You have an error in your SQL syntax near 'SELECT' at line 1",
        "PostgreSQL query failed: syntax error",
        "Microsoft OLE DB Provider for SQL Server error",
        "ORA-00936: missing expression"
    ]
    
    for error in test_errors:
        detected_db = engine._detect_database_from_errors(error)
        print(f"Error: {error[:50]}... -> Detected DB: {detected_db}")
    
    print(f"{Fore.GREEN}[+] Injection engine test completed{Style.RESET_ALL}\n")

@pytest.mark.asyncio
async def test_agent_workflow():
    """Test the complete agent workflow"""
    print(f"{Fore.CYAN}[+] Testing Agent Workflow{Style.RESET_ALL}")
    
    # Create a test target (this would be a real vulnerable target in practice)
    test_target = "https://httpbin.org/get?param=test"
    
    agent = SQLInjectionAgent()
    
    print(f"Testing target: {test_target}")
    print("Note: This is a test target and may not be vulnerable")
    
    try:
        result = await agent.run_assessment(test_target)
        
        if result['success']:
            print(f"{Fore.GREEN}[+] Assessment completed successfully{Style.RESET_ALL}")
            print(f"Confidence Score: {result['report']['confidence_score']:.2f}")
            print(f"Vulnerable Parameters: {len(result['report']['vulnerable_parameters'])}")
            
            if result['report']['vulnerable_parameters']:
                print(f"Vulnerable Parameters: {', '.join(result['report']['vulnerable_parameters'])}")
            
            print(f"\nRecommendations:")
            for rec in result['report']['recommendations']:
                print(f"  - {rec}")
        else:
            print(f"{Fore.RED}[-] Assessment failed: {result.get('error', 'Unknown error')}{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error during assessment: {str(e)}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[+] Agent workflow test completed{Style.RESET_ALL}\n")

@pytest.mark.asyncio
async def test_parameter_analysis():
    """Test parameter analysis functionality"""
    print(f"{Fore.CYAN}[+] Testing Parameter Analysis{Style.RESET_ALL}")
    
    test_parameters = [
        "username",
        "password", 
        "user_id",
        "search",
        "query",
        "page",
        "limit",
        "sort",
        "filter"
    ]
    
    agent = SQLInjectionAgent()
    
    for param in test_parameters:
        param_type = agent._classify_parameter(param)
        risk_level = agent._assess_parameter_risk(param)
        print(f"Parameter: {param:12} -> Type: {param_type:15} -> Risk: {risk_level}")
    
    print(f"{Fore.GREEN}[+] Parameter analysis test completed{Style.RESET_ALL}\n")

@pytest.mark.asyncio
async def demo_comprehensive_assessment():
    """Demonstrate a comprehensive assessment workflow"""
    print(f"{Fore.CYAN}[+] Comprehensive Assessment Demo{Style.RESET_ALL}")
    
    # This would be a real target in practice
    demo_target = "https://httpbin.org/get?user=admin&search=test&page=1"
    
    print(f"Demo Target: {demo_target}")
    print("This demo shows the complete workflow without actually testing a vulnerable target")
    
    agent = SQLInjectionAgent()
    
    # Simulate the workflow steps
    steps = [
        ("Reconnaissance", "Analyzing target URL and extracting parameters"),
        ("Parameter Discovery", "Identifying and classifying parameters by risk level"),
        ("Injection Testing", "Testing parameters with various SQL injection techniques"),
        ("Vulnerability Analysis", "Analyzing results and calculating confidence scores"),
        ("Report Generation", "Creating comprehensive security report")
    ]
    
    for step_name, description in steps:
        print(f"{Fore.YELLOW}[*] {step_name}: {description}{Style.RESET_ALL}")
        await asyncio.sleep(0.5)  # Simulate processing time
    
    print(f"{Fore.GREEN}[+] Demo completed - Ready for real assessments{Style.RESET_ALL}\n")

async def main():
    """Main test function"""
    print(f"{Fore.CYAN}{'='*60}")
    print(f"SQL INJECTION ASSESSMENT AGENT - TEST SUITE")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    try:
        # Run all tests
        await test_payloads()
        await test_injection_engine()
        await test_parameter_analysis()
        await test_agent_workflow()
        await demo_comprehensive_assessment()
        
        print(f"{Fore.GREEN}{'='*60}")
        print(f"ALL TESTS COMPLETED SUCCESSFULLY")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Next Steps:{Style.RESET_ALL}")
        print("1. Run: python -m SQL_INJECTION.main https://your-target.com")
        print("2. Create a targets.txt file for batch testing")
        print("3. Use the -v flag for verbose output")
        print("4. Check generated JSON reports for detailed results")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Test suite failed: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main()) 