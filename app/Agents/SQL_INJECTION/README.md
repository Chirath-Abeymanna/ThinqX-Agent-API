# SQL Injection Assessment Agent

A comprehensive AI agent for detecting SQL injection vulnerabilities using LangGraph and advanced testing techniques.

## Features

- **Multi-Technique Testing**: Supports Boolean-based, Time-based, Error-based, Union-based, Stacked Queries, and Out-of-Band SQL injection
- **Intelligent Payload Selection**: Automatically selects relevant payloads based on parameter analysis
- **Comprehensive Detection**: Uses pattern matching, response analysis, and timing detection
- **Risk Assessment**: Provides confidence scores and risk levels for detected vulnerabilities
- **Detailed Reporting**: Generates comprehensive JSON reports with technical details
- **Batch Processing**: Support for testing multiple targets from a file
- **Real-time Analysis**: Live feedback during assessment process

## Installation

1. Ensure you have Python 3.8+ installed
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Single Target Assessment

```bash
# Basic assessment
python -m SQL_INJECTION.main https://example.com/vulnerable.php?id=1

# Verbose output with detailed results
python -m SQL_INJECTION.main https://example.com/vulnerable.php?id=1 -v
```

### Batch Assessment

Create a file `targets.txt` with one URL per line:

```
https://example1.com/vulnerable.php?id=1
https://example2.com/search.php?q=test
https://example3.com/login.php
```

Then run:

```bash
python -m SQL_INJECTION.main -f targets.txt
```

### Programmatic Usage

```python
import asyncio
from SQL_INJECTION.agent import SQLInjectionAgent

async def main():
    agent = SQLInjectionAgent()
    result = await agent.run_assessment("https://example.com/vulnerable.php?id=1")
    
    if result['success']:
        print(f"Confidence Score: {result['report']['confidence_score']}")
        print(f"Vulnerable Parameters: {result['report']['vulnerable_parameters']}")

asyncio.run(main())
```

## Assessment Phases

The agent performs assessment in the following phases:

1. **Reconnaissance**: Analyzes target URL, extracts forms and parameters
2. **Parameter Discovery**: Identifies and classifies parameters by risk level
3. **Injection Testing**: Tests each parameter with various SQL injection techniques
4. **Vulnerability Analysis**: Analyzes results and calculates confidence scores
5. **Report Generation**: Creates comprehensive security report

## Supported Injection Techniques

### Boolean-Based Injection
- Authentication bypass attempts
- Data extraction through boolean logic
- Parameter manipulation

### Time-Based Injection
- Delayed response detection
- Database enumeration through timing
- Conditional time delays

### Error-Based Injection
- Database error extraction
- Version information gathering
- Schema enumeration

### Union-Based Injection
- Data extraction through UNION queries
- Column enumeration
- Database content retrieval

### Stacked Queries
- Multiple query execution
- Database modification attempts
- Privilege escalation tests

### Out-of-Band Injection
- DNS exfiltration attempts
- HTTP request-based data extraction

## Output and Reports

The agent generates detailed JSON reports containing:

- Assessment summary with risk levels
- Vulnerable parameters identified
- Successful injection details
- Technical recommendations
- Confidence scores and metrics

Example report structure:

```json
{
  "target_url": "https://example.com/vulnerable.php?id=1",
  "assessment_summary": {
    "total_parameters_tested": 3,
    "vulnerable_parameters": 1,
    "total_injection_tests": 45,
    "successful_injections": 2,
    "confidence_score": 0.85,
    "risk_level": "HIGH"
  },
  "vulnerable_parameters": ["id"],
  "successful_injections": [
    {
      "parameter": "id",
      "payload": "' OR 1=1--",
      "type": "boolean_based",
      "confidence": 0.9,
      "extracted_data": null,
      "error_message": "MySQL database detected"
    }
  ],
  "recommendations": [
    "CRITICAL: SQL injection vulnerabilities detected!",
    "Use parameterized queries or prepared statements",
    "Implement input validation and sanitization"
  ]
}
```

## Security Considerations

⚠️ **IMPORTANT**: This tool is for authorized security testing only. Always ensure you have proper authorization before testing any target.

- Only test targets you own or have explicit permission to test
- Respect rate limits and avoid overwhelming target servers
- Follow responsible disclosure practices
- Comply with applicable laws and regulations

## Configuration

The agent can be customized through various parameters:

- **Timeout settings**: Adjust request timeouts
- **Delay thresholds**: Configure time-based injection detection
- **Payload selection**: Modify payload databases
- **Risk scoring**: Adjust confidence calculation algorithms

## Dependencies

- `langgraph`: Workflow orchestration
- `aiohttp`: Asynchronous HTTP requests
- `beautifulsoup4`: HTML parsing
- `colorama`: Colored terminal output
- `pydantic`: Data validation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is for educational and authorized security testing purposes only.

## Disclaimer

This tool is provided as-is for educational purposes. Users are responsible for ensuring they have proper authorization before testing any targets. The authors are not responsible for any misuse of this tool. 