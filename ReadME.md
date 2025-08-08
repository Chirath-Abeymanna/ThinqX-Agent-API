# ThinqX Web Crawler API

Advanced vulnerability scanning and web reconnaissance tool built with FastAPI.

## Features

- **Intelligent Web Crawling**: OWASP ZAP-like capabilities for comprehensive web scanning
- **Vulnerability Detection**: Automated discovery of sensitive files, configuration issues, and security weaknesses
- **Async Processing**: Long-running scans with status tracking and real-time progress updates
- **Comprehensive Reporting**: Detailed JSON reports with categorized findings and risk assessment
- **Technology Fingerprinting**: Automatic detection of web technologies, frameworks, and services
- **Security Analysis**: Analysis of security headers, cookies, forms, and potential attack vectors

## Quick Start

### 1. Install Dependencies

```bash
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install packages
pip install -r requirements.txt
```

### 2. Start the Server

```bash
# Option 1: Using the startup script
python start_server.py

# Option 2: Using uvicorn directly
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Access API Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

## API Endpoints

### Synchronous Crawl

```http
POST /api/v1/crawler/scan
Content-Type: application/json

{
    "domain": "example.com",
    "max_threads": 10,
    "max_depth": 3
}
```

### Asynchronous Crawl

```http
POST /api/v1/crawler/scan/async
Content-Type: application/json

{
    "domain": "example.com",
    "max_threads": 10,
    "max_depth": 3
}
```

### Check Status

```http
GET /api/v1/crawler/status/{task_id}
```

### Get Results

```http
GET /api/v1/crawler/results/{task_id}
```

## Usage Examples

### Python Example

```python
import requests
import time

# Start a crawl
response = requests.post("http://localhost:8000/api/v1/crawler/scan", json={
    "domain": "example.com",
    "max_threads": 10,
    "max_depth": 3
})

if response.status_code == 200:
    results = response.json()
    print(f"Crawl completed successfully!")
    print(f"URLs discovered: {results['crawl_summary']['urls_discovered']}")
    print(f"High-priority findings: {len(results['detailed_results'])}")

    # Print vulnerable endpoints
    for finding in results['detailed_results']:
        print(f"[{finding['sensitivity_level']}] {finding['url']} - {finding['category']}")
```

### cURL Example

```bash
# Start synchronous crawl
curl -X POST "http://localhost:8000/api/v1/crawler/scan" \
     -H "Content-Type: application/json" \
     -d '{"domain": "example.com", "max_threads": 10, "max_depth": 3}'

# Start asynchronous crawl
curl -X POST "http://localhost:8000/api/v1/crawler/scan/async" \
     -H "Content-Type: application/json" \
     -d '{"domain": "example.com", "max_threads": 5, "max_depth": 2}'
```

## Response Format

The API returns comprehensive vulnerability reports in JSON format:

```json
{
    "success": true,
    "message": "Crawl completed successfully",
    "crawl_summary": {
        "target_domain": "example.com",
        "urls_discovered": 150,
        "urls_successfully_crawled": 145,
        "crawl_duration": 67.4,
        "errors_encountered": 5
    },
    "discovery_statistics": {
        "total_files_found": 23,
        "total_forms_found": 8,
        "sensitive_files_found": 3,
        "hidden_files_discovered": 12
    },
    "categorized_findings": {
        "Admin/Management": {
            "count": 2,
            "sensitivity_breakdown": {"high": 2},
            "urls": [...]
        },
        "Configuration": {
            "count": 1,
            "sensitivity_breakdown": {"critical": 1},
            "urls": [...]
        }
    },
    "detailed_results": [
        {
            "url": "https://example.com/.env",
            "category": "Configuration",
            "sensitivity_level": "critical",
            "status_code": 200,
            "content_type": "text/plain",
            "title": "",
            "forms": [],
            "technologies": [],
            "security_headers": {},
            "cookies": []
        }
    ],
    "technology_fingerprints": {
        "Apache": 15,
        "PHP": 8,
        "WordPress": 3
    },
    "security_analysis": {
        "security_headers_coverage": {
            "X-Frame-Options": 12,
            "X-XSS-Protection": 8
        },
        "forms_discovered": 8,
        "cookies_found": 15
    }
}
```

## Configuration

The application can be configured using environment variables:

```bash
# .env file
APP_NAME="ThinqX Web Crawler API"
DEBUG=false
HOST=0.0.0.0
PORT=8000
DEFAULT_MAX_THREADS=10
DEFAULT_MAX_DEPTH=3
MAX_CRAWL_TIMEOUT=300
```

## Testing

Run the test suite to verify everything is working:

```bash
# Make sure the server is running on localhost:8000
python test_api.py
```

## Security Considerations

- The crawler respects robots.txt files
- Rate limiting is implemented to prevent overwhelming target servers
- Only publicly accessible content is crawled
- No authentication bypass or injection attacks are performed
- Use responsibly and only on domains you own or have permission to test

## Project Structure

```
app/
├── main.py                 # FastAPI application entry point
├── core/
│   └── config.py          # Application configuration
├── models/
│   └── crawl_models.py    # Pydantic models for API
├── services/
│   ├── web_crawler_agent.py    # Original crawler implementation
│   └── crawler_service.py      # FastAPI service wrapper
└── api/
    └── v1/
        ├── api.py              # API router configuration
        └── endpoints/
            └── web_crawler.py  # Crawler endpoints
```

## License

This project is licensed under the MIT License.
