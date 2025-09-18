# URL Safety Checker

A web application that analyzes URLs for potential security risks and provides safety recommendations.

## Features

- URL syntax validation
- SSL certificate verification
- Suspicious pattern detection
- Redirect chain analysis
- Domain information extraction
- Safety scoring system
- Detailed recommendations

## Installation

1. Clone the repository
2. Create a virtual environment: python -m venv venv
3. Activate the virtual environment:
   - Windows: env\Scripts\activate
   - Unix/MacOS: source venv/bin/activate
4. Install dependencies: pip install -r requirements.txt
5. Create a .env file with a SECRET_KEY variable

## Usage

1. Run the application: python url_checker_app.py
2. Open a web browser and navigate to http://127.0.0.1:5000
3. Enter a URL to check its safety

## API Usage

The application also provides a REST API endpoint for programmatic access:

`
POST /api/check
Content-Type: application/json

{
    "url": "https://example.com"
}
`

Response:

`json
{
    "url": "https://example.com",
    "is_safe": true,
    "syntax_valid": true,
    "ssl_secure": true,
    "suspicious_patterns": false,
    "redirect_count": 0,
    "domain_info": {
        "subdomain": "",
        "domain": "example",
        "suffix": "com",
        "registered_domain": "example.com"
    },
    "safety_score": 100,
    "recommendation": "This URL appears to be safe based on our checks. However, always exercise caution when sharing personal information online."
}
`

## License

MIT
