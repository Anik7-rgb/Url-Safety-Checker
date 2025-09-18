import os
import re
import socket
import ssl
import requests
import tldextract
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from dotenv import load_dotenv

# Load environment variables
load_dotenv()  # take environment variables from .env

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-for-testing')

# Form for URL submission
class URLForm(FlaskForm):
    url = StringField('Enter URL to check', validators=[DataRequired()])
    submit = SubmitField('Check URL')

# URL checking functions
def is_valid_url(url):
    """Check if URL has valid syntax"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def has_ssl_certificate(url):
    """Check if URL uses HTTPS"""
    return url.startswith('https://')

def contains_suspicious_patterns(url):
    """Check for suspicious patterns in URL"""
    suspicious_patterns = [
        r'\.(tk|ml|ga|cf|gq|top|xyz|pw)\/', # Suspicious TLDs
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', # IP addresses
        r'(paypal|apple|microsoft|google|amazon|facebook|instagram)\.\w+\.', # Brand names with suspicious domains
        r'secure|login|signin|bank|account|update|verify|password', # Suspicious keywords
        r'[a-zA-Z0-9]{25,}', # Very long strings
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False

def check_redirect_count(url, max_redirects=3):
    """Check if URL has too many redirects (common in phishing)"""
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        redirect_count = len(response.history)
        return {
            'count': redirect_count,
            'is_suspicious': redirect_count > max_redirects
        }
    except:
        return {
            'count': 0,
            'is_suspicious': False
        }

def extract_domain_info(url):
    """Extract domain information from URL"""
    extracted = tldextract.extract(url)
    return {
        'subdomain': extracted.subdomain,
        'domain': extracted.domain,
        'suffix': extracted.suffix,
        'registered_domain': f"{extracted.domain}.{extracted.suffix}"
    }

def calculate_safety_score(url):
    """Calculate overall safety score for URL"""
    # Start with a perfect score
    score = 100
    
    # Basic checks
    if not is_valid_url(url):
        score -= 50  # Invalid URL syntax is a major red flag
        return score
    
    # SSL checks
    if not has_ssl_certificate(url):
        score -= 20  # No HTTPS
    
    # Suspicious patterns
    if contains_suspicious_patterns(url):
        score -= 30  # Contains suspicious patterns
    
    # Redirect check
    redirect_info = check_redirect_count(url)
    if redirect_info['is_suspicious']:
        score -= 10 * redirect_info['count']  # Excessive redirects
    
    # Ensure score is between 0 and 100
    return max(0, min(100, score))

def get_safety_recommendation(score):
    """Get safety recommendation based on score"""
    if score >= 80:
        return "This URL appears to be safe based on our checks. However, always exercise caution when sharing personal information online."
    elif score >= 60:
        return "This URL seems legitimate but has some minor concerns. Proceed with caution and avoid sharing sensitive information."
    elif score >= 40:
        return "This URL has several suspicious characteristics. We recommend avoiding this website unless you're absolutely certain it's legitimate."
    else:
        return "This URL has multiple high-risk indicators and is likely unsafe. We strongly advise against visiting this website."

# Main function to check URL safety
def check_url_safety(url):
    """Comprehensive URL safety check"""
    if not is_valid_url(url):
        return {
            'url': url,
            'is_safe': False,
            'syntax_valid': False,
            'ssl_secure': False,
            'suspicious_patterns': True,
            'redirect_count': 0,
            'domain_info': None,
            'safety_score': 0,
            'recommendation': "Invalid URL format. This is not a properly formatted web address."
        }
    
    # Extract domain information
    domain_info = extract_domain_info(url)
    
    # Check redirects
    redirect_info = check_redirect_count(url)
    
    # Calculate safety score
    safety_score = calculate_safety_score(url)
    
    # Get recommendation
    recommendation = get_safety_recommendation(safety_score)
    
    # Determine overall safety
    is_safe = safety_score >= 60
    
    return {
        'url': url,
        'is_safe': is_safe,
        'syntax_valid': True,
        'ssl_secure': has_ssl_certificate(url),
        'suspicious_patterns': contains_suspicious_patterns(url),
        'redirect_count': redirect_info['count'],
        'domain_info': domain_info,
        'safety_score': safety_score,
        'recommendation': recommendation
    }

@app.route('/', methods=['GET', 'POST'])
def index():
    form = URLForm()
    result = None
    
    if form.validate_on_submit():
        url = form.url.data
        if not url.startswith('http'):
            url = 'http://' + url  # Add http:// if missing
        
        # Perform safety check using utility function
        result = check_url_safety(url)
    
    return render_template('index.html', form=form, result=result)

@app.route('/api/check', methods=['POST'])
def api_check():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
    
    url = data['url']
    if not url.startswith('http'):
        url = 'http://' + url  # Add http:// if missing
    
    # Perform safety check using utility function
    result = check_url_safety(url)
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
