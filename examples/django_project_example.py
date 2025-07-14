
"""
Example of how to integrate django-security-scanner into a Django project.
"""

# In your Django settings.py
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Add django-security-scanner
    'django_security_scanner',
    
    # Your apps
    'myapp',
]

# Security settings recommended by the scanner
DEBUG = False
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

# Usage examples:

# 1. As Django management command
# python manage.py security_scan --output=security_report.html

# 2. Programmatic usage
from django_security_scanner.core.scanner import SecurityScanner

def run_security_audit():
    scanner = SecurityScanner()
    results = scanner.scan_project()
    
    print(f"Security Score: {results.score}/100")
    print(f"Vulnerabilities found: {len(results.vulnerabilities)}")
    
    for vuln in results.vulnerabilities:
        print(f"  - {vuln.severity}: {vuln.description}")
        print(f"    File: {vuln.file_path}:{vuln.line_number}")

# 3. Custom configuration
config = {
    "severity_threshold": "élevé",
    "exclude_patterns": ["*/tests/*"]
}
scanner = SecurityScanner(config)
results = scanner.scan_project()
