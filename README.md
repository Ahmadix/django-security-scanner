
# Django Security Scanner

🔒 **Professional security audit tool for Django projects**

[![PyPI version](https://badge.fury.io/py/django-security-scanner.svg)](https://badge.fury.io/py/django-security-scanner)
[![Python Support](https://img.shields.io/pypi/pyversions/django-security-scanner.svg)](https://pypi.org/project/django-security-scanner/)
[![Django Support](https://img.shields.io/badge/Django-3.2%20to%205.0-092E20.svg)](https://www.djangoproject.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive security scanner for Django applications that identifies potential vulnerabilities, security misconfigurations, and code patterns that could lead to security issues.

## Features

- 🔍 **AST-based code analysis** for accurate vulnerability detection
- 🛡️ **100+ security patterns** covering OWASP Top 10 and Django-specific issues
- 📊 **Beautiful HTML reports** with interactive charts and detailed findings
- 🚀 **Django management command** integration
- 📋 **Settings validation** against security best practices
- 🔧 **Customizable rules** and severity levels
- 📦 **Dependencies analysis** with vulnerability tracking

## Quick Start

### Installation

```bash
pip install django-security-scanner
```

### Add to Django project

```python
# settings.py
INSTALLED_APPS = [
    # ... your apps
    'django_security_scanner',
]
```

### Run security scan

```bash
# As Django management command
python manage.py security_scan

# As standalone CLI tool
django-security-scan --settings=myproject.settings --output=security_report.html

# Scan with custom configuration
python manage.py security_scan --config=security_config.json --format=json
```

## Usage Examples

### Basic scan
```bash
python manage.py security_scan
```

### Advanced scan with options
```bash
python manage.py security_scan \
    --output=reports/security_audit.html \
    --format=html \
    --severity=high \
    --exclude-apps=migrations,tests
```

### Programmatic usage
```python
from django_security_scanner.scanner import SecurityScanner

scanner = SecurityScanner()
results = scanner.scan_project()
print(f"Found {len(results.vulnerabilities)} potential issues")
```

## Security Patterns Detected

- **Code Execution**: `eval()`, `exec()`, `compile()`
- **SQL Injection**: Raw SQL, cursor.execute()
- **XSS**: `mark_safe()`, template issues
- **CSRF**: `@csrf_exempt` usage
- **Authentication**: Weak password handling
- **File Operations**: Unsafe file access
- **Deserialization**: `pickle.load()`, `yaml.load()`
- **SSRF**: Unvalidated requests
- **Path Traversal**: Directory access issues
- **Information Disclosure**: Debug information leaks

## Configuration

Create a `security_config.json` file:

```json
{
    "severity_threshold": "medium",
    "exclude_patterns": ["test_*", "migrations/*"],
    "custom_rules": {
        "custom_check": {
            "pattern": "dangerous_function(",
            "severity": "high",
            "description": "Custom dangerous function detected"
        }
    },
    "output_format": "html",
    "include_dependencies": true
}
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/django-security-scanner/django-security-scanner
cd django-security-scanner
pip install -e .[dev]
python -m pytest tests/
```

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Security

If you discover a security vulnerability, please send an e-mail to security@django-scanner.org.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.
