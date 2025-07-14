
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-XX

### Added
- Initial release of Django Security Scanner
- AST-based vulnerability detection for 100+ security patterns
- HTML and JSON report generation
- Django management command integration
- CLI tool for standalone usage
- Settings validation against security best practices
- Dependencies analysis and vulnerability tracking
- Interactive HTML reports with charts
- Configurable scanning rules and severity levels
- Support for Django 3.2 to 5.0
- Support for Python 3.8 to 3.12

### Security Patterns Detected
- Code execution vulnerabilities (eval, exec, compile)
- SQL injection risks (raw queries, cursor.execute)
- XSS vulnerabilities (mark_safe, template issues)
- CSRF bypass (@csrf_exempt)
- Authentication and session issues
- Unsafe deserialization (pickle, yaml)
- SSRF vulnerabilities
- Path traversal risks
- Information disclosure
- Hardcoded credentials
- Weak cryptography usage
- Django-specific security issues

## [Unreleased]

### Planned
- Integration with CI/CD pipelines
- Custom rule definitions
- Database of known vulnerable packages
- IDE plugins (VS Code, PyCharm)
- Additional report formats (PDF, SARIF)
- Performance optimizations for large codebases
