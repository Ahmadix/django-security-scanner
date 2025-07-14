
# Contributing to Django Security Scanner

Thank you for your interest in contributing to Django Security Scanner! This document provides guidelines for contributing to the project.

## Getting Started

### Development Setup

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/django-security-scanner.git
   cd django-security-scanner
   ```

3. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e .[dev]
   ```

4. Run tests to ensure everything works:
   ```bash
   python -m pytest tests/
   ```

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists in GitHub Issues
2. If not, create a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Python/Django versions
   - Code samples if applicable

### Suggesting Enhancements

1. Check existing issues and discussions
2. Create a new issue with:
   - Clear description of the enhancement
   - Use cases and benefits
   - Possible implementation approach

### Contributing Code

1. Create a new branch for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our coding standards
3. Add tests for new functionality
4. Ensure all tests pass:
   ```bash
   python -m pytest tests/
   ```

5. Update documentation if needed
6. Commit your changes:
   ```bash
   git commit -m "Add feature: description"
   ```

7. Push to your fork and create a Pull Request

## Adding New Security Patterns

To add new security patterns:

1. Update `django_security_scanner/core/patterns.py`:
   ```python
   SECURITY_PATTERNS["new_pattern"] = (
       "pattern_to_match",
       "severity_level",  # critique, élevé, moyen
       "Description of the security issue"
   )
   ```

2. Add tests in `tests/test_patterns.py`
3. Update documentation with the new pattern

## Code Style

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Add docstrings for functions and classes
- Keep line length under 88 characters
- Use meaningful variable and function names

## Testing

- Write tests for all new functionality
- Maintain or improve test coverage
- Use descriptive test names
- Test both positive and negative cases

## Documentation

- Update README.md for user-facing changes
- Add docstrings for new functions/classes
- Update CHANGELOG.md with your changes
- Include examples for new features

## Security Considerations

Since this is a security tool:

- Be careful with test cases containing actual vulnerabilities
- Validate all inputs thoroughly
- Follow secure coding practices
- Report security issues privately to security@django-scanner.org

## Questions?

Feel free to:
- Open an issue for discussion
- Join our community discussions
- Reach out to maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
