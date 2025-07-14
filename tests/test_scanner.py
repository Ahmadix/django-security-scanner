
"""Tests for the security scanner."""

import tempfile
import unittest
from pathlib import Path

from django_security_scanner.core.scanner import SecurityScanner


class TestSecurityScanner(unittest.TestCase):
    """Test cases for SecurityScanner."""
    
    def setUp(self):
        self.scanner = SecurityScanner()
    
    def test_scan_vulnerable_code(self):
        """Test scanning code with vulnerabilities."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
def dangerous_function():
    user_input = input("Enter command: ")
    eval(user_input)  # This should be detected
    
def safe_function():
    return "Hello World"
""")
            f.flush()
            
            vulnerabilities = self.scanner.scan_file(Path(f.name))
            
            # Should find eval vulnerability
            self.assertTrue(len(vulnerabilities) > 0)
            self.assertTrue(any(v.pattern_id == 'eval' for v in vulnerabilities))
    
    def test_scan_safe_code(self):
        """Test scanning safe code."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
def safe_function():
    return "Hello World"
    
def another_safe_function(data):
    return data.upper()
""")
            f.flush()
            
            vulnerabilities = self.scanner.scan_file(Path(f.name))
            
            # Should find no vulnerabilities
            self.assertEqual(len(vulnerabilities), 0)


if __name__ == '__main__':
    unittest.main()
