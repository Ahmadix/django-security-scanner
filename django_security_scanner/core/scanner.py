
"""Main security scanner engine with AST analysis."""

import ast
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional
from dataclasses import dataclass

from .patterns import SECURITY_PATTERNS, SECURITY_DECORATORS, RISK_WEIGHTS


@dataclass
class Vulnerability:
    """Represents a security vulnerability finding."""
    file_path: str
    line_number: int
    pattern_id: str
    severity: str
    description: str
    code_snippet: str


@dataclass
class ScanResult:
    """Complete scan results."""
    vulnerabilities: List[Vulnerability]
    score: float
    risk_counters: Dict[str, int]
    apps_scanned: List[str]
    dependencies: Dict[str, Any]
    settings_issues: List[Dict[str, Any]]


class SecurityScanner:
    """Main security scanner class."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.patterns = SECURITY_PATTERNS
        self.security_decorators = SECURITY_DECORATORS
        self.risk_weights = RISK_WEIGHTS
    
    def scan_file(self, file_path: Path) -> List[Vulnerability]:
        """Scan a single Python file for security vulnerabilities."""
        vulnerabilities = []
        
        try:
            source_code = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = source_code.splitlines()
        except Exception:
            return vulnerabilities
        
        try:
            tree = ast.parse(source_code, str(file_path))
        except SyntaxError:
            return vulnerabilities
        
        # AST-based analysis
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node)
                if func_name:
                    vulnerability = self._check_function_call(node, func_name, file_path, lines)
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
            
            elif isinstance(node, ast.Name):
                vulnerability = self._check_name_usage(node, file_path, lines)
                if vulnerability:
                    vulnerabilities.append(vulnerability)
        
        # Text-based pattern matching for decorators and special cases
        for line_num, line in enumerate(lines, 1):
            vulnerability = self._check_line_patterns(line_num, line, file_path)
            if vulnerability:
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_function_name(self, node: ast.Call) -> Optional[str]:
        """Extract function name from AST call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            try:
                return f"{ast.unparse(node.func.value)}.{node.func.attr}"
            except Exception:
                return None
        return None
    
    def _check_function_call(self, node: ast.Call, func_name: str, file_path: Path, lines: List[str]) -> Optional[Vulnerability]:
        """Check if function call matches security patterns."""
        for pattern_id, (pattern, severity, description) in self.patterns.items():
            pattern_clean = pattern.rstrip('(')
            if func_name == pattern_clean:
                if not self._has_security_decorator(lines, node.lineno):
                    return Vulnerability(
                        file_path=str(file_path),
                        line_number=node.lineno,
                        pattern_id=pattern_id,
                        severity=severity,
                        description=description,
                        code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    )
        return None
    
    def _check_name_usage(self, node: ast.Name, file_path: Path, lines: List[str]) -> Optional[Vulnerability]:
        """Check if name usage matches security patterns."""
        for pattern_id, (pattern, severity, description) in self.patterns.items():
            if node.id == pattern:
                return Vulnerability(
                    file_path=str(file_path),
                    line_number=node.lineno,
                    pattern_id=pattern_id,
                    severity=severity,
                    description=description,
                    code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                )
        return None
    
    def _check_line_patterns(self, line_num: int, line: str, file_path: Path) -> Optional[Vulnerability]:
        """Check line-based patterns (decorators, etc.)."""
        for pattern_id, (pattern, severity, description) in self.patterns.items():
            if pattern.startswith("@") or ".AllowAny" in pattern:
                if pattern in line:
                    return Vulnerability(
                        file_path=str(file_path),
                        line_number=line_num,
                        pattern_id=pattern_id,
                        severity=severity,
                        description=description,
                        code_snippet=line.strip()
                    )
        return None
    
    def _has_security_decorator(self, lines: List[str], line_num: int, window: int = 5) -> bool:
        """Check if function has security decorators nearby."""
        start = max(0, line_num - window - 1)
        end = min(len(lines), line_num)
        
        for i in range(start, end):
            for decorator in self.security_decorators:
                if decorator in lines[i]:
                    return True
        return False
    
    def scan_project(self, project_path: Optional[Path] = None) -> ScanResult:
        """Scan entire Django project."""
        if project_path is None:
            project_path = Path.cwd()
        
        vulnerabilities = []
        apps_scanned = []
        risk_counters = {"critique": 0, "élevé": 0, "moyen": 0}
        
        # Scan Python files
        for py_file in project_path.rglob("*.py"):
            if self._should_skip_file(py_file):
                continue
            
            file_vulnerabilities = self.scan_file(py_file)
            vulnerabilities.extend(file_vulnerabilities)
            
            # Update risk counters
            for vuln in file_vulnerabilities:
                risk_counters[vuln.severity] = risk_counters.get(vuln.severity, 0) + 1
        
        # Calculate score
        total_score = 100
        for vuln in vulnerabilities:
            weight = self.risk_weights.get(vuln.severity, 0.1)
            total_score -= weight * 10
        
        score = max(0, total_score)
        
        return ScanResult(
            vulnerabilities=vulnerabilities,
            score=score,
            risk_counters=risk_counters,
            apps_scanned=apps_scanned,
            dependencies={},
            settings_issues=[]
        )
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Determine if file should be skipped during scanning."""
        skip_patterns = [
            "__pycache__",
            ".git",
            "migrations",
            "venv",
            "env",
            ".pytest_cache",
            "node_modules"
        ]
        
        path_str = str(file_path)
        return any(pattern in path_str for pattern in skip_patterns)
    
    def parse_requirements(self, req_file: Path) -> Dict[str, Optional[str]]:
        """Parse requirements.txt file."""
        requirements = {}
        if not req_file.exists():
            return requirements
        
        for line in req_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if "==" in line:
                name, version = line.split("==", 1)
                requirements[name.lower()] = version
            else:
                requirements[line.lower()] = None
        
        return requirements
    
    def get_installed_packages(self) -> Dict[str, str]:
        """Get currently installed packages."""
        packages = {}
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "freeze"],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.splitlines():
                if "==" in line:
                    name, version = line.split("==", 1)
                    packages[name.lower()] = version
        except subprocess.CalledProcessError:
            pass
        
        return packages
