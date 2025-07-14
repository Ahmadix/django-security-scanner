
"""JSON report generator for programmatic access."""

import json
from datetime import datetime
from typing import Dict, Any

from django_security_scanner.core.scanner import ScanResult


class JsonReportGenerator:
    """Generate JSON security reports."""
    
    def generate_report(self, results: ScanResult) -> str:
        """Generate JSON report."""
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "scanner_version": "1.0.0",
                "total_vulnerabilities": len(results.vulnerabilities)
            },
            "summary": {
                "security_score": round(results.score, 2),
                "risk_distribution": results.risk_counters,
                "apps_scanned": results.apps_scanned
            },
            "vulnerabilities": [
                {
                    "id": idx + 1,
                    "file_path": vuln.file_path,
                    "line_number": vuln.line_number,
                    "pattern_id": vuln.pattern_id,
                    "severity": vuln.severity,
                    "description": vuln.description,
                    "code_snippet": vuln.code_snippet
                }
                for idx, vuln in enumerate(results.vulnerabilities)
            ],
            "dependencies": results.dependencies,
            "settings_issues": results.settings_issues
        }
        
        return json.dumps(report_data, indent=2, ensure_ascii=False)
