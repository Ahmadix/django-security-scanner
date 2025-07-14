
"""Command line interface for django-security-scanner."""

import argparse
import json
import sys
from pathlib import Path

from django_security_scanner.core.scanner import SecurityScanner
from django_security_scanner.reports.html_generator import HtmlReportGenerator
from django_security_scanner.reports.json_generator import JsonReportGenerator


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Django Security Scanner - Professional security audit tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  django-security-scan --settings=myproject.settings
  django-security-scan --output=report.html --format=html
  django-security-scan --config=config.json --severity=critique
        """
    )
    
    parser.add_argument(
        "--settings", "-s",
        required=True,
        help="Django settings module (e.g., myproject.settings)"
    )
    parser.add_argument(
        "--output", "-o",
        default="security_report.html",
        help="Output file path (default: security_report.html)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["html", "json"],
        default="html",
        help="Report format (default: html)"
    )
    parser.add_argument(
        "--config", "-c",
        help="Configuration file path"
    )
    parser.add_argument(
        "--severity",
        choices=["critique", "élevé", "moyen"],
        help="Minimum severity level to report"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="django-security-scanner 1.0.0"
    )
    
    args = parser.parse_args()
    
    # Setup Django environment
    import os
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', args.settings)
    
    try:
        import django
        django.setup()
    except Exception as e:
        print(f"Error setting up Django: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Load configuration
    config = {}
    if args.config:
        config_path = Path(args.config)
        if config_path.exists():
            config = json.loads(config_path.read_text())
        else:
            print(f"Configuration file not found: {args.config}", file=sys.stderr)
            sys.exit(1)
    
    # Run security scan
    print("🔒 Starting Django Security Scanner...")
    scanner = SecurityScanner(config)
    results = scanner.scan_project()
    
    # Filter by severity if specified
    if args.severity:
        severity_order = ['critique', 'élevé', 'moyen']
        min_severity_idx = severity_order.index(args.severity)
        results.vulnerabilities = [
            v for v in results.vulnerabilities
            if severity_order.index(v.severity) <= min_severity_idx
        ]
    
    # Generate report
    output_path = Path(args.output)
    
    if args.format == "html":
        generator = HtmlReportGenerator()
        report_content = generator.generate_report(results)
        output_path.write_text(report_content, encoding="utf-8")
        print(f"✅ HTML report saved to: {output_path}")
    
    elif args.format == "json":
        generator = JsonReportGenerator()
        report_content = generator.generate_report(results)
        output_path.write_text(report_content, encoding="utf-8")
        print(f"✅ JSON report saved to: {output_path}")
    
    # Summary
    total_vulns = len(results.vulnerabilities)
    if total_vulns == 0:
        print("🎉 No security issues found!")
    else:
        print(f"⚠️  Found {total_vulns} potential security issues")
        print(f"🔢 Security score: {results.score:.1f}/100")
    
    return 0 if total_vulns == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
