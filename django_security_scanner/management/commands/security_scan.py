
"""Django management command for security scanning."""

import json
from pathlib import Path
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings

from django_security_scanner.core.scanner import SecurityScanner
from django_security_scanner.reports.html_generator import HtmlReportGenerator
from django_security_scanner.reports.json_generator import JsonReportGenerator


class Command(BaseCommand):
    help = 'Run security scan on Django project'

    def add_arguments(self, parser):
        parser.add_argument(
            '--output',
            type=str,
            default='security_report.html',
            help='Output file path for the report'
        )
        parser.add_argument(
            '--format',
            choices=['html', 'json', 'console'],
            default='html',
            help='Report format'
        )
        parser.add_argument(
            '--config',
            type=str,
            help='Configuration file path'
        )
        parser.add_argument(
            '--severity',
            choices=['critique', 'élevé', 'moyen'],
            help='Minimum severity level to report'
        )
        parser.add_argument(
            '--exclude-apps',
            type=str,
            help='Comma-separated list of apps to exclude'
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Starting Django Security Scanner...')
        )

        # Load configuration
        config = {}
        if options['config']:
            config_path = Path(options['config'])
            if config_path.exists():
                config = json.loads(config_path.read_text())
            else:
                raise CommandError(f"Configuration file not found: {options['config']}")

        # Initialize scanner
        scanner = SecurityScanner(config)
        
        # Run scan
        self.stdout.write('Scanning project files...')
        results = scanner.scan_project()
        
        # Filter by severity if specified
        if options['severity']:
            severity_order = ['critique', 'élevé', 'moyen']
            min_severity_idx = severity_order.index(options['severity'])
            results.vulnerabilities = [
                v for v in results.vulnerabilities
                if severity_order.index(v.severity) <= min_severity_idx
            ]

        # Generate report
        output_format = options['format']
        output_path = options['output']
        
        if output_format == 'html':
            generator = HtmlReportGenerator()
            report_content = generator.generate_report(results)
            Path(output_path).write_text(report_content, encoding='utf-8')
            self.stdout.write(
                self.style.SUCCESS(f'HTML report saved to: {output_path}')
            )
        
        elif output_format == 'json':
            generator = JsonReportGenerator()
            report_content = generator.generate_report(results)
            Path(output_path).write_text(report_content, encoding='utf-8')
            self.stdout.write(
                self.style.SUCCESS(f'JSON report saved to: {output_path}')
            )
        
        elif output_format == 'console':
            self._print_console_report(results)

        # Summary
        total_vulns = len(results.vulnerabilities)
        if total_vulns == 0:
            self.stdout.write(
                self.style.SUCCESS('✅ No security issues found!')
            )
        else:
            self.stdout.write(
                self.style.WARNING(f'⚠️  Found {total_vulns} potential security issues')
            )
            self.stdout.write(f'Security score: {results.score:.1f}/100')

    def _print_console_report(self, results):
        """Print results to console."""
        self.stdout.write('\n' + '='*60)
        self.stdout.write('SECURITY SCAN RESULTS')
        self.stdout.write('='*60)
        
        for vuln in results.vulnerabilities:
            severity_style = {
                'critique': self.style.ERROR,
                'élevé': self.style.WARNING,
                'moyen': self.style.NOTICE
            }.get(vuln.severity, self.style.NOTICE)
            
            self.stdout.write(f'\n📍 {vuln.file_path}:{vuln.line_number}')
            self.stdout.write(f'   {severity_style(vuln.severity.upper())}: {vuln.description}')
            self.stdout.write(f'   Code: {vuln.code_snippet}')
        
        self.stdout.write('\n' + '='*60)
        self.stdout.write(f'Total vulnerabilities: {len(results.vulnerabilities)}')
        self.stdout.write(f'Security score: {results.score:.1f}/100')
