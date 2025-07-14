
"""HTML report generator with modern styling."""

import html
import textwrap
from datetime import datetime
from typing import Dict, Any

from django_security_scanner.core.scanner import ScanResult


class HtmlReportGenerator:
    """Generate beautiful HTML security reports."""
    
    def generate_report(self, results: ScanResult) -> str:
        """Generate complete HTML report."""
        now = datetime.now().strftime("%d %b %Y %H:%M")
        
        # Prepare data for template
        vulnerabilities_by_file = self._group_vulnerabilities_by_file(results.vulnerabilities)
        vuln_data_js = f"[{results.risk_counters.get('critique', 0)}, {results.risk_counters.get('élevé', 0)}, {results.risk_counters.get('moyen', 0)}]"
        
        # Generate sections
        summary_section = self._generate_summary_section(results)
        vulnerabilities_section = self._generate_vulnerabilities_section(vulnerabilities_by_file)
        
        # Complete HTML template
        html_content = f"""
<!DOCTYPE html>
<html lang="fr" data-bs-theme="auto">
<head>
    <meta charset="utf-8">
    <title>Django Security Scanner Report</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{ --bs-body-font-family: "Inter", "Segoe UI", sans-serif; }}
        .vulnerability-card {{ 
            border-left: 4px solid var(--bs-danger); 
            background: var(--bs-light);
        }}
        .vulnerability-card.severity-critique {{ border-left-color: #dc3545; }}
        .vulnerability-card.severity-élevé {{ border-left-color: #fd7e14; }}
        .vulnerability-card.severity-moyen {{ border-left-color: #ffc107; }}
        .code-snippet {{ 
            background: #f8f9fa; 
            border: 1px solid #dee2e6;
            border-radius: 0.375rem;
            padding: 0.75rem;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
        }}
        .severity-badge {{ font-weight: 600; }}
        .chart-container {{ max-width: 400px; margin: 0 auto; }}
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-md bg-primary navbar-dark shadow-sm sticky-top">
        <div class="container">
            <a class="navbar-brand fw-bold" href="#">🔒 Django Security Scanner</a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text">
                    Score: <span class="badge bg-light text-dark fs-6">{results.score:.1f}/100</span>
                </span>
            </div>
        </div>
    </nav>

    <main class="container py-4">
        {summary_section}
        {vulnerabilities_section}
        
        <section class="mt-5">
            <h3>📊 Répartition des vulnérabilités</h3>
            <div class="chart-container">
                <canvas id="vulnChart"></canvas>
            </div>
        </section>
    </main>

    <footer class="bg-light py-4 mt-5">
        <div class="container text-center text-muted">
            <p>Rapport généré le {now} par Django Security Scanner v1.0.0</p>
            <p><small>🔗 <a href="https://github.com/django-security-scanner/django-security-scanner" class="text-decoration-none">GitHub</a> | 
            📦 <a href="https://pypi.org/project/django-security-scanner/" class="text-decoration-none">PyPI</a></small></p>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        document.addEventListener("DOMContentLoaded", () => {{
            const ctx = document.getElementById("vulnChart");
            new Chart(ctx, {{
                type: "doughnut",
                data: {{
                    labels: ["Critique", "Élevé", "Moyen"],
                    datasets: [{{
                        data: {vuln_data_js},
                        backgroundColor: ["#dc3545", "#fd7e14", "#ffc107"],
                        borderColor: ["#dc3545", "#fd7e14", "#ffc107"],
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    plugins: {{
                        legend: {{ position: "bottom" }},
                        title: {{ 
                            display: true,
                            text: "Distribution des vulnérabilités par sévérité"
                        }}
                    }},
                    responsive: true,
                    maintainAspectRatio: true
                }}
            }});
        }});
    </script>
</body>
</html>
"""
        return textwrap.dedent(html_content).strip()
    
    def _generate_summary_section(self, results: ScanResult) -> str:
        """Generate summary section of the report."""
        total_vulns = len(results.vulnerabilities)
        score_color = "success" if results.score >= 80 else "warning" if results.score >= 60 else "danger"
        
        return f"""
        <section class="mb-5">
            <div class="row">
                <div class="col-lg-8">
                    <h1 class="display-6 fw-bold">🔒 Rapport de Sécurité Django</h1>
                    <p class="lead">Analyse complète des vulnérabilités potentielles de votre projet Django.</p>
                </div>
                <div class="col-lg-4 text-lg-end">
                    <div class="card bg-{score_color} text-white">
                        <div class="card-body text-center">
                            <h3 class="card-title">{results.score:.1f}/100</h3>
                            <p class="card-text">Score de Sécurité</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="row mt-4">
                <div class="col-md-3">
                    <div class="card border-danger">
                        <div class="card-body text-center">
                            <h4 class="text-danger">{results.risk_counters.get('critique', 0)}</h4>
                            <p class="mb-0 small">Critique</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card border-warning">
                        <div class="card-body text-center">
                            <h4 class="text-warning">{results.risk_counters.get('élevé', 0)}</h4>
                            <p class="mb-0 small">Élevé</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card border-info">
                        <div class="card-body text-center">
                            <h4 class="text-info">{results.risk_counters.get('moyen', 0)}</h4>
                            <p class="mb-0 small">Moyen</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card border-secondary">
                        <div class="card-body text-center">
                            <h4 class="text-secondary">{total_vulns}</h4>
                            <p class="mb-0 small">Total</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        """
    
    def _generate_vulnerabilities_section(self, vulnerabilities_by_file: Dict) -> str:
        """Generate vulnerabilities section of the report."""
        if not vulnerabilities_by_file:
            return """
            <section class="mt-5">
                <h3>🎉 Aucune vulnérabilité détectée</h3>
                <div class="alert alert-success">
                    <p class="mb-0">Félicitations ! Aucun problème de sécurité n'a été détecté dans votre code.</p>
                </div>
            </section>
            """
        
        files_html = []
        for file_path, vulns in vulnerabilities_by_file.items():
            file_html = f"""
            <div class="card mb-3">
                <div class="card-header">
                    <h5 class="mb-0">📄 {html.escape(file_path)}</h5>
                    <small class="text-muted">{len(vulns)} vulnérabilité(s) détectée(s)</small>
                </div>
                <div class="card-body">
            """
            
            for vuln in vulns:
                severity_color = {"critique": "danger", "élevé": "warning", "moyen": "info"}.get(vuln.severity, "secondary")
                file_html += f"""
                    <div class="vulnerability-card severity-{vuln.severity} p-3 mb-3 rounded">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                            <span class="badge bg-{severity_color} severity-badge">{vuln.severity.upper()}</span>
                            <small class="text-muted">Ligne {vuln.line_number}</small>
                        </div>
                        <p class="mb-2">{html.escape(vuln.description)}</p>
                        <div class="code-snippet">
                            <code>{html.escape(vuln.code_snippet)}</code>
                        </div>
                        <small class="text-muted mt-1 d-block">Pattern: {vuln.pattern_id}</small>
                    </div>
                """
            
            file_html += """
                </div>
            </div>
            """
            files_html.append(file_html)
        
        return f"""
        <section class="mt-5">
            <h3>🚨 Vulnérabilités Détectées</h3>
            {''.join(files_html)}
        </section>
        """
    
    def _group_vulnerabilities_by_file(self, vulnerabilities):
        """Group vulnerabilities by file path."""
        grouped = {}
        for vuln in vulnerabilities:
            if vuln.file_path not in grouped:
                grouped[vuln.file_path] = []
            grouped[vuln.file_path].append(vuln)
        return grouped
