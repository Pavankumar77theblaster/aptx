"""
APT-X Report Generator
======================

Generate professional penetration testing reports.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from aptx.core.logger import get_logger
from aptx.reporting.cvss import CVSSCalculator


class ReportGenerator:
    """Generate professional penetration testing reports."""

    def __init__(self, templates_dir: Optional[Path] = None):
        self.logger = get_logger().get_child("reporting")
        self.templates_dir = templates_dir or Path(__file__).parent / "templates"
        self.cvss = CVSSCalculator()

        # Setup Jinja2
        if self.templates_dir.exists():
            self.env = Environment(
                loader=FileSystemLoader(str(self.templates_dir)),
                autoescape=select_autoescape(["html", "xml"])
            )
        else:
            self.env = None

    def generate(
        self,
        scan: Dict,
        findings: List[Dict],
        format: str = "html",
        output_path: Optional[str] = None,
        options: Optional[Dict] = None
    ) -> str:
        """
        Generate a report.

        Args:
            scan: Scan metadata
            findings: List of findings
            format: Output format (html, pdf, json)
            output_path: Output file path
            options: Report options

        Returns:
            Path to generated report
        """
        options = options or {}

        # Prepare report data
        report_data = self._prepare_report_data(scan, findings, options)

        # Generate based on format
        if format == "json":
            content = self._generate_json(report_data)
        elif format == "html":
            content = self._generate_html(report_data)
        elif format == "pdf":
            content = self._generate_pdf(report_data)
        else:
            raise ValueError(f"Unsupported format: {format}")

        # Write to file
        if not output_path:
            output_path = f"report_{scan.get('id', 'unknown')[:8]}.{format}"

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "pdf":
            output_path.write_bytes(content)
        else:
            output_path.write_text(content, encoding="utf-8")

        self.logger.info(f"Report generated: {output_path}")
        return str(output_path)

    def _prepare_report_data(
        self,
        scan: Dict,
        findings: List[Dict],
        options: Dict
    ) -> Dict[str, Any]:
        """Prepare data for report generation."""
        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "info"), 5)
        )

        # Calculate statistics
        stats = self._calculate_statistics(findings)

        # Generate executive summary
        exec_summary = self._generate_executive_summary(scan, stats)

        return {
            "title": f"Penetration Test Report - {scan.get('target', 'Unknown')}",
            "generated_at": datetime.utcnow().isoformat(),
            "generator": "APT-X Framework v1.0.0",
            "scan": scan,
            "findings": sorted_findings,
            "statistics": stats,
            "executive_summary": exec_summary,
            "methodology": self._get_methodology(),
            "options": options,
        }

    def _calculate_statistics(self, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate finding statistics."""
        stats = {
            "total": len(findings),
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "by_type": {},
            "validated": 0,
            "false_positives": 0,
        }

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in stats["by_severity"]:
                stats["by_severity"][severity] += 1

            vuln_type = finding.get("vuln_type", "other")
            stats["by_type"][vuln_type] = stats["by_type"].get(vuln_type, 0) + 1

            if finding.get("validated"):
                stats["validated"] += 1
            if finding.get("false_positive"):
                stats["false_positives"] += 1

        # Calculate risk score
        stats["risk_score"] = (
            stats["by_severity"]["critical"] * 10 +
            stats["by_severity"]["high"] * 7 +
            stats["by_severity"]["medium"] * 4 +
            stats["by_severity"]["low"] * 1
        )

        return stats

    def _generate_executive_summary(self, scan: Dict, stats: Dict) -> str:
        """Generate executive summary text."""
        risk_level = "Low"
        if stats["risk_score"] > 50:
            risk_level = "Critical"
        elif stats["risk_score"] > 30:
            risk_level = "High"
        elif stats["risk_score"] > 10:
            risk_level = "Medium"

        return f"""
A penetration test was conducted against {scan.get('target', 'the target')}
to identify security vulnerabilities. The assessment identified {stats['total']}
findings, including {stats['by_severity']['critical']} critical and
{stats['by_severity']['high']} high severity issues.

Overall Risk Level: {risk_level}

The most significant findings require immediate attention to prevent potential
exploitation by malicious actors.
"""

    def _generate_json(self, data: Dict) -> str:
        """Generate JSON report."""
        return json.dumps(data, indent=2, default=str)

    def _generate_html(self, data: Dict) -> str:
        """Generate HTML report."""
        # Use built-in template if Jinja2 templates not available
        return self._generate_html_inline(data)

    def _generate_html_inline(self, data: Dict) -> str:
        """Generate HTML report with inline template."""
        findings_html = ""
        for i, finding in enumerate(data["findings"], 1):
            severity = finding.get("severity", "info")
            severity_color = {
                "critical": "#dc3545",
                "high": "#fd7e14",
                "medium": "#ffc107",
                "low": "#17a2b8",
                "info": "#6c757d",
            }.get(severity.lower(), "#6c757d")

            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {severity_color}; padding: 15px; margin: 15px 0; background: #f8f9fa;">
                <h4>{i}. {finding.get('title', 'Unknown')}</h4>
                <p><strong>Severity:</strong> <span style="color: {severity_color};">{severity.upper()}</span></p>
                <p><strong>Type:</strong> {finding.get('vuln_type', 'N/A')}</p>
                <p><strong>URL:</strong> {finding.get('url', 'N/A')}</p>
                <p><strong>Confidence:</strong> {finding.get('confidence', 0)}%</p>
                <p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>
                {f"<p><strong>Evidence:</strong> <code>{finding.get('evidence', '')[:500]}</code></p>" if finding.get('evidence') else ""}
                {f"<p><strong>Remediation:</strong> {finding.get('remediation', '')}</p>" if finding.get('remediation') else ""}
            </div>
            """

        stats = data["statistics"]

        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{data['title']}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; color: #333; }}
        h1 {{ color: #2563eb; border-bottom: 2px solid #2563eb; padding-bottom: 10px; }}
        h2 {{ color: #1e40af; margin-top: 30px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
        .stat-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; min-width: 120px; text-align: center; }}
        .stat-card .number {{ font-size: 2em; font-weight: bold; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #17a2b8; }}
        .finding {{ border-radius: 5px; }}
        code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #6c757d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>{data['title']}</h1>
    <p>Generated: {data['generated_at']}</p>
    <p>By: {data['generator']}</p>

    <h2>Executive Summary</h2>
    <p>{data['executive_summary']}</p>

    <h2>Statistics</h2>
    <div class="stats">
        <div class="stat-card">
            <div class="number">{stats['total']}</div>
            <div>Total Findings</div>
        </div>
        <div class="stat-card">
            <div class="number critical">{stats['by_severity']['critical']}</div>
            <div>Critical</div>
        </div>
        <div class="stat-card">
            <div class="number high">{stats['by_severity']['high']}</div>
            <div>High</div>
        </div>
        <div class="stat-card">
            <div class="number medium">{stats['by_severity']['medium']}</div>
            <div>Medium</div>
        </div>
        <div class="stat-card">
            <div class="number low">{stats['by_severity']['low']}</div>
            <div>Low</div>
        </div>
    </div>

    <h2>Findings</h2>
    {findings_html if findings_html else "<p>No findings to report.</p>"}

    <h2>Methodology</h2>
    <p>{data['methodology']}</p>

    <div class="footer">
        <p>This report was generated by APT-X Automated Penetration Testing Framework.</p>
        <p>For questions or clarification, contact your security team.</p>
    </div>
</body>
</html>
"""

    def _generate_pdf(self, data: Dict) -> bytes:
        """Generate PDF report."""
        # Generate HTML first
        html_content = self._generate_html(data)

        try:
            from weasyprint import HTML
            return HTML(string=html_content).write_pdf()
        except ImportError:
            self.logger.warning("WeasyPrint not available, returning HTML as fallback")
            return html_content.encode("utf-8")

    def _get_methodology(self) -> str:
        """Get methodology description."""
        return """
The penetration test followed industry-standard methodologies including OWASP Testing Guide
and PTES (Penetration Testing Execution Standard). The assessment included:

1. Reconnaissance - Information gathering and target enumeration
2. Scanning - Port scanning, service detection, and web discovery
3. Vulnerability Detection - Automated and manual vulnerability identification
4. Validation - Verification of findings with safe proof-of-concept testing
5. Reporting - Documentation of findings with remediation guidance

Testing was performed in safe mode to prevent disruption to production systems.
"""
