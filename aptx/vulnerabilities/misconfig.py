"""
APT-X Security Misconfiguration Scanner
=======================================

Detection of common security misconfigurations.
"""

import re
from typing import Dict, List, Optional, Tuple

from aptx.vulnerabilities.base import (
    WebVulnerabilityScanner, Finding, ScanTarget, Severity, VulnerabilityType,
)


class MisconfigScanner(WebVulnerabilityScanner):
    """Security Misconfiguration scanner."""

    vuln_type = VulnerabilityType.MISCONFIG
    name = "misconfig"
    description = "Security misconfiguration detection"
    severity = Severity.MEDIUM

    # Security headers to check
    SECURITY_HEADERS = {
        "Strict-Transport-Security": ("missing", Severity.MEDIUM),
        "X-Content-Type-Options": ("nosniff", Severity.LOW),
        "X-Frame-Options": ("DENY|SAMEORIGIN", Severity.MEDIUM),
        "X-XSS-Protection": ("1", Severity.LOW),
        "Content-Security-Policy": ("missing", Severity.MEDIUM),
        "Referrer-Policy": ("missing", Severity.LOW),
    }

    # Sensitive paths to check
    SENSITIVE_PATHS = [
        "/.git/HEAD", "/.env", "/wp-config.php.bak",
        "/config.php.bak", "/.htaccess", "/robots.txt",
        "/sitemap.xml", "/crossdomain.xml", "/.well-known/security.txt",
    ]

    async def scan(self, target: ScanTarget, options: Optional[Dict] = None) -> List[Finding]:
        """Scan for security misconfigurations."""
        findings = []
        if not self.validate_target(target):
            return findings

        self.logger.info(f"Scanning for misconfigurations: {target.url}")

        # Check security headers
        response = await self._request(target)
        if response:
            header_findings = self._check_security_headers(target, response)
            findings.extend(header_findings)

            # Check for information disclosure
            disclosure_findings = self._check_info_disclosure(target, response)
            findings.extend(disclosure_findings)

        # Check sensitive paths
        sensitive_findings = await self._check_sensitive_paths(target)
        findings.extend(sensitive_findings)

        return findings

    def _check_security_headers(self, target: ScanTarget, response: Dict) -> List[Finding]:
        """Check for missing or misconfigured security headers."""
        findings = []
        headers = {k.lower(): v for k, v in response.get("headers", {}).items()}

        for header, (expected, severity) in self.SECURITY_HEADERS.items():
            header_lower = header.lower()

            if expected == "missing":
                if header_lower not in headers:
                    findings.append(self.create_finding(
                        target=target,
                        title=f"Missing {header} header",
                        description=f"The {header} security header is not set.",
                        evidence=f"Header not present in response",
                        confidence=90,
                        severity=severity,
                    ))
            else:
                value = headers.get(header_lower, "")
                if not re.search(expected, value, re.I):
                    findings.append(self.create_finding(
                        target=target,
                        title=f"Weak {header} header",
                        description=f"The {header} header is set but may not be optimal.",
                        evidence=f"Current value: {value}",
                        confidence=70,
                        severity=Severity.LOW,
                    ))

        return findings

    def _check_info_disclosure(self, target: ScanTarget, response: Dict) -> List[Finding]:
        """Check for information disclosure."""
        findings = []
        headers = response.get("headers", {})
        body = response.get("body", "")

        # Server version disclosure
        server = headers.get("Server", "")
        if re.search(r"[0-9]+\.[0-9]+", server):
            findings.append(self.create_finding(
                target=target,
                title="Server version disclosure",
                description="The Server header reveals version information.",
                evidence=f"Server: {server}",
                confidence=85,
                severity=Severity.LOW,
            ))

        # X-Powered-By disclosure
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            findings.append(self.create_finding(
                target=target,
                title="X-Powered-By disclosure",
                description="The X-Powered-By header reveals technology stack.",
                evidence=f"X-Powered-By: {powered_by}",
                confidence=85,
                severity=Severity.LOW,
            ))

        # Debug mode indicators
        debug_patterns = [
            r"DEBUG\s*=\s*True",
            r"stack\s*trace",
            r"Traceback\s*\(",
            r"Exception in",
        ]
        for pattern in debug_patterns:
            if re.search(pattern, body, re.I):
                findings.append(self.create_finding(
                    target=target,
                    title="Debug mode enabled",
                    description="The application appears to be running in debug mode.",
                    evidence=f"Pattern matched: {pattern}",
                    confidence=70,
                    severity=Severity.MEDIUM,
                ))
                break

        return findings

    async def _check_sensitive_paths(self, target: ScanTarget) -> List[Finding]:
        """Check for exposed sensitive files."""
        findings = []
        base_url = target.url.rstrip("/")

        for path in self.SENSITIVE_PATHS[:5]:  # Limit
            test_target = ScanTarget(url=base_url + path)
            response = await self._request(test_target)

            if response and response.get("status_code") == 200:
                body = response.get("body", "")
                # Verify it's actual content, not error page
                if len(body) > 10 and "404" not in body.lower():
                    severity = Severity.HIGH if path in ["/.git/HEAD", "/.env"] else Severity.MEDIUM

                    findings.append(self.create_finding(
                        target=test_target,
                        title=f"Sensitive file exposed: {path}",
                        description=f"The file {path} is publicly accessible.",
                        evidence=body[:200],
                        confidence=85,
                        severity=severity,
                    ))

        return findings

    async def validate(self, finding: Finding, options: Optional[Dict] = None) -> Tuple[bool, str]:
        return True, "Misconfiguration findings are typically validated by observation"

    def get_remediation(self, finding: Optional[Finding] = None) -> str:
        return """
**Security Misconfiguration Remediation:**
1. Implement all recommended security headers
2. Disable debug mode in production
3. Remove server version banners
4. Block access to sensitive files
5. Regular security configuration audits
6. Use security configuration baselines
"""
