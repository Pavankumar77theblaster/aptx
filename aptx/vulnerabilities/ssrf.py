"""
APT-X SSRF Scanner
==================

Server-Side Request Forgery detection.
"""

from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from aptx.vulnerabilities.base import (
    WebVulnerabilityScanner, Finding, ScanTarget, Severity, VulnerabilityType,
)


class SSRFScanner(WebVulnerabilityScanner):
    """SSRF vulnerability scanner."""

    vuln_type = VulnerabilityType.SSRF
    name = "ssrf"
    description = "Server-Side Request Forgery detection"
    severity = Severity.HIGH

    # SSRF detection payloads
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://169.254.169.254",  # AWS metadata
        "http://metadata.google.internal",  # GCP metadata
        "file:///etc/passwd",
        "dict://127.0.0.1:22",
        "gopher://127.0.0.1:25",
    ]

    # URL-like parameters
    URL_PARAMS = ["url", "uri", "path", "dest", "redirect", "target", "rurl", "link", "src", "source", "ref"]

    async def scan(self, target: ScanTarget, options: Optional[Dict] = None) -> List[Finding]:
        """Scan for SSRF vulnerabilities."""
        findings = []
        if not self.validate_target(target):
            return findings

        self.logger.info(f"Scanning for SSRF: {target.url}")

        # Find URL-like parameters
        url_params = [p for p in target.parameters if p.lower() in self.URL_PARAMS]

        for param in url_params:
            baseline = await self._request(target)

            for payload in self.SSRF_PAYLOADS[:5]:  # Limit in safe mode
                response = await self._request(target, payload, param)
                if not response:
                    continue

                if self._check_ssrf_indicators(baseline, response, payload):
                    finding = self.create_finding(
                        target=target,
                        title=f"Potential SSRF in '{param}'",
                        description="The application may be making server-side requests based on user input.",
                        evidence="SSRF indicators detected",
                        payload=payload,
                        confidence=50,
                        parameter=param,
                    )
                    findings.append(finding)
                    break

        return findings

    def _check_ssrf_indicators(self, baseline: Dict, response: Dict, payload: str) -> bool:
        """Check for SSRF indicators."""
        body = response.get("body", "")

        # Check for internal content indicators
        internal_indicators = [
            "root:", "localhost", "127.0.0.1", "internal", "private",
            "ami-id", "instance-id",  # AWS metadata
        ]

        for indicator in internal_indicators:
            if indicator in body and indicator not in (baseline.get("body", "") or ""):
                return True

        # Different response suggests backend interaction
        if response.get("status_code") != baseline.get("status_code"):
            return True

        return False

    async def validate(self, finding: Finding, options: Optional[Dict] = None) -> Tuple[bool, str]:
        return False, "SSRF validation requires out-of-band callback server"

    def get_remediation(self, finding: Optional[Finding] = None) -> str:
        return """
**SSRF Remediation:**
1. Validate and sanitize URL inputs
2. Use allowlist for allowed domains/IPs
3. Block requests to internal networks
4. Disable unnecessary URL schemes
5. Use network segmentation
6. Don't return raw responses to users
"""
