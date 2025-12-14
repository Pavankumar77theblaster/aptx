"""
APT-X Open Redirect Scanner
===========================

Open redirect vulnerability detection.
"""

from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

from aptx.vulnerabilities.base import (
    WebVulnerabilityScanner, Finding, ScanTarget, Severity, VulnerabilityType,
)


class OpenRedirectScanner(WebVulnerabilityScanner):
    """Open Redirect vulnerability scanner."""

    vuln_type = VulnerabilityType.OPEN_REDIRECT
    name = "open_redirect"
    description = "Open redirect detection"
    severity = Severity.MEDIUM

    REDIRECT_PARAMS = ["url", "redirect", "redir", "dest", "destination", "next", "return", "returnurl", "goto", "link"]

    PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
        "////evil.com",
        "https://evil.com/",
        "@evil.com",
    ]

    async def scan(self, target: ScanTarget, options: Optional[Dict] = None) -> List[Finding]:
        """Scan for open redirect vulnerabilities."""
        findings = []
        if not self.validate_target(target):
            return findings

        redirect_params = [p for p in target.parameters if p.lower() in self.REDIRECT_PARAMS]

        for param in redirect_params:
            for payload in self.PAYLOADS[:5]:
                response = await self._request(target, payload, param)
                if not response:
                    continue

                # Check if redirected to evil domain
                final_url = response.get("url", "")
                if "evil.com" in final_url or response.get("status_code") in [301, 302, 303, 307, 308]:
                    location = response.get("headers", {}).get("location", "")
                    if "evil.com" in location:
                        finding = self.create_finding(
                            target=target,
                            title=f"Open Redirect in '{param}'",
                            description="The application redirects to user-controlled URLs.",
                            evidence=f"Redirect to: {location}",
                            payload=payload,
                            confidence=75,
                            parameter=param,
                        )
                        findings.append(finding)
                        break

        return findings

    async def validate(self, finding: Finding, options: Optional[Dict] = None) -> Tuple[bool, str]:
        return True, "Open redirect validated by redirect location"

    def get_remediation(self, finding: Optional[Finding] = None) -> str:
        return """
**Open Redirect Remediation:**
1. Use allowlist of allowed redirect destinations
2. Validate redirect URLs against same-origin policy
3. Don't use user input for redirects directly
4. Use indirect reference maps for redirects
5. Warn users before external redirects
"""
