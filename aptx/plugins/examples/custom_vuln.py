"""
Example Custom Vulnerability Scanner Plugin
============================================

This is an example plugin demonstrating how to create
custom vulnerability scanners for APT-X.
"""

from typing import Dict, List, Optional, Tuple

from aptx.plugins.sdk import VulnerabilityPlugin, PluginMetadata
from aptx.vulnerabilities.base import Finding, ScanTarget, Severity, VulnerabilityType


class CustomHeaderScanner(VulnerabilityPlugin):
    """
    Example: Custom security header analyzer.

    This plugin checks for custom/proprietary security headers
    that may be specific to your organization.
    """

    metadata = PluginMetadata(
        name="custom_header_scanner",
        version="1.0.0",
        author="APT-X Example",
        description="Scans for custom security headers",
        category="vulnerability"
    )

    vuln_type = VulnerabilityType.MISCONFIG
    name = "custom_headers"
    description = "Custom security header verification"
    severity = Severity.LOW

    # Custom headers to check
    REQUIRED_HEADERS = [
        "X-Custom-Security",
        "X-Request-ID",
    ]

    async def scan(
        self,
        target: ScanTarget,
        options: Optional[Dict] = None
    ) -> List[Finding]:
        """Scan for missing custom headers."""
        findings = []

        response = await self._request(target)
        if not response:
            return findings

        headers = response.get("headers", {})
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for required_header in self.REQUIRED_HEADERS:
            if required_header.lower() not in headers_lower:
                finding = self.create_finding(
                    target=target,
                    title=f"Missing {required_header} header",
                    description=f"The custom security header {required_header} is not present.",
                    evidence=f"Header not found in response",
                    confidence=80,
                )
                findings.append(finding)

        return findings

    async def validate(
        self,
        finding: Finding,
        options: Optional[Dict] = None
    ) -> Tuple[bool, str]:
        """Validate finding."""
        # Re-check the header
        target = ScanTarget(url=finding.url)
        response = await self._request(target)

        if response:
            headers = response.get("headers", {})
            header_name = finding.title.replace("Missing ", "").replace(" header", "")
            if header_name.lower() not in {k.lower() for k in headers}:
                return True, "Header confirmed missing"

        return False, "Could not validate"

    def get_remediation(self, finding: Optional[Finding] = None) -> str:
        return """
**Custom Header Remediation:**

Add the required custom security headers to your web server configuration:

Apache:
```
Header always set X-Custom-Security "enabled"
Header always set X-Request-ID "%{UNIQUE_ID}e"
```

Nginx:
```
add_header X-Custom-Security "enabled" always;
add_header X-Request-ID $request_id always;
```
"""


# This makes the plugin discoverable
Plugin = CustomHeaderScanner
