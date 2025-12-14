"""
APT-X Authentication Bypass Scanner
===================================

Detection of authentication and authorization bypass vulnerabilities.
"""

from typing import Dict, List, Optional, Tuple

from aptx.vulnerabilities.base import (
    WebVulnerabilityScanner,
    Finding,
    ScanTarget,
    Severity,
    VulnerabilityType,
)


class AuthBypassScanner(WebVulnerabilityScanner):
    """Authentication and Authorization Bypass scanner."""

    vuln_type = VulnerabilityType.AUTH_BYPASS
    name = "auth_bypass"
    description = "Authentication and Authorization bypass detection"
    severity = Severity.CRITICAL

    # Common admin/protected paths
    PROTECTED_PATHS = [
        "/admin", "/admin/", "/administrator",
        "/manage", "/management", "/dashboard",
        "/api/admin", "/api/v1/admin",
        "/config", "/settings",
        "/users", "/api/users",
    ]

    # Bypass techniques
    BYPASS_HEADERS = [
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Forwarded-Host", "localhost"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Remote-IP", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
    ]

    BYPASS_PATHS = [
        "/%2e/admin",
        "/admin/.",
        "//admin",
        "/./admin",
        "/admin..;/",
        "/admin;/",
        "/admin/~",
        "/ADMIN",
        "/Admin",
    ]

    async def scan(
        self,
        target: ScanTarget,
        options: Optional[Dict] = None
    ) -> List[Finding]:
        """Scan for authentication bypass vulnerabilities."""
        findings = []
        options = options or {}

        if not self.validate_target(target):
            return findings

        self.logger.info(f"Scanning for auth bypass: {target.url}")

        # Test protected paths
        base_url = target.url.rstrip("/")

        for path in self.PROTECTED_PATHS[:5]:  # Limit paths in safe mode
            test_url = base_url + path
            test_target = ScanTarget(url=test_url, method="GET")

            # Normal request (should be blocked/redirected)
            baseline = await self._request(test_target)
            if not baseline:
                continue

            baseline_status = baseline.get("status_code", 0)

            # Skip if already accessible (200 OK)
            if baseline_status == 200:
                continue

            # Test bypass techniques
            bypass_findings = await self._test_bypasses(test_target, baseline_status, path)
            findings.extend(bypass_findings)

        # Test method override
        method_findings = await self._test_method_override(target)
        findings.extend(method_findings)

        return findings

    async def _test_bypasses(
        self,
        target: ScanTarget,
        baseline_status: int,
        path: str
    ) -> List[Finding]:
        """Test various bypass techniques."""
        findings = []

        # Test header-based bypasses
        for header_name, header_value in self.BYPASS_HEADERS[:3]:
            test_target = ScanTarget(
                url=target.url,
                method="GET",
                headers={header_name: header_value}
            )

            response = await self._request(test_target)
            if response and response.get("status_code") == 200:
                if baseline_status in [401, 403, 302]:
                    finding = self.create_finding(
                        target=target,
                        title=f"Authentication Bypass via {header_name} header",
                        description=(
                            f"Protected path '{path}' can be accessed by adding the "
                            f"{header_name} header. This may indicate a misconfigured "
                            "reverse proxy or web server."
                        ),
                        evidence=f"Header: {header_name}: {header_value}",
                        payload=f"{header_name}: {header_value}",
                        confidence=70,
                    )
                    findings.append(finding)

        return findings

    async def _test_method_override(self, target: ScanTarget) -> List[Finding]:
        """Test HTTP method override vulnerabilities."""
        findings = []

        # Test X-HTTP-Method-Override
        for method in ["GET", "HEAD"]:
            test_target = ScanTarget(
                url=target.url,
                method="POST",
                headers={"X-HTTP-Method-Override": method}
            )

            response = await self._request(test_target)
            if response:
                # Check if method was overridden
                pass  # Would need more context to determine

        return findings

    async def validate(
        self,
        finding: Finding,
        options: Optional[Dict] = None
    ) -> Tuple[bool, str]:
        """Validate authentication bypass."""
        return False, "Auth bypass requires manual verification"

    def get_remediation(self, finding: Optional[Finding] = None) -> str:
        return """
**Authentication Bypass Remediation:**

1. **Implement proper access controls at application level**
   - Don't rely solely on URL-based restrictions
   - Verify authentication in application code

2. **Configure reverse proxies correctly**
   - Don't trust X-Forwarded-* headers blindly
   - Validate header sources

3. **Use consistent URL handling**
   - Normalize paths before authorization checks
   - Handle URL encoding consistently

4. **Implement defense in depth**
   - Multiple layers of authorization checks
   - Log and alert on bypass attempts
"""
