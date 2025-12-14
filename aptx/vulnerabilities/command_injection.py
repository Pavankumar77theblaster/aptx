"""
APT-X Command Injection Scanner
===============================

Command injection vulnerability detection with safe mode.
"""

import re
from typing import Dict, List, Optional, Tuple

from aptx.vulnerabilities.base import (
    WebVulnerabilityScanner, Finding, ScanTarget, Severity, VulnerabilityType,
)


class CommandInjectionScanner(WebVulnerabilityScanner):
    """Command Injection vulnerability scanner."""

    vuln_type = VulnerabilityType.COMMAND_INJECTION
    name = "command_injection"
    description = "Command injection detection"
    severity = Severity.CRITICAL

    # Safe detection payloads (don't execute anything harmful)
    SAFE_PAYLOADS = [
        "; echo aptx_test",
        "| echo aptx_test",
        "& echo aptx_test",
        "`echo aptx_test`",
        "$(echo aptx_test)",
        "|| echo aptx_test",
        "&& echo aptx_test",
    ]

    # Patterns indicating command execution
    ERROR_PATTERNS = [
        r"sh: \d+: .+: not found",
        r"command not found",
        r"/bin/sh:",
        r"syntax error",
        r"unexpected token",
    ]

    async def scan(self, target: ScanTarget, options: Optional[Dict] = None) -> List[Finding]:
        """Scan for command injection."""
        findings = []
        if not self.validate_target(target):
            return findings

        self.logger.info(f"Scanning for command injection: {target.url}")

        for param in target.parameters:
            baseline = await self._request(target)
            if not baseline:
                continue

            for payload in self.SAFE_PAYLOADS:
                response = await self._request(target, payload, param)
                if not response:
                    continue

                # Check for injection indicators
                if self._check_injection(baseline, response, payload):
                    finding = self.create_finding(
                        target=target,
                        title=f"Potential Command Injection in '{param}'",
                        description="Command injection indicators detected.",
                        evidence="Response suggests command execution",
                        payload=payload,
                        confidence=60,
                        parameter=param,
                    )
                    findings.append(finding)
                    break

        return findings

    def _check_injection(self, baseline: Dict, response: Dict, payload: str) -> bool:
        """Check for command injection indicators."""
        body = response.get("body", "")

        # Check for our marker
        if "aptx_test" in body:
            return True

        # Check for error patterns
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.I):
                return True

        # Check for timing differences (basic time-based)
        baseline_time = baseline.get("elapsed", 0)
        response_time = response.get("elapsed", 0)
        if response_time > baseline_time + 2:  # 2 second difference
            return True

        return False

    async def validate(self, finding: Finding, options: Optional[Dict] = None) -> Tuple[bool, str]:
        return False, "Command injection requires careful manual validation"

    def get_remediation(self, finding: Optional[Finding] = None) -> str:
        return """
**Command Injection Remediation:**
1. Avoid system calls with user input
2. Use parameterized APIs instead of shell commands
3. Validate and sanitize all input
4. Use allowlist validation
5. Run with minimal privileges
6. Use sandboxing/containerization
"""
