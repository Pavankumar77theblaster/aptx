"""
APT-X IDOR Scanner
==================

Insecure Direct Object Reference (IDOR) detection.
"""

import re
from typing import Dict, List, Optional, Tuple

from aptx.vulnerabilities.base import (
    WebVulnerabilityScanner,
    Finding,
    ScanTarget,
    Severity,
    VulnerabilityType,
)


class IDORScanner(WebVulnerabilityScanner):
    """IDOR vulnerability scanner."""

    vuln_type = VulnerabilityType.IDOR
    name = "idor"
    description = "Insecure Direct Object Reference detection"
    severity = Severity.HIGH

    # Patterns indicating object references
    ID_PATTERNS = [
        r'id=\d+',
        r'user_id=\d+',
        r'account=\d+',
        r'profile=\d+',
        r'doc=\d+',
        r'file=\d+',
        r'order=\d+',
        r'/users/\d+',
        r'/api/v\d+/\w+/\d+',
        r'uuid=[a-f0-9-]+',
    ]

    async def scan(
        self,
        target: ScanTarget,
        options: Optional[Dict] = None
    ) -> List[Finding]:
        """Scan for IDOR vulnerabilities."""
        findings = []
        options = options or {}

        if not self.validate_target(target):
            return findings

        self.logger.info(f"Scanning for IDOR: {target.url}")

        # Identify numeric/ID parameters
        id_params = self._find_id_parameters(target)

        for param, original_value in id_params:
            # Test with modified values
            test_values = self._generate_test_values(original_value)

            baseline = await self._request(target)
            if not baseline:
                continue

            for test_value in test_values:
                response = await self._request(target, test_value, param)
                if not response:
                    continue

                # Check for IDOR indicators
                if self._check_idor_indicators(baseline, response, original_value, test_value):
                    confidence = self._calculate_idor_confidence(baseline, response)

                    finding = self.create_finding(
                        target=target,
                        title=f"Potential IDOR in '{param}' parameter",
                        description=(
                            "The application may be vulnerable to Insecure Direct Object Reference. "
                            "Changing the object identifier returned different data, suggesting "
                            "inadequate authorization checks."
                        ),
                        evidence=f"Modified {param} from {original_value} to {test_value}",
                        payload=test_value,
                        confidence=confidence,
                        parameter=param,
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"
                        ]
                    )
                    findings.append(finding)
                    break

        return findings

    def _find_id_parameters(self, target: ScanTarget) -> List[Tuple[str, str]]:
        """Find parameters that look like object IDs."""
        id_params = []

        for param, value in target.parameters.items():
            # Check if value looks like an ID
            if re.match(r'^\d+$', value):
                id_params.append((param, value))
            elif re.match(r'^[a-f0-9-]{36}$', value.lower()):  # UUID
                id_params.append((param, value))
            elif param.lower() in ['id', 'user_id', 'uid', 'account_id', 'file_id', 'doc_id']:
                id_params.append((param, value))

        return id_params

    def _generate_test_values(self, original: str) -> List[str]:
        """Generate test values for IDOR testing."""
        test_values = []

        if original.isdigit():
            num = int(original)
            test_values.extend([
                str(num + 1),
                str(num - 1),
                str(num + 100),
                "1",
                "0",
            ])
        else:
            # For UUIDs or other formats, just modify slightly
            test_values.append(original[:-1] + "0")

        return test_values

    def _check_idor_indicators(
        self,
        baseline: Dict,
        response: Dict,
        original: str,
        test_value: str
    ) -> bool:
        """Check if response indicates potential IDOR."""
        # Successful response (200 OK)
        if response.get("status_code") == 200:
            # Check if content differs (different object returned)
            baseline_len = len(baseline.get("body", ""))
            response_len = len(response.get("body", ""))

            # Content should differ but still be successful
            if abs(baseline_len - response_len) > 50:
                return True

            # Or same structure with different data
            if baseline.get("body") != response.get("body"):
                return True

        return False

    def _calculate_idor_confidence(self, baseline: Dict, response: Dict) -> int:
        """Calculate confidence score for IDOR finding."""
        confidence = 30  # Base confidence

        # Higher confidence if both are 200 OK
        if baseline.get("status_code") == 200 and response.get("status_code") == 200:
            confidence += 20

        # Higher if content differs significantly
        baseline_len = len(baseline.get("body", ""))
        response_len = len(response.get("body", ""))
        if abs(baseline_len - response_len) > 100:
            confidence += 15

        return min(70, confidence)  # Cap at 70 (needs manual verification)

    async def validate(
        self,
        finding: Finding,
        options: Optional[Dict] = None
    ) -> Tuple[bool, str]:
        """IDOR requires manual validation with authenticated contexts."""
        return False, "IDOR requires manual verification with different user sessions"

    def get_remediation(self, finding: Optional[Finding] = None) -> str:
        return """
**IDOR Remediation:**

1. **Implement proper authorization checks**
   - Verify user has permission to access requested object
   - Check ownership or role-based access

2. **Use indirect object references**
   - Map user-specific IDs to actual object IDs
   - Use session-based mappings

3. **Validate all object access requests**
   - Don't rely on obscurity (random IDs are not security)
   - Always verify authorization server-side
"""
