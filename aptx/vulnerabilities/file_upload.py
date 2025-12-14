"""
APT-X File Upload Scanner
=========================

File upload vulnerability detection.
"""

from typing import Dict, List, Optional, Tuple

from aptx.vulnerabilities.base import (
    WebVulnerabilityScanner, Finding, ScanTarget, Severity, VulnerabilityType,
)


class FileUploadScanner(WebVulnerabilityScanner):
    """File Upload vulnerability scanner."""

    vuln_type = VulnerabilityType.FILE_UPLOAD
    name = "file_upload"
    description = "File upload vulnerability detection"
    severity = Severity.HIGH

    DANGEROUS_EXTENSIONS = [".php", ".jsp", ".asp", ".aspx", ".exe", ".sh", ".py"]
    BYPASS_EXTENSIONS = [".php.jpg", ".php%00.jpg", ".pHp", ".php5", ".phtml"]

    async def scan(self, target: ScanTarget, options: Optional[Dict] = None) -> List[Finding]:
        """Scan for file upload vulnerabilities."""
        findings = []
        # In safe mode, only detect upload forms without actual uploading
        response = await self._request(target)
        if response and self._detect_upload_form(response.get("body", "")):
            finding = self.create_finding(
                target=target,
                title="File upload form detected",
                description="A file upload form was detected. Manual testing recommended.",
                evidence="<input type='file'> found",
                confidence=30,
                severity=Severity.INFO,
            )
            findings.append(finding)
        return findings

    def _detect_upload_form(self, body: str) -> bool:
        """Detect file upload forms."""
        return 'type="file"' in body.lower() or "type='file'" in body.lower()

    async def validate(self, finding: Finding, options: Optional[Dict] = None) -> Tuple[bool, str]:
        return False, "File upload requires manual testing"

    def get_remediation(self, finding: Optional[Finding] = None) -> str:
        return """
**File Upload Remediation:**
1. Validate file types server-side (not just extension)
2. Use allowlist for permitted file types
3. Store uploads outside webroot
4. Rename uploaded files
5. Set proper Content-Type headers
6. Scan uploads for malware
"""
