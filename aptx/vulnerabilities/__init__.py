"""
APT-X Vulnerability Scanners
============================

Vulnerability detection modules for common web application vulnerabilities.
Each scanner implements detection logic, safe validation, and remediation guidance.
"""

from aptx.vulnerabilities.base import (
    VulnerabilityScanner,
    Finding,
    Severity,
    VulnerabilityType,
)
from aptx.vulnerabilities.sqli import SQLiScanner
from aptx.vulnerabilities.xss import XSSScanner
from aptx.vulnerabilities.idor import IDORScanner
from aptx.vulnerabilities.auth_bypass import AuthBypassScanner
from aptx.vulnerabilities.file_upload import FileUploadScanner
from aptx.vulnerabilities.command_injection import CommandInjectionScanner
from aptx.vulnerabilities.ssrf import SSRFScanner
from aptx.vulnerabilities.open_redirect import OpenRedirectScanner
from aptx.vulnerabilities.misconfig import MisconfigScanner

__all__ = [
    "VulnerabilityScanner",
    "Finding",
    "Severity",
    "VulnerabilityType",
    "SQLiScanner",
    "XSSScanner",
    "IDORScanner",
    "AuthBypassScanner",
    "FileUploadScanner",
    "CommandInjectionScanner",
    "SSRFScanner",
    "OpenRedirectScanner",
    "MisconfigScanner",
]

# Scanner registry
SCANNERS = {
    "sqli": SQLiScanner,
    "xss": XSSScanner,
    "idor": IDORScanner,
    "auth_bypass": AuthBypassScanner,
    "file_upload": FileUploadScanner,
    "command_injection": CommandInjectionScanner,
    "ssrf": SSRFScanner,
    "open_redirect": OpenRedirectScanner,
    "misconfig": MisconfigScanner,
}


def get_scanner(vuln_type: str) -> type:
    """Get scanner class by vulnerability type."""
    return SCANNERS.get(vuln_type.lower())


def get_all_scanners() -> dict:
    """Get all registered scanners."""
    return SCANNERS.copy()
