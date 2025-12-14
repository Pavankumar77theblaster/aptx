"""
Tests for APT-X Vulnerability Scanners
======================================
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from aptx.vulnerabilities.base import (
    VulnerabilityScanner,
    WebVulnerabilityScanner,
    Finding,
    ScanTarget,
    Severity,
    VulnerabilityType,
)
from aptx.core.scope import ScopeValidator, ScopeConfig
from aptx.core.database import Severity as DbSeverity


class TestFinding:
    """Test cases for Finding class."""

    def test_finding_creation(self):
        """Test Finding creation."""
        finding = Finding(
            vuln_type="sqli",
            title="SQL Injection",
            severity=DbSeverity.CRITICAL,
            url="http://example.com/login",
            parameter="username"
        )

        assert finding.vuln_type == "sqli"
        assert finding.title == "SQL Injection"
        assert finding.severity == DbSeverity.CRITICAL

    def test_finding_to_dict(self):
        """Test converting Finding to dictionary."""
        finding = Finding(
            vuln_type="xss",
            title="Cross-Site Scripting",
            severity=DbSeverity.HIGH,
            url="http://example.com/search",
            confidence=75
        )

        result = finding.to_dict()
        assert result["vuln_type"] == "xss"
        assert result["severity"] == "high"
        assert result["confidence"] == 75

    def test_finding_default_values(self):
        """Test Finding default values."""
        finding = Finding(
            vuln_type="test",
            title="Test Finding",
            severity=DbSeverity.MEDIUM,
            url="http://example.com"
        )

        assert finding.confidence == 50
        assert finding.validated is False
        assert finding.false_positive is False


class TestScanTarget:
    """Test cases for ScanTarget class."""

    def test_scan_target_creation(self):
        """Test ScanTarget creation."""
        target = ScanTarget(
            url="http://example.com/api",
            method="POST",
            parameters={"id": "1"}
        )

        assert target.url == "http://example.com/api"
        assert target.method == "POST"
        assert target.parameters["id"] == "1"

    def test_scan_target_defaults(self):
        """Test ScanTarget default values."""
        target = ScanTarget(url="http://example.com")

        assert target.method == "GET"
        assert target.parameters == {}
        assert target.headers == {}


class MockVulnerabilityScanner(VulnerabilityScanner):
    """Mock vulnerability scanner for testing."""

    vuln_type = VulnerabilityType.OTHER
    name = "mock_scanner"
    description = "Mock scanner for testing"
    severity = DbSeverity.MEDIUM

    detection_payloads = ["test1", "test2"]
    safe_payloads = ["safe1"]

    async def scan(self, target, options=None):
        return [self.create_finding(
            target=target,
            title="Test Finding",
            description="Test description",
            evidence="Test evidence",
            payload="test"
        )]

    async def validate(self, finding, options=None):
        return True, "Validated"


class TestVulnerabilityScanner:
    """Test cases for VulnerabilityScanner base class."""

    def test_scanner_initialization(self):
        """Test scanner initialization."""
        scanner = MockVulnerabilityScanner()
        assert scanner.name == "mock_scanner"
        assert scanner.safe_mode is True

    def test_scanner_with_scope(self):
        """Test scanner with scope validator."""
        config = ScopeConfig(
            allowed_domains=["example.com"],
            strict_mode=True
        )
        scope = ScopeValidator(config=config)
        scanner = MockVulnerabilityScanner(scope=scope)

        target = ScanTarget(url="http://example.com/api")
        assert scanner.validate_target(target) is True

        target = ScanTarget(url="http://other.com/api")
        assert scanner.validate_target(target) is False

    def test_get_payloads_safe_mode(self):
        """Test getting payloads in safe mode."""
        scanner = MockVulnerabilityScanner(safe_mode=True)
        payloads = scanner.get_payloads()
        assert payloads == ["safe1"]

    def test_get_payloads_full_mode(self):
        """Test getting payloads in full mode."""
        scanner = MockVulnerabilityScanner(safe_mode=False)
        payloads = scanner.get_payloads()
        assert payloads == ["test1", "test2"]

    def test_calculate_confidence(self):
        """Test confidence calculation."""
        scanner = MockVulnerabilityScanner()

        # No indicators
        assert scanner.calculate_confidence([]) == 0

        # Single indicator
        confidence = scanner.calculate_confidence(["error_based"])
        assert confidence > 0

        # Multiple indicators
        confidence = scanner.calculate_confidence(["error_based", "boolean_based"])
        assert confidence > scanner.calculate_confidence(["error_based"])

    def test_create_finding(self):
        """Test finding creation."""
        scanner = MockVulnerabilityScanner()
        target = ScanTarget(url="http://example.com/api")

        finding = scanner.create_finding(
            target=target,
            title="Test Finding",
            description="Description",
            evidence="Evidence",
            payload="payload",
            confidence=80
        )

        assert finding.title == "Test Finding"
        assert finding.confidence == 80
        assert finding.url == "http://example.com/api"

    @pytest.mark.asyncio
    async def test_scan(self):
        """Test scanner execution."""
        scanner = MockVulnerabilityScanner()
        target = ScanTarget(url="http://example.com")

        findings = await scanner.scan(target)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_validate(self):
        """Test finding validation."""
        scanner = MockVulnerabilityScanner()
        finding = Finding(
            vuln_type="test",
            title="Test",
            severity=DbSeverity.MEDIUM,
            url="http://example.com"
        )

        is_valid, note = await scanner.validate(finding)
        assert is_valid is True


class TestSQLiScanner:
    """Test cases for SQL injection scanner."""

    def test_sqli_scanner_init(self):
        """Test SQLi scanner initialization."""
        from aptx.vulnerabilities.sqli import SQLiScanner

        scanner = SQLiScanner()
        assert scanner.name == "sqli"
        assert scanner.vuln_type == VulnerabilityType.SQLI

    def test_sqli_error_patterns(self):
        """Test SQLi error pattern detection."""
        from aptx.vulnerabilities.sqli import SQLiScanner

        scanner = SQLiScanner()

        # MySQL error
        result = scanner._check_error_based("You have an error in your SQL syntax")
        assert result == "error_based"

        # PostgreSQL error
        result = scanner._check_error_based("PostgreSQL ERROR: syntax error")
        assert result == "error_based"

        # No error
        result = scanner._check_error_based("Normal page content")
        assert result is None

    def test_sqli_boolean_based(self):
        """Test SQLi boolean-based detection."""
        from aptx.vulnerabilities.sqli import SQLiScanner

        scanner = SQLiScanner()

        baseline = {"body": "a" * 1000}
        true_response = {"body": "a" * 1000}  # Similar
        false_response = {"body": "b" * 500}  # Different

        # True condition should return similar content
        result = scanner._check_boolean_based(baseline, true_response, "' OR '1'='1")
        assert result is False  # Similar content, inconclusive

        # False condition with different content indicates vulnerability
        result = scanner._check_boolean_based(baseline, false_response, "' OR '1'='2")
        assert result is True

    def test_sqli_safe_payloads(self):
        """Test SQLi safe payloads."""
        from aptx.vulnerabilities.sqli import SQLiScanner

        scanner = SQLiScanner(safe_mode=True)
        payloads = scanner.get_payloads()

        # Should use safe payloads
        assert "'" in payloads
        assert len(payloads) < len(scanner.detection_payloads)


class TestXSSScanner:
    """Test cases for XSS scanner."""

    def test_xss_scanner_init(self):
        """Test XSS scanner initialization."""
        from aptx.vulnerabilities.xss import XSSScanner

        scanner = XSSScanner()
        assert scanner.name == "xss"
        assert scanner.vuln_type == VulnerabilityType.XSS


class TestIDORScanner:
    """Test cases for IDOR scanner."""

    def test_idor_scanner_init(self):
        """Test IDOR scanner initialization."""
        from aptx.vulnerabilities.idor import IDORScanner

        scanner = IDORScanner()
        assert scanner.name == "idor"
        assert scanner.vuln_type == VulnerabilityType.IDOR


class TestSSRFScanner:
    """Test cases for SSRF scanner."""

    def test_ssrf_scanner_init(self):
        """Test SSRF scanner initialization."""
        from aptx.vulnerabilities.ssrf import SSRFScanner

        scanner = SSRFScanner()
        assert scanner.name == "ssrf"
        assert scanner.vuln_type == VulnerabilityType.SSRF


class TestOpenRedirectScanner:
    """Test cases for Open Redirect scanner."""

    def test_open_redirect_scanner_init(self):
        """Test Open Redirect scanner initialization."""
        from aptx.vulnerabilities.open_redirect import OpenRedirectScanner

        scanner = OpenRedirectScanner()
        assert scanner.name == "open_redirect"
        assert scanner.vuln_type == VulnerabilityType.OPEN_REDIRECT


class TestCommandInjectionScanner:
    """Test cases for Command Injection scanner."""

    def test_command_injection_scanner_init(self):
        """Test Command Injection scanner initialization."""
        from aptx.vulnerabilities.command_injection import CommandInjectionScanner

        scanner = CommandInjectionScanner()
        assert scanner.name == "command_injection"
        assert scanner.vuln_type == VulnerabilityType.COMMAND_INJECTION
