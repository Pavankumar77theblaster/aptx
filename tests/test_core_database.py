"""
Tests for APT-X Database Module
===============================
"""

import pytest
from datetime import datetime

from aptx.core.database import (
    Database,
    Scan,
    Finding,
    Scope,
    Intelligence,
    ScanStatus,
    Severity,
    VulnerabilityType,
    get_database,
    reset_database,
)


class TestDatabase:
    """Test cases for Database class."""

    def test_database_initialization(self, temp_dir):
        """Test database initialization."""
        db_path = temp_dir / "test_init.db"
        db = Database(engine="sqlite", sqlite_path=str(db_path))
        assert db.engine_type == "sqlite"
        db.create_tables()

    def test_database_create_tables(self, clean_database):
        """Test table creation."""
        # Tables should already be created by fixture
        # Just verify we can query them
        with clean_database.session() as session:
            scans = session.query(Scan).all()
            assert isinstance(scans, list)


class TestScanOperations:
    """Test cases for Scan CRUD operations."""

    def test_create_scan(self, clean_database):
        """Test creating a scan."""
        scan = clean_database.create_scan(
            target="example.com",
            name="Test Scan",
            safe_mode=True
        )
        assert scan["target"] == "example.com"
        assert scan["status"] == ScanStatus.PENDING.value

    def test_get_scan(self, clean_database):
        """Test getting a scan by ID."""
        scan = clean_database.create_scan(target="example.com")
        result = clean_database.get_scan(scan["id"])
        assert result is not None
        assert result["target"] == "example.com"

    def test_get_scan_not_found(self, clean_database):
        """Test getting non-existent scan."""
        result = clean_database.get_scan("nonexistent-id")
        assert result is None

    def test_update_scan(self, clean_database):
        """Test updating a scan."""
        scan = clean_database.create_scan(target="example.com")
        result = clean_database.update_scan(
            scan["id"],
            status=ScanStatus.RUNNING.value
        )
        assert result["status"] == ScanStatus.RUNNING.value

    def test_list_scans(self, clean_database):
        """Test listing scans."""
        clean_database.create_scan(target="example1.com")
        clean_database.create_scan(target="example2.com")

        scans = clean_database.list_scans()
        assert len(scans) == 2

    def test_list_scans_with_filter(self, clean_database):
        """Test listing scans with status filter."""
        clean_database.create_scan(target="example1.com")
        scan2 = clean_database.create_scan(target="example2.com")
        clean_database.update_scan(scan2["id"], status=ScanStatus.COMPLETED.value)

        scans = clean_database.list_scans(status=ScanStatus.COMPLETED.value)
        assert len(scans) == 1
        assert scans[0]["target"] == "example2.com"


class TestFindingOperations:
    """Test cases for Finding CRUD operations."""

    def test_add_finding(self, clean_database, sample_finding):
        """Test adding a finding."""
        scan = clean_database.create_scan(target="example.com")

        finding = clean_database.add_finding(
            scan_id=scan["id"],
            **sample_finding
        )

        assert finding["vuln_type"] == "sqli"
        assert finding["severity"] == "critical"

    def test_add_finding_updates_counts(self, clean_database, sample_finding):
        """Test that adding finding updates scan counts."""
        scan = clean_database.create_scan(target="example.com")

        clean_database.add_finding(scan_id=scan["id"], **sample_finding)

        updated_scan = clean_database.get_scan(scan["id"])
        assert updated_scan["total_findings"] == 1
        assert updated_scan["critical_count"] == 1

    def test_get_findings(self, clean_database, sample_finding):
        """Test getting findings for a scan."""
        scan = clean_database.create_scan(target="example.com")
        clean_database.add_finding(scan_id=scan["id"], **sample_finding)

        findings = clean_database.get_findings(scan["id"])
        assert len(findings) == 1
        assert findings[0]["title"] == sample_finding["title"]

    def test_get_findings_with_filters(self, clean_database, sample_finding):
        """Test getting findings with filters."""
        scan = clean_database.create_scan(target="example.com")

        # Add critical finding
        clean_database.add_finding(scan_id=scan["id"], **sample_finding)

        # Add low finding
        sample_finding["severity"] = "low"
        sample_finding["title"] = "Low severity issue"
        clean_database.add_finding(scan_id=scan["id"], **sample_finding)

        critical_findings = clean_database.get_findings(
            scan["id"],
            severity="critical"
        )
        assert len(critical_findings) == 1


class TestScopeOperations:
    """Test cases for Scope CRUD operations."""

    def test_create_scope(self, clean_database):
        """Test creating a scope."""
        scope = clean_database.create_scope(
            name="Test Scope",
            allowed_domains=["example.com"],
            strict_mode=True
        )
        assert scope["name"] == "Test Scope"
        assert "example.com" in scope["allowed_domains"]

    def test_get_scope(self, clean_database):
        """Test getting a scope by ID."""
        scope = clean_database.create_scope(
            name="Test Scope",
            allowed_domains=["example.com"]
        )
        result = clean_database.get_scope(scope["id"])
        assert result is not None
        assert result["name"] == "Test Scope"


class TestIntelligenceOperations:
    """Test cases for Intelligence CRUD operations."""

    def test_add_intelligence(self, clean_database):
        """Test adding intelligence data."""
        intel = clean_database.add_intelligence(
            data_type="payload",
            content="' OR '1'='1",
            category="sqli",
            source="test"
        )
        assert intel["data_type"] == "payload"
        assert intel["category"] == "sqli"

    def test_add_intelligence_deduplication(self, clean_database):
        """Test that duplicate intelligence is not added."""
        intel1 = clean_database.add_intelligence(
            data_type="payload",
            content="' OR '1'='1",
            category="sqli"
        )
        intel2 = clean_database.add_intelligence(
            data_type="payload",
            content="' OR '1'='1",
            category="sqli"
        )
        assert intel1["id"] == intel2["id"]

    def test_get_intelligence(self, clean_database):
        """Test getting intelligence data."""
        clean_database.add_intelligence(
            data_type="payload",
            content="test1",
            category="sqli"
        )
        clean_database.add_intelligence(
            data_type="payload",
            content="test2",
            category="xss"
        )

        sqli_intel = clean_database.get_intelligence(
            data_type="payload",
            category="sqli"
        )
        assert len(sqli_intel) == 1


class TestEnums:
    """Test cases for database enums."""

    def test_scan_status_values(self):
        """Test ScanStatus enum values."""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"

    def test_severity_values(self):
        """Test Severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"

    def test_vulnerability_type_values(self):
        """Test VulnerabilityType enum values."""
        assert VulnerabilityType.SQLI.value == "sqli"
        assert VulnerabilityType.XSS.value == "xss"
        assert VulnerabilityType.SSRF.value == "ssrf"
