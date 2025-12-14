"""
APT-X Integration Tests
=======================

End-to-end integration tests for the APT-X framework.
"""

import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from aptx.core.config import Config, get_config, reset_config
from aptx.core.database import Database, get_database, reset_database
from aptx.core.scope import ScopeValidator, ScopeConfig
from aptx.core.pipeline import Pipeline, PipelineContext, create_default_pipeline
from aptx.core.rate_limiter import RateLimiter, RateLimitConfig
from aptx.vulnerabilities.base import ScanTarget


class TestConfigToDatabase:
    """Test configuration to database integration."""

    def test_config_database_path(self, temp_dir, clean_config):
        """Test database path from configuration."""
        # Create config with custom database path
        config_content = f"""
general:
  data_dir: {temp_dir}/data
  log_dir: {temp_dir}/logs

database:
  engine: sqlite
  sqlite:
    path: {temp_dir}/test.db

safety:
  require_authorization: true
  safe_mode: true

logging:
  level: INFO
"""
        config_path = temp_dir / "config.yaml"
        config_path.write_text(config_content)

        config = Config(
            config_path=config_path,
            load_defaults=False,
            load_local=False
        )

        # Verify database engine from config
        assert config.get("database.engine") == "sqlite"


class TestScopeToPipeline:
    """Test scope validation in pipeline."""

    def test_scope_in_pipeline_context(self):
        """Test scope validator in pipeline context."""
        scope_config = ScopeConfig(
            name="Test Scope",
            allowed_domains=["example.com", "*.example.com"],
            strict_mode=True
        )
        scope = ScopeValidator(config=scope_config)

        context = PipelineContext(
            scan_id="test-123",
            target="example.com",
            config={},
            scope=scope,
            safe_mode=True
        )

        # Verify scope is accessible
        assert context.scope is not None
        valid, reason = context.scope.validate("sub.example.com")
        assert valid is True


class TestRateLimiterIntegration:
    """Test rate limiter integration."""

    @pytest.mark.asyncio
    async def test_rate_limiter_in_context(self):
        """Test rate limiter in pipeline context."""
        rate_config = RateLimitConfig(
            requests_per_second=10,
            burst_size=5
        )
        rate_limiter = RateLimiter(config=rate_config)

        context = PipelineContext(
            scan_id="test-123",
            target="example.com",
            config={},
            rate_limiter=rate_limiter
        )

        # Verify rate limiter works
        assert context.rate_limiter is not None
        await context.rate_limiter.acquire_async()  # Should not block


class TestDatabaseToReporting:
    """Test database to reporting integration."""

    def test_findings_storage_and_retrieval(self, clean_database, sample_finding):
        """Test storing and retrieving findings."""
        # Create scan
        scan = clean_database.create_scan(target="example.com")

        # Add findings
        for i in range(3):
            finding = sample_finding.copy()
            finding["title"] = f"Finding {i}"
            clean_database.add_finding(scan_id=scan["id"], **finding)

        # Retrieve findings
        findings = clean_database.get_findings(scan["id"])
        assert len(findings) == 3

        # Verify scan counts updated
        updated_scan = clean_database.get_scan(scan["id"])
        assert updated_scan["total_findings"] == 3


class TestFullPipelineFlow:
    """Test full pipeline execution flow."""

    @pytest.mark.asyncio
    async def test_pipeline_basic_flow(self, temp_dir, clean_database):
        """Test basic pipeline execution."""
        # Create pipeline
        pipeline = create_default_pipeline()

        # Create scope
        scope_config = ScopeConfig(
            allowed_domains=["example.com"],
            strict_mode=True
        )
        pipeline.scope = ScopeValidator(config=scope_config)

        # Run only initial stages
        context = await pipeline.run(
            target="example.com",
            stages=["target_intake", "scope_validation"],
            safe_mode=True,
            scan_name="Integration Test"
        )

        # Verify context populated
        assert context.scan_id is not None
        assert "example.com" in context.subdomains

    @pytest.mark.asyncio
    async def test_pipeline_with_callback(self, temp_dir, clean_database):
        """Test pipeline with progress callback."""
        pipeline = create_default_pipeline()

        progress_updates = []

        def progress_callback(stage, status, progress, message):
            progress_updates.append({
                "stage": stage,
                "status": status,
                "progress": progress
            })

        pipeline.on_progress(progress_callback)

        # Create minimal scope
        scope_config = ScopeConfig(
            allowed_domains=["example.com"],
            strict_mode=True
        )
        pipeline.scope = ScopeValidator(config=scope_config)

        await pipeline.run(
            target="example.com",
            stages=["target_intake", "scope_validation"],
            safe_mode=True
        )

        # Verify callbacks were called
        assert len(progress_updates) > 0


class TestIntelligenceFlow:
    """Test intelligence data flow."""

    def test_intelligence_storage_effectiveness(self, clean_database):
        """Test intelligence storage and effectiveness tracking."""
        # Add intelligence
        intel = clean_database.add_intelligence(
            data_type="payload",
            content="' OR '1'='1",
            category="sqli",
            source="test"
        )

        # Update effectiveness
        clean_database.update_intelligence_effectiveness(intel["id"], success=True)
        clean_database.update_intelligence_effectiveness(intel["id"], success=True)
        clean_database.update_intelligence_effectiveness(intel["id"], success=False)

        # Retrieve and verify
        intel_list = clean_database.get_intelligence(data_type="payload")
        assert len(intel_list) >= 1


class TestVulnerabilityScannerIntegration:
    """Test vulnerability scanner integration."""

    @pytest.mark.asyncio
    async def test_scanner_with_scope(self):
        """Test vulnerability scanner with scope validation."""
        from aptx.vulnerabilities.sqli import SQLiScanner

        scope_config = ScopeConfig(
            allowed_domains=["example.com"],
            strict_mode=True
        )
        scope = ScopeValidator(config=scope_config)

        scanner = SQLiScanner(scope=scope, safe_mode=True)

        # In-scope target
        target = ScanTarget(
            url="http://example.com/login",
            parameters={"username": "test"}
        )
        assert scanner.validate_target(target) is True

        # Out-of-scope target
        target = ScanTarget(
            url="http://other.com/login",
            parameters={"username": "test"}
        )
        assert scanner.validate_target(target) is False


class TestReportGeneration:
    """Test report generation integration."""

    def test_report_with_findings(self, temp_dir, clean_database, sample_finding):
        """Test report generation with findings."""
        from aptx.reporting.generator import ReportGenerator

        # Create scan and add findings
        scan = clean_database.create_scan(target="example.com")
        clean_database.add_finding(scan_id=scan["id"], **sample_finding)

        findings = clean_database.get_findings(scan["id"])

        # Generate report
        generator = ReportGenerator()
        scan_data = clean_database.get_scan(scan["id"])

        report_path = generator.generate(
            scan=scan_data,
            findings=findings,
            format="html",
            output_path=str(temp_dir / "report.html")
        )

        assert Path(report_path).exists()
        content = Path(report_path).read_text()
        assert "example.com" in content


class TestCLIIntegration:
    """Test CLI integration."""

    def test_cli_import(self):
        """Test CLI module imports successfully."""
        from aptx.cli import main, scan, init, scans, report
        assert main is not None
        assert scan is not None

    def test_cli_version(self):
        """Test version is accessible."""
        from aptx import __version__
        assert __version__ is not None
        assert isinstance(__version__, str)


class TestPluginSystem:
    """Test plugin system integration."""

    def test_plugin_sdk_import(self):
        """Test plugin SDK imports."""
        from aptx.plugins.sdk import (
            PluginBase,
            VulnerabilityPlugin,
            ReconPlugin,
            PluginMetadata
        )
        assert PluginBase is not None
        assert VulnerabilityPlugin is not None

    def test_plugin_loader_import(self):
        """Test plugin loader imports."""
        from aptx.plugins.loader import PluginLoader
        assert PluginLoader is not None


class TestWebUIIntegration:
    """Test Web UI integration."""

    def test_fastapi_app_creation(self):
        """Test FastAPI app can be created."""
        from aptx.ui.app import create_app

        app = create_app()
        assert app is not None

    def test_app_routes(self):
        """Test app has expected routes."""
        from aptx.ui.app import create_app

        app = create_app()
        routes = [r.path for r in app.routes]

        # Check for expected routes
        assert "/" in routes or any("/" in str(r) for r in routes)


class TestEndToEndScenarios:
    """End-to-end scenario tests."""

    @pytest.mark.asyncio
    async def test_minimal_scan_scenario(self, temp_dir, clean_database):
        """Test minimal scan scenario."""
        # Setup
        pipeline = create_default_pipeline()

        scope_config = ScopeConfig(
            allowed_domains=["test.example.com"],
            strict_mode=True
        )
        pipeline.scope = ScopeValidator(config=scope_config)
        pipeline.rate_limiter = RateLimiter()

        # Execute
        context = await pipeline.run(
            target="test.example.com",
            stages=["target_intake", "scope_validation"],
            safe_mode=True
        )

        # Verify
        assert context.scan_id is not None
        assert len(context.subdomains) >= 1

        # Check database
        scan = clean_database.get_scan(context.scan_id)
        assert scan is not None
        assert scan["target"] == "test.example.com"

    def test_intelligence_ingestion_scenario(self, temp_dir, clean_database):
        """Test intelligence data ingestion scenario."""
        from aptx.data_feeds.ingestor import DataIngestor

        # Create test payload file
        payload_file = temp_dir / "sqli_payloads.txt"
        payload_file.write_text("' OR '1'='1\n\" OR \"1\"=\"1\n' AND '1'='1")

        # Ingest
        ingestor = DataIngestor()
        result = ingestor.ingest(str(payload_file))

        assert result.success is True
        assert result.items_parsed >= 1

    def test_scope_file_loading_scenario(self, sample_scope_file):
        """Test loading scope from file scenario."""
        scope = ScopeValidator(config_file=sample_scope_file)

        # Verify scope loaded correctly
        assert scope.config.name == "Test Scope"

        # Test validations
        valid, _ = scope.validate("example.com")
        assert valid is True

        valid, _ = scope.validate("admin.example.com")
        assert valid is False  # Blocked

        valid, _ = scope.validate("random.com")
        assert valid is False  # Not in allowlist
