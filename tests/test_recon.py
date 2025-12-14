"""
Tests for APT-X Recon Modules
=============================
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from aptx.recon.base import ReconModule, ReconResult, ReconType, ReconPipelineStage
from aptx.core.pipeline import PipelineContext, StageStatus
from aptx.core.scope import ScopeValidator, ScopeConfig


class TestReconResult:
    """Test cases for ReconResult."""

    def test_recon_result_creation(self):
        """Test ReconResult creation."""
        result = ReconResult(
            recon_type=ReconType.SUBDOMAIN,
            target="example.com",
            success=True,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            data={"subdomains": ["sub.example.com"]},
            items_found=1
        )

        assert result.recon_type == ReconType.SUBDOMAIN
        assert result.success is True
        assert result.items_found == 1

    def test_recon_result_to_dict(self):
        """Test converting ReconResult to dictionary."""
        started = datetime.utcnow()
        completed = datetime.utcnow()

        result = ReconResult(
            recon_type=ReconType.PORT_SCAN,
            target="example.com",
            success=True,
            started_at=started,
            completed_at=completed,
            data={}
        )

        result_dict = result.to_dict()
        assert result_dict["recon_type"] == "port_scan"
        assert result_dict["target"] == "example.com"
        assert result_dict["success"] is True


class TestReconType:
    """Test cases for ReconType enum."""

    def test_recon_type_values(self):
        """Test ReconType enum values."""
        assert ReconType.SUBDOMAIN.value == "subdomain"
        assert ReconType.PORT_SCAN.value == "port_scan"
        assert ReconType.WEB_DISCOVERY.value == "web_discovery"
        assert ReconType.PASSIVE.value == "passive"


class MockReconModule(ReconModule):
    """Mock recon module for testing."""

    recon_type = ReconType.PASSIVE
    name = "mock"
    description = "Mock module for testing"

    async def execute(self, target, options=None):
        return ReconResult(
            recon_type=self.recon_type,
            target=target,
            success=True,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            data={"test": True},
            items_found=1
        )


class TestReconModule:
    """Test cases for ReconModule base class."""

    def test_module_initialization(self):
        """Test module initialization."""
        module = MockReconModule()
        assert module.name == "mock"
        assert module.scope is None
        assert module.rate_limiter is None

    def test_validate_target_no_scope(self):
        """Test target validation without scope."""
        module = MockReconModule()
        assert module.validate_target("example.com") is True

    def test_validate_target_with_scope(self):
        """Test target validation with scope."""
        config = ScopeConfig(
            allowed_domains=["example.com"],
            strict_mode=True
        )
        scope = ScopeValidator(config=config)
        module = MockReconModule(scope=scope)

        assert module.validate_target("example.com") is True
        assert module.validate_target("other.com") is False

    def test_filter_in_scope(self):
        """Test filtering targets by scope."""
        config = ScopeConfig(
            allowed_domains=["example.com"],
            strict_mode=True
        )
        scope = ScopeValidator(config=config)
        module = MockReconModule(scope=scope)

        targets = ["example.com", "sub.example.com", "other.com"]
        filtered = module.filter_in_scope(targets)

        assert "example.com" in filtered
        assert "other.com" not in filtered

    @pytest.mark.asyncio
    async def test_execute(self):
        """Test module execution."""
        module = MockReconModule()
        result = await module.execute("example.com")

        assert result.success is True
        assert result.target == "example.com"


class MockReconStage(ReconPipelineStage):
    """Mock recon stage for testing."""

    name = "mock_stage"
    description = "Mock stage for testing"
    requires = ["target_intake"]
    produces = ["mock_data"]
    module_class = MockReconModule


class TestReconPipelineStage:
    """Test cases for ReconPipelineStage base class."""

    def test_stage_initialization(self):
        """Test stage initialization."""
        stage = MockReconStage()
        assert stage.name == "mock_stage"
        assert "target_intake" in stage.requires

    @pytest.mark.asyncio
    async def test_stage_execute(self):
        """Test stage execution."""
        stage = MockReconStage()

        context = PipelineContext(
            scan_id="test",
            target="example.com",
            config={}
        )
        context.add_subdomain("example.com")

        result = await stage.execute(context)
        assert result.status == StageStatus.COMPLETED

    def test_create_module(self):
        """Test module creation."""
        stage = MockReconStage()

        context = PipelineContext(
            scan_id="test",
            target="example.com",
            config={}
        )

        module = stage._create_module(context)
        assert isinstance(module, MockReconModule)


class TestSubdomainEnumerator:
    """Test cases for subdomain enumeration."""

    @pytest.mark.asyncio
    async def test_subdomain_enum_no_tools(self):
        """Test subdomain enumeration with no tools available."""
        from aptx.recon.subdomain import SubdomainEnumerator

        # Create module (tools will report as unavailable)
        module = SubdomainEnumerator()

        result = await module.execute("example.com")

        # Without tools, should fail or return empty
        if not module.available_tools:
            assert result.success is False or result.items_found == 0


class TestPortScanner:
    """Test cases for port scanning."""

    def test_port_scanner_init(self):
        """Test port scanner initialization."""
        from aptx.recon.port_scan import PortScanner

        scanner = PortScanner()
        assert scanner.name == "port_scan"

    def test_safe_ports_constant(self):
        """Test safe ports constant."""
        from aptx.recon.port_scan import PortScanner

        assert "80" in PortScanner.SAFE_PORTS
        assert "443" in PortScanner.SAFE_PORTS
        assert "22" in PortScanner.SAFE_PORTS


class TestWebDiscovery:
    """Test cases for web discovery."""

    def test_web_discovery_init(self):
        """Test web discovery initialization."""
        from aptx.recon.web_discovery import WebDiscovery

        discovery = WebDiscovery()
        assert discovery.name == "web_discovery"

    def test_default_ports(self):
        """Test default web ports."""
        from aptx.recon.web_discovery import WebDiscovery

        assert 80 in WebDiscovery.DEFAULT_PORTS
        assert 443 in WebDiscovery.DEFAULT_PORTS
        assert 8080 in WebDiscovery.DEFAULT_PORTS

    def test_prepare_targets(self):
        """Test target URL preparation."""
        from aptx.recon.web_discovery import WebDiscovery

        discovery = WebDiscovery()

        # With protocol already present
        targets = discovery._prepare_targets("http://example.com", {})
        assert targets == ["http://example.com"]

        # Without protocol
        targets = discovery._prepare_targets("example.com", {"ports": [80, 443]})
        assert any("http://example.com" in t for t in targets)
        assert any("https://example.com" in t for t in targets)
