"""
Tests for APT-X Pipeline Module
===============================
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

from aptx.core.pipeline import (
    Pipeline,
    PipelineStage,
    PipelineContext,
    StageResult,
    StageStatus,
    TargetIntakeStage,
    ScopeValidationStage,
    create_default_pipeline,
)
from aptx.core.scope import ScopeValidator, ScopeConfig


class TestPipelineContext:
    """Test cases for PipelineContext."""

    def test_context_initialization(self):
        """Test context initialization."""
        context = PipelineContext(
            scan_id="test-123",
            target="example.com",
            config={}
        )
        assert context.scan_id == "test-123"
        assert context.target == "example.com"
        assert context.safe_mode is True

    def test_add_subdomain(self):
        """Test adding subdomains."""
        context = PipelineContext(
            scan_id="test",
            target="example.com",
            config={}
        )
        context.add_subdomain("sub.example.com")
        context.add_subdomain("SUB.example.com")  # Should be lowercased

        assert "sub.example.com" in context.subdomains
        assert len(context.subdomains) == 1  # Deduplication

    def test_add_web_server(self):
        """Test adding web servers."""
        context = PipelineContext(
            scan_id="test",
            target="example.com",
            config={}
        )
        context.add_web_server("http://example.com")
        context.add_web_server("https://example.com")

        assert len(context.web_servers) == 2

    def test_add_endpoint(self):
        """Test adding endpoints."""
        context = PipelineContext(
            scan_id="test",
            target="example.com",
            config={}
        )
        context.add_endpoint("http://example.com/api/users")

        assert len(context.endpoints) == 1

    def test_add_finding(self):
        """Test adding findings."""
        context = PipelineContext(
            scan_id="test",
            target="example.com",
            config={}
        )
        context.add_finding({"type": "sqli", "severity": "high"})

        assert len(context.findings) == 1

    def test_context_to_dict(self):
        """Test converting context to dictionary."""
        context = PipelineContext(
            scan_id="test",
            target="example.com",
            config={}
        )
        context.add_subdomain("sub.example.com")

        result = context.to_dict()
        assert result["scan_id"] == "test"
        assert result["subdomains_count"] == 1


class TestStageResult:
    """Test cases for StageResult."""

    def test_stage_result_creation(self):
        """Test StageResult creation."""
        result = StageResult(
            stage_name="test_stage",
            status=StageStatus.COMPLETED,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            data={"key": "value"}
        )
        assert result.stage_name == "test_stage"
        assert result.status == StageStatus.COMPLETED


class TestTargetIntakeStage:
    """Test cases for TargetIntakeStage."""

    @pytest.mark.asyncio
    async def test_target_intake_domain(self):
        """Test target intake with domain."""
        stage = TargetIntakeStage()
        context = PipelineContext(
            scan_id="test",
            target="example.com",
            config={}
        )

        result = await stage.execute(context)

        assert result.status == StageStatus.COMPLETED
        assert "example.com" in context.subdomains

    @pytest.mark.asyncio
    async def test_target_intake_url(self):
        """Test target intake with URL."""
        stage = TargetIntakeStage()
        context = PipelineContext(
            scan_id="test",
            target="https://example.com/path",
            config={}
        )

        result = await stage.execute(context)

        assert result.status == StageStatus.COMPLETED
        assert "example.com" in context.subdomains
        assert "https://example.com/path" in context.web_servers


class TestScopeValidationStage:
    """Test cases for ScopeValidationStage."""

    @pytest.mark.asyncio
    async def test_scope_validation_pass(self):
        """Test scope validation passing."""
        stage = ScopeValidationStage()
        config = ScopeConfig(
            allowed_domains=["example.com"],
            strict_mode=True
        )
        scope = ScopeValidator(config=config)

        context = PipelineContext(
            scan_id="test",
            target="example.com",
            config={},
            scope=scope
        )
        context.add_subdomain("example.com")

        result = await stage.execute(context)
        assert result.status == StageStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_scope_validation_fail(self):
        """Test scope validation failing."""
        stage = ScopeValidationStage()
        config = ScopeConfig(
            allowed_domains=["example.com"],
            strict_mode=True
        )
        scope = ScopeValidator(config=config)

        context = PipelineContext(
            scan_id="test",
            target="other.com",
            config={},
            scope=scope
        )
        context.add_subdomain("other.com")

        result = await stage.execute(context)
        assert result.status == StageStatus.FAILED

    @pytest.mark.asyncio
    async def test_scope_validation_no_scope(self):
        """Test scope validation without scope validator."""
        stage = ScopeValidationStage()

        context = PipelineContext(
            scan_id="test",
            target="example.com",
            config={},
            scope=None
        )
        context.add_subdomain("example.com")

        result = await stage.execute(context)
        assert result.status == StageStatus.COMPLETED


class TestPipeline:
    """Test cases for Pipeline class."""

    def test_pipeline_initialization(self):
        """Test pipeline initialization."""
        pipeline = Pipeline()
        assert pipeline._stages == {}
        assert not pipeline._running

    def test_register_stage(self):
        """Test registering a stage."""
        pipeline = Pipeline()
        pipeline.register_stage(TargetIntakeStage)

        assert "target_intake" in pipeline._stages

    def test_unregister_stage(self):
        """Test unregistering a stage."""
        pipeline = Pipeline()
        pipeline.register_stage(TargetIntakeStage)
        pipeline.unregister_stage("target_intake")

        assert "target_intake" not in pipeline._stages

    def test_get_stage(self):
        """Test getting a stage instance."""
        pipeline = Pipeline()
        pipeline.register_stage(TargetIntakeStage)

        stage = pipeline.get_stage("target_intake")
        assert isinstance(stage, TargetIntakeStage)

    def test_get_available_stages(self):
        """Test getting list of available stages."""
        pipeline = Pipeline()
        pipeline.register_stage(TargetIntakeStage)
        pipeline.register_stage(ScopeValidationStage)

        stages = pipeline.get_available_stages()
        assert len(stages) == 2
        assert any(s["name"] == "target_intake" for s in stages)

    def test_create_default_pipeline(self):
        """Test creating default pipeline."""
        pipeline = create_default_pipeline()

        assert "target_intake" in pipeline._stages
        assert "scope_validation" in pipeline._stages

    def test_on_progress(self):
        """Test progress callback registration."""
        pipeline = Pipeline()
        callback = MagicMock()
        pipeline.on_progress(callback)

        assert callback in pipeline._progress_callbacks

    def test_cancel(self):
        """Test pipeline cancellation."""
        pipeline = Pipeline()
        pipeline._running = True
        pipeline.cancel()

        assert pipeline._cancelled is True
