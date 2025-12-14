"""
APT-X Pipeline Engine
=====================

Orchestrates the automated penetration testing pipeline with
configurable stages, parallel execution, and progress tracking.
"""

import asyncio
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Type
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

from aptx.core.config import get_config
from aptx.core.database import get_database, ScanStatus
from aptx.core.logger import get_logger, AuditAction
from aptx.core.scope import ScopeValidator
from aptx.core.rate_limiter import RateLimiter
from aptx.core.exceptions import ScanError, ScopeViolationError


class StageStatus(str, Enum):
    """Pipeline stage status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class StageResult:
    """Result from a pipeline stage execution."""
    stage_name: str
    status: StageStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    findings_count: int = 0
    artifacts: List[str] = field(default_factory=list)


@dataclass
class PipelineContext:
    """Shared context passed through pipeline stages."""
    scan_id: str
    target: str
    config: Dict[str, Any]
    scope: Optional[ScopeValidator] = None
    rate_limiter: Optional[RateLimiter] = None
    safe_mode: bool = True

    # Accumulated data from stages
    subdomains: Set[str] = field(default_factory=set)
    open_ports: Dict[str, List[int]] = field(default_factory=dict)
    web_servers: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    parameters: Dict[str, List[Dict]] = field(default_factory=dict)
    findings: List[Dict] = field(default_factory=list)

    # Metadata
    started_at: Optional[datetime] = None
    stage_results: Dict[str, StageResult] = field(default_factory=dict)

    def add_subdomain(self, subdomain: str) -> None:
        """Add a discovered subdomain."""
        self.subdomains.add(subdomain.lower().strip())

    def add_web_server(self, url: str) -> None:
        """Add a discovered web server."""
        self.web_servers.add(url)

    def add_endpoint(self, endpoint: str) -> None:
        """Add a discovered endpoint."""
        self.endpoints.add(endpoint)

    def add_finding(self, finding: Dict) -> None:
        """Add a vulnerability finding."""
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "safe_mode": self.safe_mode,
            "subdomains_count": len(self.subdomains),
            "web_servers_count": len(self.web_servers),
            "endpoints_count": len(self.endpoints),
            "findings_count": len(self.findings),
            "stages_completed": sum(
                1 for r in self.stage_results.values()
                if r.status == StageStatus.COMPLETED
            ),
        }


class PipelineStage(ABC):
    """
    Abstract base class for pipeline stages.

    Each stage represents a step in the penetration testing workflow.
    """

    name: str = "base"
    description: str = "Base pipeline stage"
    requires: List[str] = []  # Stages this stage depends on
    produces: List[str] = []  # Data types this stage produces

    def __init__(self):
        self.logger = get_logger().get_child(f"stage.{self.name}")

    @abstractmethod
    async def execute(self, context: PipelineContext) -> StageResult:
        """
        Execute the pipeline stage.

        Args:
            context: Shared pipeline context

        Returns:
            StageResult with execution details
        """
        pass

    def validate_prerequisites(self, context: PipelineContext) -> bool:
        """
        Validate that prerequisites are met.

        Args:
            context: Pipeline context

        Returns:
            True if prerequisites are satisfied
        """
        for req in self.requires:
            if req not in context.stage_results:
                return False
            if context.stage_results[req].status != StageStatus.COMPLETED:
                return False
        return True

    def should_skip(self, context: PipelineContext) -> bool:
        """
        Determine if this stage should be skipped.

        Args:
            context: Pipeline context

        Returns:
            True if stage should be skipped
        """
        return False


class Pipeline:
    """
    Main pipeline orchestrator for APT-X.

    Manages stage execution, dependency resolution, and progress tracking.
    """

    # Default stage order
    DEFAULT_STAGES = [
        "target_intake",
        "scope_validation",
        "subdomain_enum",
        "port_scan",
        "web_discovery",
        "crawling",
        "parameter_discovery",
        "vulnerability_scan",
        "validation",
        "reporting",
    ]

    def __init__(
        self,
        config: Optional[Dict] = None,
        scope: Optional[ScopeValidator] = None,
        rate_limiter: Optional[RateLimiter] = None
    ):
        """
        Initialize pipeline.

        Args:
            config: Pipeline configuration
            scope: Scope validator
            rate_limiter: Rate limiter
        """
        self.config = config or get_config().get_section("automation")
        self.scope = scope
        self.rate_limiter = rate_limiter or RateLimiter()
        self.logger = get_logger().get_child("pipeline")
        self.db = get_database()

        # Registered stages
        self._stages: Dict[str, Type[PipelineStage]] = {}
        self._stage_order: List[str] = []

        # Execution state
        self._running = False
        self._cancelled = False
        self._current_stage: Optional[str] = None

        # Progress callbacks
        self._progress_callbacks: List[Callable] = []

        # Thread pool for blocking operations
        self._executor = ThreadPoolExecutor(max_workers=4)

    def register_stage(
        self,
        stage_class: Type[PipelineStage],
        position: Optional[int] = None
    ) -> None:
        """
        Register a pipeline stage.

        Args:
            stage_class: Stage class to register
            position: Optional position in execution order
        """
        name = stage_class.name
        self._stages[name] = stage_class

        if name not in self._stage_order:
            if position is not None:
                self._stage_order.insert(position, name)
            else:
                self._stage_order.append(name)

        self.logger.debug(f"Registered stage: {name}")

    def unregister_stage(self, name: str) -> None:
        """Unregister a pipeline stage."""
        if name in self._stages:
            del self._stages[name]
        if name in self._stage_order:
            self._stage_order.remove(name)

    def get_stage(self, name: str) -> Optional[PipelineStage]:
        """Get an instantiated stage by name."""
        if name in self._stages:
            return self._stages[name]()
        return None

    def _resolve_dependencies(
        self,
        stages: List[str]
    ) -> List[str]:
        """
        Resolve stage dependencies and return execution order.

        Args:
            stages: List of stage names to execute

        Returns:
            Ordered list of stages including dependencies
        """
        resolved: List[str] = []
        seen: Set[str] = set()

        def resolve(stage_name: str):
            if stage_name in seen:
                return
            seen.add(stage_name)

            stage_class = self._stages.get(stage_name)
            if stage_class:
                for req in stage_class.requires:
                    if req in self._stages:
                        resolve(req)

            if stage_name not in resolved:
                resolved.append(stage_name)

        for stage in stages:
            resolve(stage)

        return resolved

    def on_progress(self, callback: Callable) -> None:
        """
        Register a progress callback.

        Args:
            callback: Function called with (stage_name, status, progress_pct)
        """
        self._progress_callbacks.append(callback)

    def _notify_progress(
        self,
        stage: str,
        status: StageStatus,
        progress: float = 0.0,
        message: str = ""
    ) -> None:
        """Notify progress callbacks."""
        for callback in self._progress_callbacks:
            try:
                callback(stage, status.value, progress, message)
            except Exception as e:
                self.logger.warning(f"Progress callback error: {e}")

    async def run(
        self,
        target: str,
        stages: Optional[List[str]] = None,
        vuln_types: Optional[List[str]] = None,
        safe_mode: bool = True,
        scan_name: Optional[str] = None
    ) -> PipelineContext:
        """
        Run the penetration testing pipeline.

        Args:
            target: Target domain/IP/URL
            stages: Specific stages to run (None for all)
            vuln_types: Vulnerability types to check
            safe_mode: Enable safe/non-destructive mode

        Returns:
            PipelineContext with results
        """
        if self._running:
            raise ScanError("Pipeline is already running")

        self._running = True
        self._cancelled = False

        # Create scan record
        scan = self.db.create_scan(
            target=target,
            name=scan_name,
            stages=stages or self.DEFAULT_STAGES,
            vuln_types=vuln_types or [],
            safe_mode=safe_mode
        )
        scan_id = scan["id"]

        # Initialize context
        context = PipelineContext(
            scan_id=scan_id,
            target=target,
            config=self.config,
            scope=self.scope,
            rate_limiter=self.rate_limiter,
            safe_mode=safe_mode,
            started_at=datetime.utcnow()
        )

        self.logger.info(f"Starting pipeline for target: {target}")
        self.logger.audit(
            AuditAction.SCAN_STARTED,
            f"Pipeline started for {target}",
            target=target,
            scan_id=scan_id,
            details={"stages": stages, "safe_mode": safe_mode}
        )

        # Update scan status
        self.db.update_scan(scan_id, status=ScanStatus.RUNNING.value, started_at=datetime.utcnow())

        try:
            # Determine stages to run
            stages_to_run = stages or list(self._stages.keys())
            stages_to_run = self._resolve_dependencies(stages_to_run)

            total_stages = len(stages_to_run)

            for idx, stage_name in enumerate(stages_to_run):
                if self._cancelled:
                    self.logger.info("Pipeline cancelled")
                    break

                self._current_stage = stage_name
                progress = (idx / total_stages) * 100

                # Get stage instance
                stage = self.get_stage(stage_name)
                if not stage:
                    self.logger.warning(f"Stage not found: {stage_name}")
                    continue

                # Check prerequisites
                if not stage.validate_prerequisites(context):
                    self.logger.warning(f"Prerequisites not met for stage: {stage_name}")
                    context.stage_results[stage_name] = StageResult(
                        stage_name=stage_name,
                        status=StageStatus.SKIPPED,
                        error="Prerequisites not met"
                    )
                    continue

                # Check if should skip
                if stage.should_skip(context):
                    self.logger.info(f"Skipping stage: {stage_name}")
                    context.stage_results[stage_name] = StageResult(
                        stage_name=stage_name,
                        status=StageStatus.SKIPPED
                    )
                    continue

                # Execute stage
                self._notify_progress(stage_name, StageStatus.RUNNING, progress)
                self.logger.info(f"Executing stage: {stage_name}")

                try:
                    result = await stage.execute(context)
                    context.stage_results[stage_name] = result

                    if result.status == StageStatus.COMPLETED:
                        self._notify_progress(
                            stage_name,
                            StageStatus.COMPLETED,
                            progress,
                            f"Found {result.findings_count} findings"
                        )
                    else:
                        self._notify_progress(
                            stage_name,
                            result.status,
                            progress,
                            result.error or ""
                        )

                except Exception as e:
                    self.logger.error(f"Stage {stage_name} failed: {e}")
                    context.stage_results[stage_name] = StageResult(
                        stage_name=stage_name,
                        status=StageStatus.FAILED,
                        error=str(e)
                    )
                    self._notify_progress(stage_name, StageStatus.FAILED, progress, str(e))

            # Pipeline completed
            final_status = ScanStatus.COMPLETED.value
            if self._cancelled:
                final_status = ScanStatus.CANCELLED.value
            elif any(r.status == StageStatus.FAILED for r in context.stage_results.values()):
                final_status = ScanStatus.FAILED.value

            # Update scan record
            self.db.update_scan(
                scan_id,
                status=final_status,
                completed_at=datetime.utcnow(),
                total_findings=len(context.findings)
            )

            self.logger.audit(
                AuditAction.SCAN_COMPLETED,
                f"Pipeline completed for {target}",
                target=target,
                scan_id=scan_id,
                details={
                    "status": final_status,
                    "findings": len(context.findings),
                    "stages_completed": sum(
                        1 for r in context.stage_results.values()
                        if r.status == StageStatus.COMPLETED
                    )
                }
            )

        except Exception as e:
            self.logger.error(f"Pipeline failed: {e}")
            self.db.update_scan(scan_id, status=ScanStatus.FAILED.value)
            self.logger.audit(
                AuditAction.SCAN_FAILED,
                f"Pipeline failed for {target}: {e}",
                target=target,
                scan_id=scan_id,
                success=False
            )
            raise ScanError(f"Pipeline failed: {e}", scan_id=scan_id)

        finally:
            self._running = False
            self._current_stage = None

        return context

    def cancel(self) -> None:
        """Cancel the running pipeline."""
        if self._running:
            self._cancelled = True
            self.logger.info("Pipeline cancellation requested")

    def is_running(self) -> bool:
        """Check if pipeline is running."""
        return self._running

    @property
    def current_stage(self) -> Optional[str]:
        """Get the currently executing stage."""
        return self._current_stage

    def get_available_stages(self) -> List[Dict[str, str]]:
        """Get list of available stages with descriptions."""
        return [
            {
                "name": name,
                "description": cls.description if hasattr(cls, "description") else "",
                "requires": cls.requires if hasattr(cls, "requires") else [],
            }
            for name, cls in self._stages.items()
        ]


# Built-in pipeline stages

class TargetIntakeStage(PipelineStage):
    """Initial target intake and parsing stage."""

    name = "target_intake"
    description = "Parse and validate target input"
    requires = []

    async def execute(self, context: PipelineContext) -> StageResult:
        started = datetime.utcnow()

        # Parse target (URL, domain, or IP)
        target = context.target.strip()

        # Extract domain/host
        if "://" in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.netloc
            if ":" in host:
                host = host.split(":")[0]
            context.add_web_server(target)
        else:
            host = target

        context.add_subdomain(host)

        completed = datetime.utcnow()
        return StageResult(
            stage_name=self.name,
            status=StageStatus.COMPLETED,
            started_at=started,
            completed_at=completed,
            duration_seconds=(completed - started).total_seconds(),
            data={"host": host, "original_target": target}
        )


class ScopeValidationStage(PipelineStage):
    """Validate target against scope."""

    name = "scope_validation"
    description = "Validate target is within authorized scope"
    requires = ["target_intake"]

    async def execute(self, context: PipelineContext) -> StageResult:
        started = datetime.utcnow()

        if context.scope:
            for subdomain in context.subdomains:
                valid, reason = context.scope.validate(subdomain)
                if not valid:
                    return StageResult(
                        stage_name=self.name,
                        status=StageStatus.FAILED,
                        started_at=started,
                        completed_at=datetime.utcnow(),
                        error=f"Scope violation: {subdomain} - {reason}"
                    )

        completed = datetime.utcnow()
        return StageResult(
            stage_name=self.name,
            status=StageStatus.COMPLETED,
            started_at=started,
            completed_at=completed,
            duration_seconds=(completed - started).total_seconds(),
            data={"validated": True}
        )


def create_default_pipeline() -> Pipeline:
    """Create a pipeline with default stages registered."""
    pipeline = Pipeline()

    # Register all stages
    from aptx.core.stages import register_all_stages
    register_all_stages(pipeline)

    return pipeline
