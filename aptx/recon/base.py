"""
APT-X Reconnaissance Base
=========================

Base classes for reconnaissance modules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from enum import Enum

from aptx.core.logger import get_logger
from aptx.core.rate_limiter import RateLimiter
from aptx.core.scope import ScopeValidator
from aptx.core.pipeline import PipelineStage, PipelineContext, StageResult, StageStatus


class ReconType(str, Enum):
    """Reconnaissance type enumeration."""
    SUBDOMAIN = "subdomain"
    PORT_SCAN = "port_scan"
    WEB_DISCOVERY = "web_discovery"
    PASSIVE = "passive"
    DNS = "dns"
    WHOIS = "whois"


@dataclass
class ReconResult:
    """Result from reconnaissance operation."""
    recon_type: ReconType
    target: str
    success: bool
    started_at: datetime
    completed_at: datetime
    duration_seconds: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)
    items_found: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "recon_type": self.recon_type.value,
            "target": self.target,
            "success": self.success,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "data": self.data,
            "items_found": self.items_found,
            "error": self.error,
        }


class ReconModule(ABC):
    """
    Abstract base class for reconnaissance modules.

    Provides common functionality for target information gathering.
    """

    recon_type: ReconType = ReconType.PASSIVE
    name: str = "base"
    description: str = "Base reconnaissance module"

    def __init__(
        self,
        config: Optional[Dict] = None,
        scope: Optional[ScopeValidator] = None,
        rate_limiter: Optional[RateLimiter] = None
    ):
        """
        Initialize reconnaissance module.

        Args:
            config: Module configuration
            scope: Scope validator for target validation
            rate_limiter: Rate limiter for request throttling
        """
        self.config = config or {}
        self.scope = scope
        self.rate_limiter = rate_limiter
        self.logger = get_logger().get_child(f"recon.{self.name}")

    @abstractmethod
    async def execute(
        self,
        target: str,
        options: Optional[Dict] = None
    ) -> ReconResult:
        """
        Execute reconnaissance against target.

        Args:
            target: Target to recon
            options: Module-specific options

        Returns:
            ReconResult with findings
        """
        pass

    def validate_target(self, target: str) -> bool:
        """
        Validate target against scope.

        Args:
            target: Target to validate

        Returns:
            True if target is in scope
        """
        if self.scope:
            valid, _ = self.scope.validate(target)
            return valid
        return True

    def filter_in_scope(self, targets: List[str]) -> List[str]:
        """
        Filter a list of targets to only those in scope.

        Args:
            targets: List of targets to filter

        Returns:
            List of in-scope targets
        """
        if not self.scope:
            return targets

        in_scope = []
        for target in targets:
            valid, _ = self.scope.validate(target)
            if valid:
                in_scope.append(target)
            else:
                self.logger.debug(f"Filtered out-of-scope target: {target}")

        return in_scope

    async def rate_limit(self, target: Optional[str] = None) -> None:
        """Apply rate limiting."""
        if self.rate_limiter:
            await self.rate_limiter.acquire_async(target=target)


class ReconPipelineStage(PipelineStage):
    """
    Base class for reconnaissance pipeline stages.

    Wraps ReconModule for use in the pipeline.
    """

    module_class: type = None  # Override in subclasses
    requires: List[str] = ["target_intake", "scope_validation"]

    def __init__(self):
        super().__init__()
        self.module: Optional[ReconModule] = None

    def _create_module(self, context: PipelineContext) -> ReconModule:
        """Create and configure the reconnaissance module."""
        if self.module_class is None:
            raise NotImplementedError("module_class must be set")

        return self.module_class(
            config=context.config,
            scope=context.scope,
            rate_limiter=context.rate_limiter
        )

    async def execute(self, context: PipelineContext) -> StageResult:
        """Execute the reconnaissance stage."""
        started = datetime.utcnow()

        try:
            self.module = self._create_module(context)

            # Get targets from context
            targets = list(context.subdomains) or [context.target]

            all_results = []
            total_items = 0

            for target in targets:
                result = await self.module.execute(target)
                all_results.append(result)

                if result.success:
                    total_items += result.items_found
                    self._process_result(result, context)

            completed = datetime.utcnow()

            return StageResult(
                stage_name=self.name,
                status=StageStatus.COMPLETED,
                started_at=started,
                completed_at=completed,
                duration_seconds=(completed - started).total_seconds(),
                data={"results": [r.to_dict() for r in all_results]},
                findings_count=total_items
            )

        except Exception as e:
            self.logger.error(f"Recon stage failed: {e}")
            return StageResult(
                stage_name=self.name,
                status=StageStatus.FAILED,
                started_at=started,
                completed_at=datetime.utcnow(),
                error=str(e)
            )

    def _process_result(
        self,
        result: ReconResult,
        context: PipelineContext
    ) -> None:
        """
        Process result and update context.

        Override in subclasses for specific handling.
        """
        pass
