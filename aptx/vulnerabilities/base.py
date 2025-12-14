"""
APT-X Vulnerability Scanner Base
================================

Base classes for vulnerability detection modules.
"""

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from aptx.core.logger import get_logger
from aptx.core.rate_limiter import RateLimiter
from aptx.core.scope import ScopeValidator
from aptx.core.database import Severity, VulnerabilityType


@dataclass
class Finding:
    """
    Represents a detected vulnerability finding.

    Contains all information about the vulnerability including
    evidence, confidence score, and remediation guidance.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    vuln_type: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: int = 50  # 0-100

    # Location
    url: str = ""
    endpoint: str = ""
    parameter: str = ""
    method: str = "GET"

    # Evidence
    request: str = ""
    response: str = ""
    evidence: str = ""
    poc: str = ""
    payload: str = ""

    # Scoring
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # Metadata
    detected_at: datetime = field(default_factory=datetime.utcnow)
    validated: bool = False
    false_positive: bool = False
    tool: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "evidence": self.evidence,
            "poc": self.poc,
            "payload": self.payload,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "remediation": self.remediation,
            "references": self.references,
            "detected_at": self.detected_at.isoformat(),
            "validated": self.validated,
            "false_positive": self.false_positive,
            "tool": self.tool,
        }


@dataclass
class ScanTarget:
    """Target for vulnerability scanning."""
    url: str
    method: str = "GET"
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    content_type: str = ""


class VulnerabilityScanner(ABC):
    """
    Abstract base class for vulnerability scanners.

    Each scanner implements detection, validation, and remediation
    for a specific vulnerability type.
    """

    vuln_type: VulnerabilityType = VulnerabilityType.OTHER
    name: str = "base"
    description: str = "Base vulnerability scanner"
    severity: Severity = Severity.MEDIUM

    # Payloads for detection (subclasses define specific payloads)
    detection_payloads: List[str] = []
    safe_payloads: List[str] = []  # Non-destructive payloads for safe mode

    def __init__(
        self,
        config: Optional[Dict] = None,
        scope: Optional[ScopeValidator] = None,
        rate_limiter: Optional[RateLimiter] = None,
        safe_mode: bool = True
    ):
        """
        Initialize vulnerability scanner.

        Args:
            config: Scanner configuration
            scope: Scope validator
            rate_limiter: Rate limiter
            safe_mode: Enable safe/non-destructive mode
        """
        self.config = config or {}
        self.scope = scope
        self.rate_limiter = rate_limiter
        self.safe_mode = safe_mode
        self.logger = get_logger().get_child(f"vuln.{self.name}")

    @abstractmethod
    async def scan(
        self,
        target: ScanTarget,
        options: Optional[Dict] = None
    ) -> List[Finding]:
        """
        Scan target for vulnerabilities.

        Args:
            target: Target to scan
            options: Scanner-specific options

        Returns:
            List of findings
        """
        pass

    @abstractmethod
    async def validate(
        self,
        finding: Finding,
        options: Optional[Dict] = None
    ) -> Tuple[bool, str]:
        """
        Validate a finding with safe PoC.

        Args:
            finding: Finding to validate
            options: Validation options

        Returns:
            Tuple of (is_valid, validation_note)
        """
        pass

    def get_payloads(self) -> List[str]:
        """Get appropriate payloads based on mode."""
        if self.safe_mode:
            return self.safe_payloads or self.detection_payloads[:10]
        return self.detection_payloads

    def calculate_confidence(
        self,
        indicators: List[str],
        weights: Optional[Dict[str, int]] = None
    ) -> int:
        """
        Calculate confidence score based on indicators.

        Args:
            indicators: List of matched indicators
            weights: Optional custom weights

        Returns:
            Confidence score (0-100)
        """
        if not indicators:
            return 0

        default_weights = {
            "error_based": 30,
            "boolean_based": 25,
            "time_based": 35,
            "union_based": 40,
            "dom_manipulation": 25,
            "reflection": 20,
            "execution": 45,
            "header_injection": 30,
            "redirect": 20,
        }

        weights = weights or default_weights

        total = 0
        for indicator in indicators:
            total += weights.get(indicator, 10)

        return min(100, total)

    def get_remediation(self, finding: Finding) -> str:
        """
        Get remediation guidance for a finding.

        Override in subclasses for specific guidance.
        """
        return self._get_generic_remediation()

    def _get_generic_remediation(self) -> str:
        """Get generic remediation advice."""
        return (
            "Implement proper input validation and output encoding. "
            "Use parameterized queries and security headers. "
            "Follow OWASP guidelines for secure development."
        )

    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target against scope."""
        if self.scope:
            valid, _ = self.scope.validate(target.url)
            return valid
        return True

    async def rate_limit(self, target: Optional[str] = None) -> None:
        """Apply rate limiting."""
        if self.rate_limiter:
            await self.rate_limiter.acquire_async(target=target)

    def create_finding(
        self,
        target: ScanTarget,
        title: str,
        description: str,
        evidence: str,
        payload: str = "",
        confidence: int = 50,
        severity: Optional[Severity] = None,
        **kwargs
    ) -> Finding:
        """
        Create a standardized finding.

        Args:
            target: Scan target
            title: Finding title
            description: Finding description
            evidence: Evidence of vulnerability
            payload: Payload used
            confidence: Confidence score
            severity: Override severity
            **kwargs: Additional finding attributes

        Returns:
            Finding instance
        """
        from urllib.parse import urlparse
        parsed = urlparse(target.url)

        return Finding(
            vuln_type=self.vuln_type.value,
            title=title,
            description=description,
            severity=severity or self.severity,
            confidence=confidence,
            url=target.url,
            endpoint=parsed.path,
            parameter=kwargs.get("parameter", ""),
            method=target.method,
            evidence=evidence[:2000],  # Truncate
            payload=payload,
            poc=kwargs.get("poc", ""),
            remediation=self.get_remediation(None) if "remediation" not in kwargs else kwargs["remediation"],
            references=kwargs.get("references", []),
            tool=self.name,
            raw_data=kwargs.get("raw_data", {}),
        )


class WebVulnerabilityScanner(VulnerabilityScanner):
    """
    Base class for web application vulnerability scanners.

    Provides HTTP request utilities for web scanning.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._client = None

    async def _get_client(self):
        """Get or create HTTP client."""
        if self._client is None:
            import httpx
            self._client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                verify=False  # For testing purposes
            )
        return self._client

    async def _request(
        self,
        target: ScanTarget,
        payload: Optional[str] = None,
        inject_param: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Make HTTP request with optional payload injection.

        Args:
            target: Scan target
            payload: Payload to inject
            inject_param: Parameter to inject into

        Returns:
            Response data or None
        """
        await self.rate_limit(target.url)

        client = await self._get_client()

        try:
            # Prepare parameters
            params = target.parameters.copy()
            data = None

            if payload and inject_param:
                if inject_param in params:
                    params[inject_param] = payload
                elif target.body and inject_param in target.body:
                    data = target.body.replace(f"{inject_param}=", f"{inject_param}={payload}")

            # Make request
            if target.method.upper() == "POST":
                response = await client.post(
                    target.url,
                    params=params if target.method == "GET" else None,
                    data=data or params,
                    headers=target.headers,
                    cookies=target.cookies
                )
            else:
                response = await client.get(
                    target.url,
                    params=params,
                    headers=target.headers,
                    cookies=target.cookies
                )

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:50000],  # Limit size
                "url": str(response.url),
                "elapsed": response.elapsed.total_seconds(),
            }

        except Exception as e:
            self.logger.debug(f"Request failed: {e}")
            return None

    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
