"""
APT-X Custom Exceptions
=======================

Custom exception classes for the APT-X framework providing clear error
handling and categorization throughout the application.
"""

from typing import Optional, Any


class APTXError(Exception):
    """Base exception for all APT-X errors."""

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[dict] = None
    ):
        self.message = message
        self.code = code or "APTX_ERROR"
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict:
        """Convert exception to dictionary for logging/API responses."""
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


class AuthorizationError(APTXError):
    """Raised when authorization is required but not provided."""

    def __init__(
        self,
        message: str = "Authorization required before performing this action",
        details: Optional[dict] = None
    ):
        super().__init__(
            message=message,
            code="AUTH_REQUIRED",
            details=details
        )


class ScopeViolationError(APTXError):
    """Raised when a target is outside the defined scope."""

    def __init__(
        self,
        target: str,
        reason: str = "Target is not in the allowed scope",
        details: Optional[dict] = None
    ):
        details = details or {}
        details["target"] = target
        super().__init__(
            message=f"Scope violation for '{target}': {reason}",
            code="SCOPE_VIOLATION",
            details=details
        )
        self.target = target


class ConfigurationError(APTXError):
    """Raised when there's a configuration issue."""

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        details: Optional[dict] = None
    ):
        details = details or {}
        if config_key:
            details["config_key"] = config_key
        super().__init__(
            message=message,
            code="CONFIG_ERROR",
            details=details
        )
        self.config_key = config_key


class ToolNotFoundError(APTXError):
    """Raised when an external tool is not found or not installed."""

    def __init__(
        self,
        tool_name: str,
        install_hint: Optional[str] = None,
        details: Optional[dict] = None
    ):
        details = details or {}
        details["tool"] = tool_name
        if install_hint:
            details["install_hint"] = install_hint
        message = f"Tool '{tool_name}' not found or not accessible"
        if install_hint:
            message += f". Install with: {install_hint}"
        super().__init__(
            message=message,
            code="TOOL_NOT_FOUND",
            details=details
        )
        self.tool_name = tool_name
        self.install_hint = install_hint


class ValidationError(APTXError):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        details: Optional[dict] = None
    ):
        details = details or {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)[:100]  # Truncate for safety
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            details=details
        )
        self.field = field
        self.value = value


class DatabaseError(APTXError):
    """Raised when a database operation fails."""

    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        details: Optional[dict] = None
    ):
        details = details or {}
        if operation:
            details["operation"] = operation
        super().__init__(
            message=message,
            code="DATABASE_ERROR",
            details=details
        )
        self.operation = operation


class ScanError(APTXError):
    """Raised when a scan operation fails."""

    def __init__(
        self,
        message: str,
        scan_id: Optional[str] = None,
        stage: Optional[str] = None,
        details: Optional[dict] = None
    ):
        details = details or {}
        if scan_id:
            details["scan_id"] = scan_id
        if stage:
            details["stage"] = stage
        super().__init__(
            message=message,
            code="SCAN_ERROR",
            details=details
        )
        self.scan_id = scan_id
        self.stage = stage


class RateLimitError(APTXError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        target: str,
        limit: int,
        window: int,
        details: Optional[dict] = None
    ):
        details = details or {}
        details["target"] = target
        details["limit"] = limit
        details["window_seconds"] = window
        super().__init__(
            message=f"Rate limit exceeded for '{target}': {limit} requests per {window}s",
            code="RATE_LIMIT_EXCEEDED",
            details=details
        )
        self.target = target
        self.limit = limit
        self.window = window


class PluginError(APTXError):
    """Raised when a plugin operation fails."""

    def __init__(
        self,
        message: str,
        plugin_name: Optional[str] = None,
        details: Optional[dict] = None
    ):
        details = details or {}
        if plugin_name:
            details["plugin"] = plugin_name
        super().__init__(
            message=message,
            code="PLUGIN_ERROR",
            details=details
        )
        self.plugin_name = plugin_name


class ReportError(APTXError):
    """Raised when report generation fails."""

    def __init__(
        self,
        message: str,
        report_format: Optional[str] = None,
        details: Optional[dict] = None
    ):
        details = details or {}
        if report_format:
            details["format"] = report_format
        super().__init__(
            message=message,
            code="REPORT_ERROR",
            details=details
        )
        self.report_format = report_format


class IntelligenceError(APTXError):
    """Raised when intelligence processing fails."""

    def __init__(
        self,
        message: str,
        source: Optional[str] = None,
        details: Optional[dict] = None
    ):
        details = details or {}
        if source:
            details["source"] = source
        super().__init__(
            message=message,
            code="INTELLIGENCE_ERROR",
            details=details
        )
        self.source = source


class NetworkError(APTXError):
    """Raised when a network operation fails."""

    def __init__(
        self,
        message: str,
        url: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[dict] = None
    ):
        details = details or {}
        if url:
            details["url"] = url
        if status_code:
            details["status_code"] = status_code
        super().__init__(
            message=message,
            code="NETWORK_ERROR",
            details=details
        )
        self.url = url
        self.status_code = status_code


class TimeoutError(APTXError):
    """Raised when an operation times out."""

    def __init__(
        self,
        message: str,
        timeout_seconds: Optional[float] = None,
        operation: Optional[str] = None,
        details: Optional[dict] = None
    ):
        details = details or {}
        if timeout_seconds:
            details["timeout_seconds"] = timeout_seconds
        if operation:
            details["operation"] = operation
        super().__init__(
            message=message,
            code="TIMEOUT_ERROR",
            details=details
        )
        self.timeout_seconds = timeout_seconds
        self.operation = operation
