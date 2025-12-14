"""
APT-X Logging System
====================

Comprehensive logging and audit trail system for APT-X framework.
Provides structured logging with audit capabilities for compliance.
"""

import os
import json
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union
from functools import lru_cache
from enum import Enum


class AuditAction(Enum):
    """Enumeration of auditable actions."""
    # Authorization
    AUTH_ACCEPTED = "auth_accepted"
    AUTH_DECLINED = "auth_declined"

    # Scope
    SCOPE_LOADED = "scope_loaded"
    SCOPE_VIOLATION = "scope_violation"
    SCOPE_CHECK_PASS = "scope_check_pass"

    # Scan
    SCAN_CREATED = "scan_created"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"

    # Target
    TARGET_ADDED = "target_added"
    TARGET_VALIDATED = "target_validated"

    # Vulnerability
    VULN_DETECTED = "vuln_detected"
    VULN_VALIDATED = "vuln_validated"
    VULN_FALSE_POSITIVE = "vuln_false_positive"

    # Tool
    TOOL_EXECUTED = "tool_executed"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"

    # Report
    REPORT_GENERATED = "report_generated"
    REPORT_EXPORTED = "report_exported"

    # Intelligence
    DATA_INGESTED = "data_ingested"
    DATA_CLASSIFIED = "data_classified"

    # System
    CONFIG_LOADED = "config_loaded"
    CONFIG_CHANGED = "config_changed"
    PLUGIN_LOADED = "plugin_loaded"
    ERROR_OCCURRED = "error_occurred"


class JsonFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add extra fields
        if hasattr(record, "extra_data"):
            log_data["data"] = record.extra_data

        # Add exception info
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class AuditLogger:
    """
    Audit logger for APT-X framework.

    Provides structured audit logging with JSON output for compliance
    and forensic analysis of penetration testing activities.
    """

    def __init__(
        self,
        name: str = "aptx",
        log_dir: Optional[Union[str, Path]] = None,
        level: str = "INFO",
        console_output: bool = True,
        file_output: bool = True,
        json_format: bool = True,
        max_file_size_mb: int = 10,
        backup_count: int = 5
    ):
        """
        Initialize audit logger.

        Args:
            name: Logger name
            log_dir: Directory for log files
            level: Logging level
            console_output: Enable console output
            file_output: Enable file output
            json_format: Use JSON format for file output
            max_file_size_mb: Maximum log file size in MB
            backup_count: Number of backup files to keep
        """
        self.name = name
        self.log_dir = Path(log_dir) if log_dir else Path.home() / ".aptx" / "logs"
        self.level = getattr(logging, level.upper(), logging.INFO)
        self.json_format = json_format

        # Create log directory
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Setup main logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.level)
        self.logger.handlers.clear()

        # Setup audit logger (separate)
        self.audit_logger = logging.getLogger(f"{name}.audit")
        self.audit_logger.setLevel(logging.INFO)
        self.audit_logger.handlers.clear()

        # Console handler
        if console_output:
            self._setup_console_handler()

        # File handlers
        if file_output:
            self._setup_file_handler(max_file_size_mb, backup_count)
            self._setup_audit_handler(max_file_size_mb, backup_count)

    def _setup_console_handler(self) -> None:
        """Setup console logging handler."""
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.level)

        # Use rich formatting for console
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def _setup_file_handler(self, max_size_mb: int, backup_count: int) -> None:
        """Setup file logging handler."""
        log_file = self.log_dir / f"{self.name}.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding="utf-8"
        )
        file_handler.setLevel(self.level)

        if self.json_format:
            formatter = JsonFormatter()
        else:
            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
            )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def _setup_audit_handler(self, max_size_mb: int, backup_count: int) -> None:
        """Setup audit logging handler (always JSON)."""
        audit_file = self.log_dir / "audit.log"
        audit_handler = logging.handlers.RotatingFileHandler(
            audit_file,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding="utf-8"
        )
        audit_handler.setLevel(logging.INFO)
        audit_handler.setFormatter(JsonFormatter())
        self.audit_logger.addHandler(audit_handler)

    def _log(
        self,
        level: int,
        message: str,
        extra: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Internal logging method with extra data support.

        Args:
            level: Logging level
            message: Log message
            extra: Additional data to include
        """
        record = self.logger.makeRecord(
            self.name,
            level,
            "",
            0,
            message,
            None,
            None
        )
        if extra:
            record.extra_data = extra
        self.logger.handle(record)

    def debug(self, message: str, **kwargs) -> None:
        """Log debug message."""
        self._log(logging.DEBUG, message, kwargs if kwargs else None)

    def info(self, message: str, **kwargs) -> None:
        """Log info message."""
        self._log(logging.INFO, message, kwargs if kwargs else None)

    def warning(self, message: str, **kwargs) -> None:
        """Log warning message."""
        self._log(logging.WARNING, message, kwargs if kwargs else None)

    def error(self, message: str, **kwargs) -> None:
        """Log error message."""
        self._log(logging.ERROR, message, kwargs if kwargs else None)

    def critical(self, message: str, **kwargs) -> None:
        """Log critical message."""
        self._log(logging.CRITICAL, message, kwargs if kwargs else None)

    def audit(
        self,
        action: Union[AuditAction, str],
        message: str,
        target: Optional[str] = None,
        scan_id: Optional[str] = None,
        user: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True
    ) -> None:
        """
        Log an auditable action.

        Args:
            action: The audit action type
            message: Human-readable description
            target: Target of the action (IP/domain)
            scan_id: Associated scan ID
            user: User performing the action
            details: Additional details
            success: Whether the action succeeded
        """
        if isinstance(action, AuditAction):
            action_str = action.value
        else:
            action_str = action

        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action_str,
            "message": message,
            "success": success,
        }

        if target:
            audit_entry["target"] = target
        if scan_id:
            audit_entry["scan_id"] = scan_id
        if user:
            audit_entry["user"] = user
        if details:
            audit_entry["details"] = details

        # Log to audit logger
        record = self.audit_logger.makeRecord(
            f"{self.name}.audit",
            logging.INFO,
            "",
            0,
            message,
            None,
            None
        )
        record.extra_data = audit_entry
        self.audit_logger.handle(record)

        # Also log to main logger at INFO level
        self.info(f"[AUDIT:{action_str}] {message}", audit_data=audit_entry)

    def log_scope_check(
        self,
        target: str,
        passed: bool,
        reason: Optional[str] = None
    ) -> None:
        """Log a scope validation check."""
        action = AuditAction.SCOPE_CHECK_PASS if passed else AuditAction.SCOPE_VIOLATION
        self.audit(
            action=action,
            message=f"Scope check for {target}: {'PASS' if passed else 'FAIL'}",
            target=target,
            details={"reason": reason} if reason else None,
            success=passed
        )

    def log_scan_event(
        self,
        event: str,
        scan_id: str,
        target: str,
        details: Optional[Dict] = None
    ) -> None:
        """Log a scan-related event."""
        action_map = {
            "created": AuditAction.SCAN_CREATED,
            "started": AuditAction.SCAN_STARTED,
            "completed": AuditAction.SCAN_COMPLETED,
            "failed": AuditAction.SCAN_FAILED,
            "cancelled": AuditAction.SCAN_CANCELLED,
        }
        action = action_map.get(event, AuditAction.SCAN_STARTED)
        self.audit(
            action=action,
            message=f"Scan {event}: {scan_id}",
            target=target,
            scan_id=scan_id,
            details=details
        )

    def log_vulnerability(
        self,
        vuln_type: str,
        target: str,
        scan_id: str,
        severity: str,
        confidence: int,
        validated: bool = False
    ) -> None:
        """Log a detected vulnerability."""
        action = AuditAction.VULN_VALIDATED if validated else AuditAction.VULN_DETECTED
        self.audit(
            action=action,
            message=f"{'Validated' if validated else 'Detected'} {vuln_type} ({severity})",
            target=target,
            scan_id=scan_id,
            details={
                "vuln_type": vuln_type,
                "severity": severity,
                "confidence": confidence,
                "validated": validated
            }
        )

    def log_tool_execution(
        self,
        tool: str,
        target: str,
        command: str,
        success: bool,
        duration: Optional[float] = None
    ) -> None:
        """Log tool execution."""
        action = AuditAction.TOOL_COMPLETED if success else AuditAction.TOOL_FAILED
        self.audit(
            action=action,
            message=f"Tool {tool} {'completed' if success else 'failed'}",
            target=target,
            details={
                "tool": tool,
                "command": command[:200],  # Truncate for safety
                "duration_seconds": duration
            },
            success=success
        )

    def get_child(self, suffix: str) -> "AuditLogger":
        """
        Get a child logger with a specific suffix.

        Args:
            suffix: Suffix to append to logger name

        Returns:
            Child AuditLogger instance
        """
        child = AuditLogger.__new__(AuditLogger)
        child.name = f"{self.name}.{suffix}"
        child.log_dir = self.log_dir
        child.level = self.level
        child.json_format = self.json_format
        child.logger = self.logger.getChild(suffix)
        child.audit_logger = self.audit_logger
        return child


# Global logger instance
_logger: Optional[AuditLogger] = None


def get_logger(
    name: str = "aptx",
    log_dir: Optional[Union[str, Path]] = None,
    level: str = "INFO",
    reinit: bool = False
) -> AuditLogger:
    """
    Get or create the global logger instance.

    Args:
        name: Logger name
        log_dir: Directory for log files
        level: Logging level
        reinit: Force reinitialization

    Returns:
        AuditLogger instance
    """
    global _logger
    if _logger is None or reinit:
        _logger = AuditLogger(name=name, log_dir=log_dir, level=level)
    return _logger


def reset_logger() -> None:
    """Reset the global logger instance."""
    global _logger
    _logger = None
