"""
APT-X Core Module
=================

Core components for the APT-X framework including configuration management,
database abstraction, logging, scope validation, and pipeline orchestration.
"""

from aptx.core.config import Config, get_config
from aptx.core.database import Database, get_database
from aptx.core.logger import AuditLogger, get_logger
from aptx.core.scope import ScopeValidator
from aptx.core.pipeline import Pipeline, PipelineStage
from aptx.core.rate_limiter import RateLimiter
from aptx.core.exceptions import (
    APTXError,
    ScopeViolationError,
    AuthorizationError,
    ConfigurationError,
    ToolNotFoundError,
    ValidationError,
)

__all__ = [
    "Config",
    "get_config",
    "Database",
    "get_database",
    "AuditLogger",
    "get_logger",
    "ScopeValidator",
    "Pipeline",
    "PipelineStage",
    "RateLimiter",
    "APTXError",
    "ScopeViolationError",
    "AuthorizationError",
    "ConfigurationError",
    "ToolNotFoundError",
    "ValidationError",
]
