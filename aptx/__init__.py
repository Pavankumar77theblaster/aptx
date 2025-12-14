"""
APT-X: Automated Penetration Testing - eXtended Framework
=========================================================

An enterprise-grade, Kali Linux-based automated penetration testing framework
designed for professional Red Team operations.

Features:
- Automated reconnaissance, vulnerability discovery, and validation
- User-selectable vulnerability focus areas
- Intelligent data feed processing and auto-classification
- Professional reporting with CVSS scoring
- Clean, enterprise-ready web UI
- Extensible plugin architecture

Usage:
    from aptx import APTXFramework

    framework = APTXFramework()
    framework.initialize()
    scan = framework.create_scan(target="example.com")
    results = scan.run()

CLI:
    aptx scan example.com --vulns sqli,xss --safe-mode

License: MIT
"""

__version__ = "1.0.0"
__author__ = "APT-X Team"
__license__ = "MIT"

from aptx.core.config import Config, get_config
from aptx.core.database import Database, get_database
from aptx.core.logger import AuditLogger, get_logger
from aptx.core.scope import ScopeValidator
from aptx.core.pipeline import Pipeline, PipelineStage
from aptx.core.exceptions import (
    APTXError,
    ScopeViolationError,
    AuthorizationError,
    ConfigurationError,
    ToolNotFoundError,
    ValidationError,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__license__",
    # Core components
    "Config",
    "get_config",
    "Database",
    "get_database",
    "AuditLogger",
    "get_logger",
    "ScopeValidator",
    "Pipeline",
    "PipelineStage",
    # Exceptions
    "APTXError",
    "ScopeViolationError",
    "AuthorizationError",
    "ConfigurationError",
    "ToolNotFoundError",
    "ValidationError",
]
