"""
APT-X Test Configuration
========================

Pytest fixtures and configuration for the test suite.
"""

import os
import sys
import tempfile
from pathlib import Path
from typing import Generator

import pytest

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture(scope="session")
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture(scope="function")
def clean_config():
    """Reset configuration between tests."""
    from aptx.core.config import reset_config
    reset_config()
    yield
    reset_config()


@pytest.fixture(scope="function")
def clean_database(temp_dir):
    """Provide a clean database for each test."""
    from aptx.core.database import Database, reset_database

    reset_database()
    db_path = temp_dir / "test.db"
    db = Database(engine="sqlite", sqlite_path=str(db_path))
    db.create_tables()
    yield db
    reset_database()


@pytest.fixture
def sample_config_file(temp_dir) -> Path:
    """Create a sample configuration file."""
    config_content = """
general:
  data_dir: ~/.aptx/data
  log_dir: ~/.aptx/logs

database:
  engine: sqlite
  sqlite:
    path: ~/.aptx/aptx.db

safety:
  require_authorization: true
  safe_mode: true
  rate_limit: 10

logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

scope:
  strict_mode: true
  block_private_ips: true
"""
    config_path = temp_dir / "test_config.yaml"
    config_path.write_text(config_content)
    return config_path


@pytest.fixture
def sample_scope_file(temp_dir) -> Path:
    """Create a sample scope file."""
    scope_content = """
name: "Test Scope"
description: "Test scope configuration"

strict_mode: true
block_private_ips: true
block_localhost: true

allowed_domains:
  - "example.com"
  - "*.example.com"
  - "test.local"

allowed_ips:
  - "93.184.216.34"

blocked_domains:
  - "admin.example.com"

blocked_paths:
  - "/admin/delete"
"""
    scope_path = temp_dir / "test_scope.yaml"
    scope_path.write_text(scope_content)
    return scope_path


@pytest.fixture
def mock_http_responses():
    """Mock HTTP responses for testing."""
    return {
        "http://example.com": {
            "status_code": 200,
            "body": "<html><body>Hello World</body></html>",
            "headers": {"content-type": "text/html"},
        },
        "http://example.com/login": {
            "status_code": 200,
            "body": '<form action="/login" method="POST"><input name="username"><input name="password"></form>',
            "headers": {"content-type": "text/html"},
        },
        "http://example.com/api/users": {
            "status_code": 200,
            "body": '{"users": []}',
            "headers": {"content-type": "application/json"},
        },
    }


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    return {
        "vuln_type": "sqli",
        "title": "SQL Injection in login form",
        "description": "The login form is vulnerable to SQL injection",
        "severity": "critical",
        "confidence": 85,
        "url": "http://example.com/login",
        "parameter": "username",
        "method": "POST",
        "evidence": "Error: You have an error in your SQL syntax",
        "remediation": "Use parameterized queries",
    }


@pytest.fixture
def sample_payloads():
    """Sample payloads for testing."""
    return {
        "sqli": [
            "'",
            "\"",
            "' OR '1'='1",
            "1' AND '1'='1",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "'\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ],
    }
