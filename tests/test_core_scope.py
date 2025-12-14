"""
Tests for APT-X Scope Validation Module
=======================================
"""

import pytest
from pathlib import Path

from aptx.core.scope import ScopeValidator, ScopeConfig
from aptx.core.exceptions import ScopeViolationError


class TestScopeConfig:
    """Test cases for ScopeConfig class."""

    def test_scope_config_defaults(self):
        """Test default ScopeConfig values."""
        config = ScopeConfig()
        assert config.strict_mode is True
        assert config.block_private_ips is True
        assert config.allowed_domains == []

    def test_scope_config_custom(self):
        """Test custom ScopeConfig values."""
        config = ScopeConfig(
            name="Custom Scope",
            allowed_domains=["example.com"],
            strict_mode=False
        )
        assert config.name == "Custom Scope"
        assert "example.com" in config.allowed_domains
        assert config.strict_mode is False


class TestScopeValidator:
    """Test cases for ScopeValidator class."""

    def test_validator_with_config(self):
        """Test ScopeValidator with ScopeConfig."""
        config = ScopeConfig(
            allowed_domains=["example.com"]
        )
        validator = ScopeValidator(config=config)
        assert validator.config == config

    def test_validator_from_file(self, sample_scope_file):
        """Test ScopeValidator loading from file."""
        validator = ScopeValidator(config_file=sample_scope_file)
        assert validator.config.name == "Test Scope"
        assert "example.com" in validator.config.allowed_domains

    def test_validate_allowed_domain(self):
        """Test validation of allowed domain."""
        config = ScopeConfig(
            allowed_domains=["example.com"],
            strict_mode=True
        )
        validator = ScopeValidator(config=config)

        valid, reason = validator.validate("example.com")
        assert valid is True

    def test_validate_subdomain_wildcard(self):
        """Test validation with wildcard subdomain."""
        config = ScopeConfig(
            allowed_domains=["*.example.com"],
            strict_mode=True
        )
        validator = ScopeValidator(config=config)

        valid, reason = validator.validate("sub.example.com")
        assert valid is True

        valid, reason = validator.validate("other.com")
        assert valid is False

    def test_validate_blocked_domain(self):
        """Test validation of blocked domain."""
        config = ScopeConfig(
            allowed_domains=["example.com", "*.example.com"],
            blocked_domains=["admin.example.com"],
            strict_mode=True
        )
        validator = ScopeValidator(config=config)

        valid, reason = validator.validate("admin.example.com")
        assert valid is False
        assert "blocked" in reason.lower()

    def test_validate_private_ip_blocked(self):
        """Test that private IPs are blocked by default."""
        config = ScopeConfig(
            block_private_ips=True,
            strict_mode=False
        )
        validator = ScopeValidator(config=config)

        valid, reason = validator.validate("192.168.1.1")
        assert valid is False
        assert "private" in reason.lower()

    def test_validate_localhost_blocked(self):
        """Test that localhost is blocked."""
        config = ScopeConfig(
            block_localhost=True,
            strict_mode=False
        )
        validator = ScopeValidator(config=config)

        valid, reason = validator.validate("localhost")
        assert valid is False

        valid, reason = validator.validate("127.0.0.1")
        assert valid is False

    def test_validate_url(self):
        """Test validation of full URL."""
        config = ScopeConfig(
            allowed_domains=["example.com"],
            strict_mode=True
        )
        validator = ScopeValidator(config=config)

        valid, reason = validator.validate("https://example.com/page")
        assert valid is True

        valid, reason = validator.validate("https://other.com/page")
        assert valid is False

    def test_validate_blocked_path(self):
        """Test validation of blocked path."""
        config = ScopeConfig(
            allowed_domains=["example.com"],
            blocked_paths=["/admin/delete"],
            strict_mode=True
        )
        validator = ScopeValidator(config=config)

        valid, reason = validator.validate("https://example.com/admin/delete")
        assert valid is False
        assert "path" in reason.lower()

    def test_validate_ip_allowed(self):
        """Test validation of allowed IP."""
        config = ScopeConfig(
            allowed_ips=["93.184.216.34"],
            strict_mode=True
        )
        validator = ScopeValidator(config=config)

        valid, reason = validator.validate("93.184.216.34")
        assert valid is True

    def test_validate_cidr(self):
        """Test validation with CIDR range."""
        config = ScopeConfig(
            allowed_cidrs=["10.0.0.0/24"],
            block_private_ips=False,
            strict_mode=True
        )
        validator = ScopeValidator(config=config)

        valid, reason = validator.validate("10.0.0.50")
        assert valid is True

        valid, reason = validator.validate("10.0.1.50")
        assert valid is False

    def test_permissive_mode(self):
        """Test permissive mode (strict_mode=False)."""
        config = ScopeConfig(
            strict_mode=False,
            blocked_domains=["blocked.com"]
        )
        validator = ScopeValidator(config=config)

        # Anything not blocked should be allowed
        valid, reason = validator.validate("random.com")
        assert valid is True

        # Blocked should still be blocked
        valid, reason = validator.validate("blocked.com")
        assert valid is False

    def test_private_ip_blocked(self):
        """Test private IP blocking via validate."""
        config = ScopeConfig(block_private_ips=True, strict_mode=False)
        validator = ScopeValidator(config=config)

        # Private IPs should be blocked
        valid, _ = validator.validate("192.168.1.1")
        assert valid is False

        valid, _ = validator.validate("10.0.0.1")
        assert valid is False

    def test_localhost_blocked(self):
        """Test localhost blocking via validate."""
        config = ScopeConfig(block_localhost=True, strict_mode=False)
        validator = ScopeValidator(config=config)

        # Localhost should be blocked
        valid, _ = validator.validate("127.0.0.1")
        assert valid is False

    def test_scope_summary(self):
        """Test getting scope summary."""
        config = ScopeConfig(
            name="Test",
            allowed_domains=["example.com", "*.test.com"],
            allowed_ips=["1.2.3.4"],
            blocked_domains=["blocked.com"]
        )
        validator = ScopeValidator(config=config)

        summary = validator.get_summary()
        assert summary["name"] == "Test"
        assert summary["allowed_domains"] == 2

    def test_scope_to_yaml(self):
        """Test exporting scope to YAML."""
        config = ScopeConfig(
            name="Export Test",
            allowed_domains=["example.com"]
        )
        validator = ScopeValidator(config=config)

        yaml_str = validator.to_yaml()
        assert "name: Export Test" in yaml_str
        assert "example.com" in yaml_str
