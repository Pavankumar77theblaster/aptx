"""
Tests for APT-X Configuration Module
====================================
"""

import os
import pytest
from pathlib import Path

from aptx.core.config import Config, get_config, reset_config
from aptx.core.exceptions import ConfigurationError


class TestConfig:
    """Test cases for Config class."""

    def test_config_initialization(self, clean_config):
        """Test basic config initialization."""
        config = Config(load_defaults=False, load_local=False)
        assert config._config == {}
        assert config.loaded_files == []

    def test_config_load_file(self, sample_config_file, clean_config):
        """Test loading configuration from file."""
        config = Config(
            config_path=sample_config_file,
            load_defaults=False,
            load_local=False
        )
        assert "general" in config._config
        assert config.get("database.engine") == "sqlite"

    def test_config_get_with_default(self, clean_config):
        """Test getting config value with default."""
        config = Config(load_defaults=False, load_local=False)
        result = config.get("nonexistent.key", default="default_value")
        assert result == "default_value"

    def test_config_get_nested_key(self, sample_config_file, clean_config):
        """Test getting nested configuration value."""
        config = Config(
            config_path=sample_config_file,
            load_defaults=False,
            load_local=False
        )
        result = config.get("safety.safe_mode")
        assert result is True

    def test_config_set(self, clean_config):
        """Test setting configuration value."""
        config = Config(load_defaults=False, load_local=False)
        config.set("test.nested.key", "test_value")
        assert config.get("test.nested.key") == "test_value"

    def test_config_get_section(self, sample_config_file, clean_config):
        """Test getting entire configuration section."""
        config = Config(
            config_path=sample_config_file,
            load_defaults=False,
            load_local=False
        )
        safety = config.get_section("safety")
        assert isinstance(safety, dict)
        assert "safe_mode" in safety

    def test_config_to_dict(self, sample_config_file, clean_config):
        """Test converting config to dictionary."""
        config = Config(
            config_path=sample_config_file,
            load_defaults=False,
            load_local=False
        )
        result = config.to_dict()
        assert isinstance(result, dict)
        assert "general" in result

    def test_config_required_key_missing(self, clean_config):
        """Test error when required key is missing."""
        config = Config(load_defaults=False, load_local=False)
        with pytest.raises(ConfigurationError):
            config.get("nonexistent.key", required=True)

    def test_config_file_not_found(self, clean_config):
        """Test error when config file not found."""
        config = Config(load_defaults=False, load_local=False)
        with pytest.raises(ConfigurationError):
            config.load_file("/nonexistent/path/config.yaml")

    def test_config_deep_merge(self, clean_config):
        """Test deep merging of configurations."""
        base = {"a": {"b": 1, "c": 2}}
        override = {"a": {"b": 10, "d": 3}}
        result = Config._deep_merge(base, override)
        assert result["a"]["b"] == 10
        assert result["a"]["c"] == 2
        assert result["a"]["d"] == 3

    def test_config_env_value_parsing(self, clean_config):
        """Test environment variable value parsing."""
        assert Config._parse_env_value("true") is True
        assert Config._parse_env_value("false") is False
        assert Config._parse_env_value("123") == 123
        assert Config._parse_env_value("12.5") == 12.5
        assert Config._parse_env_value("hello") == "hello"

    def test_config_contains(self, sample_config_file, clean_config):
        """Test __contains__ method."""
        config = Config(
            config_path=sample_config_file,
            load_defaults=False,
            load_local=False
        )
        assert "database.engine" in config
        assert "nonexistent.key" not in config

    def test_config_getitem(self, sample_config_file, clean_config):
        """Test dict-style access."""
        config = Config(
            config_path=sample_config_file,
            load_defaults=False,
            load_local=False
        )
        assert config["database.engine"] == "sqlite"


class TestGetConfig:
    """Test cases for get_config function."""

    def test_get_config_singleton(self, clean_config):
        """Test that get_config returns singleton instance."""
        config1 = get_config()
        config2 = get_config()
        assert config1 is config2

    def test_get_config_reload(self, sample_config_file, clean_config):
        """Test config reload."""
        config1 = get_config()
        config2 = get_config(config_path=sample_config_file, reload=True)
        # After reload, config should be reloaded
        assert "database" in config2._config

    def test_reset_config(self, clean_config):
        """Test config reset."""
        get_config()
        reset_config()
        # After reset, getting config should create a new instance
        # This is implicitly tested by the clean_config fixture
