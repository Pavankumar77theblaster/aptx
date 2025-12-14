"""
APT-X Configuration Management
==============================

Handles loading, merging, and accessing configuration from YAML files
with support for environment variable overrides and default values.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, Union
from functools import lru_cache
from copy import deepcopy

from aptx.core.exceptions import ConfigurationError


class Config:
    """
    Configuration management class for APT-X.

    Supports:
    - Loading from YAML files
    - Environment variable overrides (APTX_* prefix)
    - Nested key access (config.get("database.sqlite.path"))
    - Default values
    - Configuration validation
    """

    DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "default.yaml"
    USER_CONFIG_DIR = Path.home() / ".aptx"
    LOCAL_CONFIG_NAME = "local.yaml"

    def __init__(
        self,
        config_path: Optional[Union[str, Path]] = None,
        load_defaults: bool = True,
        load_local: bool = True
    ):
        """
        Initialize configuration.

        Args:
            config_path: Path to custom config file (optional)
            load_defaults: Whether to load default configuration
            load_local: Whether to load local overrides (~/.aptx/local.yaml)
        """
        self._config: Dict[str, Any] = {}
        self._loaded_files: list = []

        if load_defaults:
            self._load_default_config()

        if load_local:
            self._load_local_config()

        if config_path:
            self.load_file(config_path)

        self._apply_env_overrides()
        self._expand_paths()

    def _load_default_config(self) -> None:
        """Load the default configuration file."""
        if self.DEFAULT_CONFIG_PATH.exists():
            self.load_file(self.DEFAULT_CONFIG_PATH)

    def _load_local_config(self) -> None:
        """Load local configuration overrides."""
        local_config = self.USER_CONFIG_DIR / self.LOCAL_CONFIG_NAME
        if local_config.exists():
            self.load_file(local_config)

    def load_file(self, path: Union[str, Path]) -> None:
        """
        Load configuration from a YAML file.

        Args:
            path: Path to YAML configuration file

        Raises:
            ConfigurationError: If file cannot be loaded or parsed
        """
        path = Path(path)
        if not path.exists():
            raise ConfigurationError(f"Configuration file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            self._merge_config(data)
            self._loaded_files.append(str(path))
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Failed to parse YAML config: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load config file: {e}")

    def _merge_config(self, new_config: Dict[str, Any]) -> None:
        """
        Recursively merge new configuration into existing.

        Args:
            new_config: Configuration dictionary to merge
        """
        self._config = self._deep_merge(self._config, new_config)

    @staticmethod
    def _deep_merge(base: Dict, override: Dict) -> Dict:
        """
        Deep merge two dictionaries.

        Args:
            base: Base dictionary
            override: Override dictionary (takes precedence)

        Returns:
            Merged dictionary
        """
        result = deepcopy(base)
        for key, value in override.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = deepcopy(value)
        return result

    def _apply_env_overrides(self) -> None:
        """
        Apply environment variable overrides.

        Environment variables with APTX_ prefix override config values.
        Use double underscore for nested keys: APTX_DATABASE__ENGINE=postgresql
        """
        prefix = "APTX_"
        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix):].lower().replace("__", ".")
                self.set(config_key, self._parse_env_value(value))

    @staticmethod
    def _parse_env_value(value: str) -> Any:
        """
        Parse environment variable value to appropriate type.

        Args:
            value: String value from environment

        Returns:
            Parsed value (bool, int, float, or str)
        """
        # Handle boolean
        if value.lower() in ("true", "yes", "1", "on"):
            return True
        if value.lower() in ("false", "no", "0", "off"):
            return False

        # Handle numeric
        try:
            return int(value)
        except ValueError:
            pass

        try:
            return float(value)
        except ValueError:
            pass

        return value

    def _expand_paths(self) -> None:
        """Expand ~ and environment variables in path values."""
        self._expand_paths_recursive(self._config)

    def _expand_paths_recursive(self, config: Dict) -> None:
        """Recursively expand paths in configuration."""
        path_keys = {"path", "dir", "directory", "file", "output_dir", "data_dir", "log_dir"}
        for key, value in config.items():
            if isinstance(value, dict):
                self._expand_paths_recursive(value)
            elif isinstance(value, str) and any(pk in key.lower() for pk in path_keys):
                config[key] = os.path.expanduser(os.path.expandvars(value))

    def get(
        self,
        key: str,
        default: Any = None,
        required: bool = False
    ) -> Any:
        """
        Get a configuration value by key.

        Args:
            key: Configuration key (supports dot notation: "database.engine")
            default: Default value if key not found
            required: Raise error if key not found and no default

        Returns:
            Configuration value

        Raises:
            ConfigurationError: If required key is not found
        """
        keys = key.split(".")
        value = self._config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                if required and default is None:
                    raise ConfigurationError(
                        f"Required configuration key not found: {key}",
                        config_key=key
                    )
                return default

        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value.

        Args:
            key: Configuration key (supports dot notation)
            value: Value to set
        """
        keys = key.split(".")
        config = self._config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get an entire configuration section.

        Args:
            section: Section name (e.g., "database", "safety")

        Returns:
            Section dictionary or empty dict
        """
        return self.get(section, {})

    def to_dict(self) -> Dict[str, Any]:
        """
        Get entire configuration as dictionary.

        Returns:
            Complete configuration dictionary
        """
        return deepcopy(self._config)

    def validate(self) -> bool:
        """
        Validate the configuration.

        Returns:
            True if valid

        Raises:
            ConfigurationError: If validation fails
        """
        required_sections = ["general", "database", "safety", "logging"]
        for section in required_sections:
            if section not in self._config:
                raise ConfigurationError(
                    f"Missing required configuration section: {section}",
                    config_key=section
                )

        # Validate database configuration
        db_engine = self.get("database.engine")
        if db_engine not in ("sqlite", "postgresql"):
            raise ConfigurationError(
                f"Invalid database engine: {db_engine}",
                config_key="database.engine"
            )

        # Validate logging level
        log_level = self.get("logging.level", "INFO")
        valid_levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
        if log_level.upper() not in valid_levels:
            raise ConfigurationError(
                f"Invalid logging level: {log_level}",
                config_key="logging.level"
            )

        return True

    def ensure_directories(self) -> None:
        """Create necessary directories from configuration."""
        dirs_to_create = [
            self.get("general.data_dir"),
            self.get("general.log_dir"),
            self.get("reporting.output_dir"),
            self.get("plugins.directory"),
        ]

        for dir_path in dirs_to_create:
            if dir_path:
                path = Path(dir_path)
                path.mkdir(parents=True, exist_ok=True)

    @property
    def loaded_files(self) -> list:
        """Return list of loaded configuration files."""
        return self._loaded_files.copy()

    def __getitem__(self, key: str) -> Any:
        """Allow dict-style access: config['database']['engine']"""
        return self.get(key)

    def __contains__(self, key: str) -> bool:
        """Check if key exists in configuration."""
        try:
            self.get(key, required=True)
            return True
        except ConfigurationError:
            return False

    def __repr__(self) -> str:
        return f"Config(loaded_files={self._loaded_files})"


# Global configuration instance
_config: Optional[Config] = None


def get_config(
    config_path: Optional[Union[str, Path]] = None,
    reload: bool = False
) -> Config:
    """
    Get or create the global configuration instance.

    Args:
        config_path: Optional custom config file path
        reload: Force reload of configuration

    Returns:
        Config instance
    """
    global _config
    if _config is None or reload:
        _config = Config(config_path=config_path)
    return _config


def reset_config() -> None:
    """Reset the global configuration instance."""
    global _config
    _config = None
