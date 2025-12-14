"""
APT-X Plugin SDK
================

Base classes and utilities for plugin development.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from aptx.vulnerabilities.base import VulnerabilityScanner, Finding, ScanTarget
from aptx.recon.base import ReconModule, ReconResult


@dataclass
class PluginMetadata:
    """Plugin metadata."""
    name: str
    version: str
    author: str
    description: str
    category: str  # vulnerability, recon, reporting, etc.


class PluginBase(ABC):
    """Base class for all plugins."""

    metadata: PluginMetadata

    @abstractmethod
    def initialize(self, config: Dict) -> None:
        """Initialize the plugin with configuration."""
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Cleanup resources."""
        pass

    def get_info(self) -> Dict:
        """Get plugin information."""
        return {
            "name": self.metadata.name,
            "version": self.metadata.version,
            "author": self.metadata.author,
            "description": self.metadata.description,
            "category": self.metadata.category,
        }


class VulnerabilityPlugin(PluginBase, VulnerabilityScanner):
    """
    Base class for vulnerability scanner plugins.

    Example usage:

    ```python
    class MyCustomScanner(VulnerabilityPlugin):
        metadata = PluginMetadata(
            name="custom_vuln",
            version="1.0.0",
            author="Your Name",
            description="Custom vulnerability scanner",
            category="vulnerability"
        )

        name = "custom"
        description = "Custom vulnerability detection"
        severity = Severity.HIGH

        async def scan(self, target: ScanTarget, options: Dict = None) -> List[Finding]:
            # Your scanning logic here
            return []

        async def validate(self, finding: Finding, options: Dict = None) -> tuple:
            return False, "Not implemented"
    ```
    """

    def initialize(self, config: Dict) -> None:
        """Initialize scanner with config."""
        self.config = config

    def cleanup(self) -> None:
        """Cleanup resources."""
        pass


class ReconPlugin(PluginBase, ReconModule):
    """
    Base class for reconnaissance plugins.

    Example usage:

    ```python
    class MyReconModule(ReconPlugin):
        metadata = PluginMetadata(
            name="custom_recon",
            version="1.0.0",
            author="Your Name",
            description="Custom recon module",
            category="recon"
        )

        name = "custom_recon"
        description = "Custom reconnaissance"

        async def execute(self, target: str, options: Dict = None) -> ReconResult:
            # Your recon logic here
            pass
    ```
    """

    def initialize(self, config: Dict) -> None:
        self.config = config

    def cleanup(self) -> None:
        pass


# Decorator for registering plugins
def register_plugin(plugin_class):
    """Decorator to register a plugin class."""
    # Plugin registration logic would go here
    return plugin_class
