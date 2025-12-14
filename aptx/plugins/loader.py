"""
APT-X Plugin Loader
===================

Dynamic plugin loading and management.
"""

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type

from aptx.plugins.sdk import PluginBase
from aptx.core.logger import get_logger


class PluginLoader:
    """Loads and manages plugins."""

    def __init__(self, plugins_dir: Optional[Path] = None):
        self.logger = get_logger().get_child("plugins")
        self.plugins_dir = plugins_dir or Path.home() / ".aptx" / "plugins"
        self.plugins: Dict[str, PluginBase] = {}

    def discover(self) -> List[str]:
        """Discover available plugins."""
        found = []

        if not self.plugins_dir.exists():
            return found

        for plugin_file in self.plugins_dir.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue
            found.append(plugin_file.stem)

        self.logger.info(f"Discovered {len(found)} plugins")
        return found

    def load(self, plugin_name: str) -> Optional[PluginBase]:
        """Load a plugin by name."""
        plugin_path = self.plugins_dir / f"{plugin_name}.py"

        if not plugin_path.exists():
            self.logger.error(f"Plugin not found: {plugin_name}")
            return None

        try:
            spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[plugin_name] = module
            spec.loader.exec_module(module)

            # Find plugin class
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type) and
                    issubclass(attr, PluginBase) and
                    attr is not PluginBase
                ):
                    plugin = attr()
                    plugin.initialize({})
                    self.plugins[plugin_name] = plugin
                    self.logger.info(f"Loaded plugin: {plugin_name}")
                    return plugin

        except Exception as e:
            self.logger.error(f"Failed to load plugin {plugin_name}: {e}")

        return None

    def load_all(self) -> Dict[str, PluginBase]:
        """Load all discovered plugins."""
        for name in self.discover():
            self.load(name)
        return self.plugins

    def get(self, name: str) -> Optional[PluginBase]:
        """Get a loaded plugin."""
        return self.plugins.get(name)

    def unload(self, name: str) -> None:
        """Unload a plugin."""
        if name in self.plugins:
            self.plugins[name].cleanup()
            del self.plugins[name]
            self.logger.info(f"Unloaded plugin: {name}")
