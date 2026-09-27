import importlib
import inspect
import pkgutil
import logging
import os
import sys
from typing import Dict, List, Any, Optional, Type
from abc import ABC, abstractmethod


class BasePlugin(ABC):
    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    author: str = ""

    @abstractmethod
    async def run(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        ...

    @abstractmethod
    def get_metadata(self) -> Dict[str, Any]:
        ...


class PluginLoader:
    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        self.logger = logging.getLogger(__name__)
        self.plugins: Dict[str, BasePlugin] = {}
        self.plugin_dirs = plugin_dirs or [os.path.join(os.path.dirname(__file__), "..", "plugins")]
        self._discover_plugins()

    def _discover_plugins(self) -> None:
        for plugin_dir in self.plugin_dirs:
            if not os.path.isdir(plugin_dir):
                continue
            sys.path.insert(0, plugin_dir)
            for finder, name, ispkg in pkgutil.iter_modules([plugin_dir]):
                try:
                    module = importlib.import_module(name)
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (inspect.isclass(attr) and issubclass(attr, BasePlugin)
                                and attr is not BasePlugin):
                            instance = attr()
                            self.plugins[instance.name] = instance
                            self.logger.info(f"Loaded plugin: {instance.name} v{instance.version}")
                except Exception as e:
                    self.logger.error(f"Failed to load plugin {name}: {e}")
            sys.path.pop(0)

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        return self.plugins.get(name)

    def list_plugins(self) -> List[Dict[str, Any]]:
        return [p.get_metadata() for p in self.plugins.values()]

    async def run_plugin(self, name: str, target: str, **kwargs) -> List[Dict[str, Any]]:
        plugin = self.get_plugin(name)
        if not plugin:
            raise ValueError(f"Plugin '{name}' not found. Available: {list(self.plugins.keys())}")
        self.logger.info(f"Running plugin: {name} against {target}")
        return await plugin.run(target, **kwargs)
