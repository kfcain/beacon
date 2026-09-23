"""Load builtin plugins and drop-in modules from ``BEACON_PLUGIN_PATH``."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Iterable

from beacon.config import Settings
from beacon.errors import E_UNKNOWN_PLUGIN, fail
from beacon.plugins.cloud import builtin_plugins
from beacon.plugins.lake_logs import PLUGIN as LAKE_LOG_PLUGIN
from beacon.plugins.scf_catalog import PLUGIN as SCF_CATALOG_PLUGIN
from beacon.plugins.spec import FetcherSpec, Plugin, covers_target


def _load_module(path: Path) -> ModuleType:
    name = f"beacon_plugin_{path.stem}_{abs(hash(str(path.resolve())))}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load plugin {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _plugin_from_path(path: Path) -> Plugin:
    module = _load_module(path)
    plugin = getattr(module, "PLUGIN", None)
    if plugin is None:
        raise ImportError(f"{path} does not export PLUGIN")
    if not hasattr(plugin, "spec") or not hasattr(plugin, "collect"):
        raise ImportError(f"{path} PLUGIN must have spec and collect()")
    if not isinstance(plugin.spec, FetcherSpec):
        raise ImportError(f"{path} PLUGIN.spec must be FetcherSpec")
    return plugin


def iter_plugin_files(plugin_path: tuple[Path, ...]) -> Iterable[Path]:
    for root in plugin_path:
        if root.is_file() and root.suffix == ".py":
            yield root
            continue
        if root.is_dir():
            yield from sorted(root.glob("*.py"))


def load_plugins(settings: Settings) -> dict[str, Plugin]:
    found: dict[str, Plugin] = {}
    for plugin in (*builtin_plugins(), LAKE_LOG_PLUGIN, SCF_CATALOG_PLUGIN):
        found[plugin.spec.name] = plugin
    for path in iter_plugin_files(settings.plugin_path):
        if path.name.startswith("_"):
            continue
        plugin = _plugin_from_path(path)
        found[plugin.spec.name] = plugin
    return found


def get_plugin(settings: Settings, name: str) -> Plugin:
    plugins = load_plugins(settings)
    if name not in plugins:
        fail(E_UNKNOWN_PLUGIN, f"unknown plugin {name}")
    return plugins[name]


def plugins_for_target(settings: Settings, target: str) -> list[Plugin]:
    return [plugin for plugin in load_plugins(settings).values() if covers_target(plugin.spec, target)]
