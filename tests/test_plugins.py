"""Cloud inspectors, drop-in PLUGIN loader, live-failure honesty."""

from __future__ import annotations

from pathlib import Path

import pytest

from beacon.config import load_settings
from beacon.plugins.cloud import AWS_PROFILE, CloudInspectorPlugin, builtin_plugins
from beacon.plugins.loader import load_plugins
from beacon.plugins.spec import CollectContext, FetcherSpec


def test_aws_azure_gcp_share_plugin_class():
    plugins = builtin_plugins()
    names = [plugin.spec.name for plugin in plugins]
    assert names == ["aws.inspector", "azure.inspector", "gcp.inspector"]
    assert all(type(plugin) is CloudInspectorPlugin for plugin in plugins)
    for plugin in plugins:
        assert "IAC-01" in plugin.spec.scf_targets
        assert "CRY-05" in plugin.spec.scf_targets


def test_fixture_when_no_credentials(initialized):
    plugin = CloudInspectorPlugin(AWS_PROFILE)
    result = plugin.collect(CollectContext(live=False))
    assert result.ok is True
    assert result.mode == "fixture"
    assert result.payload["mode"] == "fixture"
    assert result.payload["source"] == "aws.inspector"


def test_live_failure_is_not_success_fixture(initialized, monkeypatch: pytest.MonkeyPatch):
    plugin = CloudInspectorPlugin(AWS_PROFILE)
    monkeypatch.setattr(plugin, "_probe", lambda: "ok")

    def boom(_ctx: CollectContext) -> dict:
        raise RuntimeError("AccessDenied: inspector live call failed")

    monkeypatch.setattr(plugin, "_live_collect", boom)
    result = plugin.collect(CollectContext(live=True))
    assert result.ok is False
    assert result.mode == "live_failed"
    assert result.payload["mode"] == "live_failed"
    findings = result.payload.get("findings") or []
    assert findings == []
    blob = str(result.payload).lower()
    assert "pass" not in blob or "live_failed" in result.mode


def test_drop_in_plugin_from_beacon_plugin_path(initialized, monkeypatch: pytest.MonkeyPatch):
    example = Path(__file__).resolve().parents[1] / "examples" / "echo_platform.py"
    monkeypatch.setenv("BEACON_PLUGIN_PATH", str(example))
    plugins = load_plugins(load_settings())
    assert "echo" in plugins
    plugin = plugins["echo"]
    assert isinstance(plugin.spec, FetcherSpec)
    result = plugin.collect(CollectContext(target="GOV-01"))
    assert result.ok is True
    assert result.payload["message"] == "GOV-01"
    assert hasattr(plugin, "collect")
    assert plugin.spec.name == "echo"
