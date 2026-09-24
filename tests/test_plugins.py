"""Cloud inspectors, drop-in PLUGIN loader, live-failure honesty."""

from __future__ import annotations

from pathlib import Path

import pytest

from beacon.config import load_settings
from beacon.plugins.cloud import AWS_PROFILE, CloudInspectorPlugin, builtin_plugins
from beacon.plugins.loader import load_plugins
from beacon.errors import E_ALREADY_INITIALIZED, BeaconError
from beacon.plugins.spec import CollectContext, FetcherSpec
from beacon.workspace import init_workspace


def test_aws_azure_gcp_share_plugin_class():
    plugins = builtin_plugins()
    names = [plugin.spec.name for plugin in plugins]
    assert names == ["aws.inspector", "azure.inspector", "gcp.inspector"]
    assert all(type(plugin) is CloudInspectorPlugin for plugin in plugins)
    for plugin in plugins:
        assert "IAC-02" in plugin.spec.scf_targets
        assert "CRY-07" in plugin.spec.scf_targets


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
    result = plugin.collect(CollectContext(target="GOV-02"))
    assert result.ok is True
    assert result.payload["message"] == "GOV-02"
    assert hasattr(plugin, "collect")
    assert plugin.spec.name == "echo"


class _Proc:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_expired_token_probe_is_live_failed_not_fixture(initialized, monkeypatch: pytest.MonkeyPatch):
    plugin = CloudInspectorPlugin(AWS_PROFILE)
    monkeypatch.setattr("beacon.plugins.cloud.shutil.which", lambda _name: "/usr/bin/aws")
    monkeypatch.setattr(
        "beacon.plugins.cloud._run",
        lambda *_a, **_k: _Proc(
            1, "", "ExpiredToken: The security token included in the request is expired"
        ),
    )
    result = plugin.collect(CollectContext())
    assert result.ok is False
    assert result.mode == "live_failed"
    assert result.payload.get("mode") == "live_failed"


def test_live_true_does_not_use_force_fixture(initialized, monkeypatch: pytest.MonkeyPatch):
    plugin = CloudInspectorPlugin(AWS_PROFILE)
    monkeypatch.setattr(plugin, "_probe", lambda: "ok")
    monkeypatch.setattr(
        plugin,
        "_live_collect",
        lambda _ctx: {"source": "aws.inspector", "mode": "live", "findings": []},
    )
    result = plugin.collect(CollectContext(live=True, extra={"force_fixture": True}))
    assert result.mode == "live"
    assert result.ok is True


def test_init_refuses_to_overwrite_keys(initialized):
    with pytest.raises(BeaconError) as caught:
        init_workspace(load_settings())
    assert caught.value.code == E_ALREADY_INITIALIZED
