"""CRA Article 14 early-warning packer: signals, not exploitation."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType

import pytest
from click.testing import CliRunner

from beacon.cli import main
from beacon.config import load_settings
from beacon.crypto.witness import check_chain, load_records, seal_payload
from beacon.errors import E_NO_CHECKPOINT, BeaconError
from beacon.plugins.loader import load_plugins
from beacon.plugins.spec import CollectContext, FetcherSpec
from beacon.scf.engine import collect_named

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "cra_art14_early_warning.py"
FIXTURE = ROOT / "examples" / "fixtures" / "cra.art14.early_warning.json"


def load_cra_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("cra_art14_early_warning_test", EXAMPLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def cra() -> ModuleType:
    return load_cra_module()


def test_drop_in_plugin_from_beacon_plugin_path(initialized, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BEACON_PLUGIN_PATH", str(EXAMPLE))
    plugins = load_plugins(load_settings())
    assert "cra.art14.early_warning" in plugins
    plugin = plugins["cra.art14.early_warning"]
    assert isinstance(plugin.spec, FetcherSpec)
    assert plugin.spec.category == "compliance"
    assert plugin.spec.scf_targets == ("GOV-01",)
    result = plugin.collect(CollectContext(live=False))
    assert result.ok is True
    assert result.mode == "fixture"


def test_fixture_collect_ok(cra, initialized):
    result = cra.PLUGIN.collect(CollectContext(live=False))
    assert result.ok is True
    assert result.mode == "fixture"
    payload = result.payload
    assert payload["schema_version"] == "1.0"
    assert payload["article"] == "CRA-Art-14"
    assert payload["mode"] == "fixture"
    assert payload["signal_sources"] == ["kev"]
    assert payload["product_scope"]["product_name"] == "fixture-widget"
    assert payload["observed_at"].endswith("Z")
    assert "KEV listing" in payload["disclaimer"]
    assert payload["observations"]["kev"]["row_count"] == 3
    assert payload["observations"]["kev"]["fetched"] is False


def test_kev_present_but_exploitation_undetermined(cra, initialized):
    result = cra.PLUGIN.collect(CollectContext(live=False))
    payload = result.payload
    matched = {item["cve_id"] for item in payload["matched_signals"]}
    assert matched == {"CVE-2099-0001", "CVE-2099-0003"}
    assert "CVE-2099-0002" not in matched
    assert payload["signal_present"] is True
    assert payload["exploitation_status"] == "undetermined"
    assert payload["notification_status"] == "not_evaluated"
    assert payload["kev_is_not_exploitation"] is True
    finding = payload["findings"][0]
    assert finding["does_not_assert_notification_duty"] is True
    assert finding["kev_is_not_exploitation"] is True
    assert "must_notify" not in finding
    critical = [item for item in payload["matched_signals"] if item["cve_id"] == "CVE-2099-0001"][0]
    assert critical["severity"] == "CRITICAL"
    assert critical["known_ransomware_campaign_use"] == "Known"
    assert critical["does_not_assert_exploitation"] is True
    blob = json.dumps(payload).lower()
    assert "product exploitation confirmed" not in blob


def test_explicit_confirmed_flag_is_the_only_exploitation_input(cra, initialized):
    result = cra.PLUGIN.collect(
        CollectContext(
            live=False,
            extra={"confirmed_exploitation": True, "notification_status": "notified"},
        )
    )
    assert result.ok is True
    assert result.payload["exploitation_status"] == "confirmed"
    assert result.payload["notification_status"] == "notified"
    default = cra.PLUGIN.collect(CollectContext(live=False))
    assert default.payload["exploitation_status"] == "undetermined"


def test_live_failed_is_not_rewritten_as_fixture(cra, initialized, monkeypatch: pytest.MonkeyPatch):
    def boom(_url: str, timeout: int = 20) -> dict:
        raise TimeoutError("synthetic KEV fetch failure")

    monkeypatch.setattr(cra, "_http_get_json", boom)
    result = cra.PLUGIN.collect(CollectContext(live=True, extra={"kev_url": "https://kev.example.test/feed.json"}))
    assert result.ok is False
    assert result.mode == "live_failed"
    assert result.payload["mode"] == "live_failed"
    assert result.payload["ok"] is False
    assert result.payload["exploitation_status"] == "undetermined"
    assert result.payload["matched_signals"] == []
    observations = result.payload["observations"]["kev"]
    assert observations["fetched"] is False
    assert observations["vulnerabilities"] == []
    assert result.payload["findings"] == []
    assert "CVE-2099-0001" not in json.dumps(observations)
    assert result.payload.get("fixture_reason") is None


def test_live_https_url_required(cra, initialized):
    result = cra.PLUGIN.collect(CollectContext(live=True, extra={"kev_url": "http://kev.example.test/feed.json"}))
    assert result.ok is False
    assert result.mode == "live_failed"
    assert "https" in (result.error or "").lower()


def test_live_rejects_file_loopback_and_credentialed_urls(cra, initialized, monkeypatch: pytest.MonkeyPatch):
    def boom(_url: str, timeout: int = 20) -> dict:
        raise AssertionError("live fetch must not run for blocked KEV URLs")

    monkeypatch.setattr(cra, "_http_get_json", boom)
    blocked = (
        "file:///etc/passwd",
        "https://127.0.0.1/feed.json",
        "https://169.254.169.254/latest/meta-data/",
        "https://user:pass@www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    for url in blocked:
        result = cra.PLUGIN.collect(CollectContext(live=True, extra={"kev_url": url}))
        assert result.ok is False
        assert result.mode == "live_failed"
        blob = json.dumps(result.payload)
        assert "user:pass" not in blob
        assert "/etc/passwd" not in blob
        assert result.payload["observations"]["kev"]["source_url"] == cra.INVALID_KEV_URL
        assert result.payload["findings"] == []


def test_live_rejects_alternate_loopback_host_spellings(cra, initialized, monkeypatch: pytest.MonkeyPatch):
    def boom(_url: str, timeout: int = 20) -> dict:
        raise AssertionError("live fetch must not run for blocked KEV URLs")

    monkeypatch.setattr(cra, "_http_get_json", boom)
    blocked = (
        "https://127.1/feed.json",
        "https://2130706433/feed.json",
        "https://0177.0.0.1/feed.json",
        "https://0x7f.0.0.1/feed.json",
        "https://127.0.1/feed.json",
    )
    for url in blocked:
        result = cra.PLUGIN.collect(CollectContext(live=True, extra={"kev_url": url}))
        assert result.ok is False, url
        assert result.mode == "live_failed", url
        assert result.payload["observations"]["kev"]["source_url"] == cra.INVALID_KEV_URL
        assert result.payload["findings"] == []
        assert result.payload.get("fixture_reason") is None


def test_live_rejects_non_catalog_json_object(cra, initialized, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cra, "_http_get_json", lambda _url, timeout=20: {"error": "unavailable"})
    result = cra.PLUGIN.collect(
        CollectContext(live=True, extra={"kev_url": "https://kev.example.test/feed.json"})
    )
    assert result.ok is False
    assert result.mode == "live_failed"
    assert result.payload["mode"] == "live_failed"
    assert result.payload["ok"] is False
    assert result.payload["matched_signals"] == []
    assert result.payload["findings"] == []
    assert result.payload.get("fixture_reason") is None
    observations = result.payload["observations"]["kev"]
    assert observations["fetched"] is False
    assert observations["vulnerabilities"] == []
    error = (result.error or result.payload.get("error") or "").lower()
    assert "catalog" in error or "vulnerabilities" in error


def test_live_accepts_empty_kev_catalog_with_metadata(cra, initialized, monkeypatch: pytest.MonkeyPatch):
    empty = {"catalogVersion": "fixture-empty", "vulnerabilities": []}
    monkeypatch.setattr(cra, "_http_get_json", lambda _url, timeout=20: empty)
    result = cra.PLUGIN.collect(
        CollectContext(
            live=True,
            extra={"kev_url": "https://kev.example.test/feed.json", "product_scope": {"product_name": "fixture-widget"}},
        )
    )
    assert result.ok is True
    assert result.mode == "live"
    assert result.payload["matched_signals"] == []
    assert result.payload["observations"]["kev"]["fetched"] is True
    assert result.payload["exploitation_status"] == "undetermined"


def test_relative_fixture_path_collects_without_crash(cra, initialized):
    rel = os.path.relpath(FIXTURE)
    assert not Path(rel).is_absolute()
    with pytest.raises(ValueError, match="relative"):
        Path(rel).as_uri()
    result = cra.PLUGIN.collect(CollectContext(live=False, extra={"fixture_path": rel}))
    assert result.ok is True
    assert result.mode == "fixture"
    source_url = result.payload["observations"]["kev"]["source_url"]
    assert source_url.startswith("file:")
    assert "cra.art14.early_warning.json" in source_url
    missing = cra.PLUGIN.collect(
        CollectContext(live=False, extra={"fixture_path": "missing-cra-art14-fixture.json"})
    )
    assert missing.ok is False
    assert missing.mode == "fixture"
    assert missing.payload["observations"]["kev"]["source_url"].startswith("file:")


def test_live_success_still_leaves_exploitation_undetermined(cra, initialized, monkeypatch: pytest.MonkeyPatch):
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setattr(cra, "_http_get_json", lambda _url, timeout=20: fixture["kev"])
    result = cra.PLUGIN.collect(
        CollectContext(
            live=True,
            extra={
                "kev_url": "https://kev.example.test/feed.json",
                "product_scope": fixture["product_scope"],
            },
        )
    )
    assert result.ok is True
    assert result.mode == "live"
    assert result.payload["mode"] == "live"
    assert result.payload["observations"]["kev"]["fetched"] is True
    assert result.payload["signal_present"] is True
    assert result.payload["exploitation_status"] == "undetermined"
    assert result.payload["notification_status"] == "not_evaluated"


def test_collect_named_seals_fixture_and_check_passes(initialized, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BEACON_PLUGIN_PATH", str(EXAMPLE))
    sealed = collect_named(
        load_settings(),
        "cra.art14.early_warning",
        CollectContext(live=False),
        checkpoint=True,
    )
    assert sealed["ok"] is True
    assert sealed["mode"] == "fixture"
    assert sealed["plugin"] == "cra.art14.early_warning"
    assert sealed["checkpoint"]["to_seq"] >= 1
    check_chain(load_settings())
    records = load_records(load_settings())
    assert records[-1].plugin == "cra.art14.early_warning"


def test_cra_seal_without_checkpoint_fails_closed(initialized):
    settings = load_settings()
    seal_payload(
        settings,
        plugin="cra.art14.early_warning",
        mode="fixture",
        scf_targets=["GOV-01"],
        payload={"article": "CRA-Art-14", "exploitation_status": "undetermined"},
    )
    with pytest.raises(BeaconError) as caught:
        check_chain(settings)
    assert caught.value.code == E_NO_CHECKPOINT


def test_cli_collect_plugin_fixture(initialized, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BEACON_PLUGIN_PATH", str(EXAMPLE))
    runner = CliRunner()
    result = runner.invoke(main, ["collect", "--plugin", "cra.art14.early_warning", "--fixture"])
    assert result.exit_code == 0
    assert "cra.art14.early_warning" in result.output
    check = runner.invoke(main, ["check"])
    assert check.exit_code == 0
