"""Offline SCF 2026.2 catalog collector: pin, hashes, fail-closed witness."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from beacon.canonical import sha256_bytes
from beacon.cli import main
from beacon.config import load_settings
from beacon.crypto.witness import check_chain, load_records, seal_payload
from beacon.errors import E_NO_CHECKPOINT, E_SCF, BeaconError
from beacon.plugins.loader import load_plugins
from beacon.plugins.scf_catalog import PLUGIN, PLUGIN_NAME
from beacon.plugins.spec import CollectContext, FetcherSpec
from beacon.scf.catalog_pin import (
    CATALOG_PROVENANCE,
    CATALOG_SCF_TARGET,
    PINNED_COUNTS,
    PINNED_SCF_VERSION,
    PINNED_WORKBOOK_SHA256,
    inspect_catalog_pin,
    vendored_catalog_dir,
    verify_catalog_pin,
)
from beacon.scf.engine import collect_named

# Control id already declared by examples/echo_platform.py. Do not invent IDs.
KNOWN_IN_REPO_TARGET = "GOV-01"


def _dump(path: Path, obj: object) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _rehash_pin(pin_dir: Path) -> None:
    pin_path = pin_dir / "PIN.json"
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    pin["file_sha256"] = {
        name: sha256_bytes((pin_dir / name).read_bytes())
        for name in ("summary.json", "families.json", "index-meta.json")
        if (pin_dir / name).is_file()
    }
    _dump(pin_path, pin)


@pytest.fixture
def catalog_copy(tmp_path: Path) -> Path:
    dest = tmp_path / "scf-catalog-pin"
    shutil.copytree(vendored_catalog_dir(), dest)
    return dest


def test_plugin_is_builtin(initialized):
    plugins = load_plugins(load_settings())
    assert PLUGIN_NAME in plugins
    plugin = plugins[PLUGIN_NAME]
    assert isinstance(plugin.spec, FetcherSpec)
    assert plugin.spec.name == "scf.catalog.offline"
    assert plugin.spec.scf_targets == (KNOWN_IN_REPO_TARGET,)
    assert plugin.spec.scf_targets == (CATALOG_SCF_TARGET,)


def test_vendored_pin_matches_catalog_truth():
    result = verify_catalog_pin()
    assert result.ok is True
    assert result.scf_version == PINNED_SCF_VERSION == "2026.2"
    assert result.workbook_sha256 == PINNED_WORKBOOK_SHA256
    assert result.workbook_sha256 == "9e0a4df4993726c95e636f04b3028d8b5edeba2bda45d16ed6722b13540e6835"
    assert result.counts == PINNED_COUNTS
    assert result.counts["total_controls"] == 1534
    assert result.counts["total_families"] == 34
    assert result.counts["total_crosswalk_frameworks"] == 249
    assert result.counts["total_evidence_requests"] == 316
    assert result.counts["total_assessment_objectives"] == 5956
    assert "QTS" in result.family_codes
    assert result.qts_control_count == 34
    assert "GOV" in result.family_codes
    pin = json.loads((vendored_catalog_dir() / "PIN.json").read_text(encoding="utf-8"))
    assert pin["xlsx_sha256"] == PINNED_WORKBOOK_SHA256
    assert pin["file_sha256"]["summary.json"] == result.file_sha256["summary.json"]


def test_fixture_collect_ok(initialized):
    result = PLUGIN.collect(CollectContext(live=False))
    assert result.ok is True
    assert result.mode == "fixture"
    payload = result.payload
    assert payload["source"] == PLUGIN_NAME
    assert payload["ok"] is True
    assert payload["pin"]["scf_version"] == "2026.2"
    assert payload["pin"]["live_api_authoritative"] is False
    assert payload["pin"]["workbook_sha256"] == PINNED_WORKBOOK_SHA256
    assert payload["pin"]["counts"]["total_controls"] == 1534
    assert payload["catalog_pin"]["provenance"] == CATALOG_PROVENANCE
    binding = payload["scf_binding"]
    assert binding["scf_version"] == "2026.2"
    assert binding["scf_id"] == KNOWN_IN_REPO_TARGET
    assert binding["scf_ids"] == [KNOWN_IN_REPO_TARGET]
    assert binding["scf_family"] == "GOV"
    assert binding["erl_ids"] == []
    assert binding["framework_hops"] == []
    assert binding["pinned"] is True
    assert binding["provenance"] == "scf-catalog"
    assert payload["findings"][0]["scf"] == KNOWN_IN_REPO_TARGET
    assert "usa-federal-gsa-fedramp-20x-ksi" not in json.dumps(payload["scf_binding"])


def test_live_is_failed_not_fixture_and_does_not_fetch(initialized, monkeypatch: pytest.MonkeyPatch):
    def boom(*_a, **_k):  # noqa: ANN002
        raise AssertionError("catalog collector must not call live HTTP")

    monkeypatch.setattr("httpx.get", boom)
    result = PLUGIN.collect(CollectContext(live=True))
    assert result.ok is False
    assert result.mode == "live_failed"
    assert result.payload["mode"] == "live_failed"
    assert result.payload["findings"] == []
    assert result.payload["scf_binding"]["pinned"] is False
    assert "not the SCF 2026.2 pin" in (result.error or "")


def test_missing_file_fails_closed(catalog_copy: Path):
    (catalog_copy / "families.json").unlink()
    result = inspect_catalog_pin(catalog_copy)
    assert result.ok is False
    assert any("families.json" in item for item in result.errors)
    with pytest.raises(BeaconError) as caught:
        verify_catalog_pin(catalog_copy)
    assert caught.value.code == E_SCF
    collected = PLUGIN.collect(CollectContext(live=False, extra={"catalog_path": str(catalog_copy)}))
    assert collected.ok is False
    assert collected.mode == "failed"
    assert collected.payload["findings"] == []


def test_wrong_version_fails_closed(catalog_copy: Path):
    summary_path = catalog_copy / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["scf_version"] = "2026.1.1"
    _dump(summary_path, summary)
    pin_path = catalog_copy / "PIN.json"
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    pin["scf_version"] = "2026.1.1"
    _dump(pin_path, pin)
    _rehash_pin(catalog_copy)
    result = inspect_catalog_pin(catalog_copy)
    assert result.ok is False
    assert any("2026.2" in item for item in result.errors)
    collected = PLUGIN.collect(CollectContext(live=False, extra={"catalog_path": str(catalog_copy)}))
    assert collected.ok is False
    assert collected.payload["scf_binding"]["pinned"] is False
    assert collected.payload["pin"]["scf_version"] == "2026.1.1"


def test_wrong_count_fails_closed(catalog_copy: Path):
    summary_path = catalog_copy / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["total_controls"] = 1468
    _dump(summary_path, summary)
    pin_path = catalog_copy / "PIN.json"
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    pin["total_controls"] = 1468
    _dump(pin_path, pin)
    _rehash_pin(catalog_copy)
    result = inspect_catalog_pin(catalog_copy)
    assert result.ok is False
    assert any("total_controls" in item for item in result.errors)


def test_wrong_hash_fails_closed(catalog_copy: Path):
    summary_path = catalog_copy / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["source"] = "tampered"
    _dump(summary_path, summary)
    result = inspect_catalog_pin(catalog_copy)
    assert result.ok is False
    assert any("SHA-256 mismatch" in item for item in result.errors)


def test_empty_file_sha256_fails_closed(catalog_copy: Path):
    pin_path = catalog_copy / "PIN.json"
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    pin["file_sha256"] = {}
    _dump(pin_path, pin)
    result = inspect_catalog_pin(catalog_copy)
    assert result.ok is False
    assert any("file_sha256 is missing" in item for item in result.errors)


def test_incomplete_file_sha256_fails_closed(catalog_copy: Path):
    pin_path = catalog_copy / "PIN.json"
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    pin["file_sha256"].pop("families.json")
    _dump(pin_path, pin)
    result = inspect_catalog_pin(catalog_copy)
    assert result.ok is False
    assert any("families.json" in item and "file_sha256" in item for item in result.errors)


def test_empty_families_list_fails_closed(catalog_copy: Path):
    families_path = catalog_copy / "families.json"
    families = json.loads(families_path.read_text(encoding="utf-8"))
    families["families"] = []
    _dump(families_path, families)
    _rehash_pin(catalog_copy)
    result = inspect_catalog_pin(catalog_copy)
    assert result.ok is False
    assert any("families list is missing" in item for item in result.errors)


def test_zero_family_counts_fails_closed(catalog_copy: Path):
    families_path = catalog_copy / "families.json"
    families = json.loads(families_path.read_text(encoding="utf-8"))
    for row in families["families"]:
        row["control_count"] = 0
    _dump(families_path, families)
    _rehash_pin(catalog_copy)
    result = inspect_catalog_pin(catalog_copy)
    assert result.ok is False
    assert any("control_count" in item for item in result.errors)


def test_missing_workbook_sha_fails_closed(catalog_copy: Path):
    pin_path = catalog_copy / "PIN.json"
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    pin.pop("xlsx_sha256")
    _dump(pin_path, pin)
    result = inspect_catalog_pin(catalog_copy)
    assert result.ok is False
    assert any("xlsx_sha256 is missing" in item for item in result.errors)
    assert result.workbook_sha256 != PINNED_WORKBOOK_SHA256 or result.ok is False


def test_env_catalog_path(catalog_copy: Path, monkeypatch: pytest.MonkeyPatch, initialized):
    monkeypatch.setenv("BEACON_SCF_CATALOG_PATH", str(catalog_copy))
    result = verify_catalog_pin()
    assert result.ok is True
    assert result.catalog_root_kind == "env"
    assert result.catalog_root == catalog_copy.resolve()
    collected = PLUGIN.collect(CollectContext(live=False))
    assert collected.ok is True
    assert collected.payload["pin"]["catalog_root_kind"] == "env"


def test_seal_and_check(initialized):
    sealed = collect_named(
        load_settings(),
        PLUGIN_NAME,
        CollectContext(live=False),
        checkpoint=True,
    )
    assert sealed["ok"] is True
    assert sealed["plugin"] == PLUGIN_NAME
    assert sealed["mode"] == "fixture"
    assert KNOWN_IN_REPO_TARGET in sealed["scf_targets"]
    check = check_chain(load_settings())
    assert check["ok"] is True
    records = load_records(load_settings())
    assert records[-1].plugin == PLUGIN_NAME
    evidence = json.loads(
        (load_settings().evidence_dir / f"{records[-1].evidence_id}.json").read_text(encoding="utf-8")
    )
    assert evidence["scf_binding"]["scf_version"] == "2026.2"
    assert evidence["scf_binding"]["provenance"] == "scf-catalog"
    assert evidence["findings"][0]["scf"] == KNOWN_IN_REPO_TARGET


def test_seal_without_checkpoint_is_e_no_checkpoint(initialized):
    collect_named(
        load_settings(),
        PLUGIN_NAME,
        CollectContext(live=False),
        checkpoint=False,
    )
    with pytest.raises(BeaconError) as caught:
        check_chain(load_settings())
    assert caught.value.code == E_NO_CHECKPOINT


def test_foreign_target_is_rejected(initialized):
    result = PLUGIN.collect(CollectContext(target="IAC-01", live=False))
    assert result.ok is False
    assert result.mode == "failed"
    assert result.scf_targets == (KNOWN_IN_REPO_TARGET,)
    assert result.payload["findings"] == []
    assert result.payload["scf_binding"]["scf_id"] == ""
    assert "IAC-01" in (result.error or "")
    sealed = collect_named(
        load_settings(),
        PLUGIN_NAME,
        CollectContext(target="IAC-01", live=False),
        checkpoint=True,
    )
    assert sealed["ok"] is False
    assert sealed["scf_targets"] == [KNOWN_IN_REPO_TARGET]
    assert "IAC-01" not in sealed["scf_targets"]


def test_cli_collect_plugin(initialized):
    runner = CliRunner()
    result = runner.invoke(main, ["collect", "--plugin", PLUGIN_NAME, "--fixture"])
    assert result.exit_code == 0, result.output
    body = json.loads(result.output)
    assert body["plugin"] == PLUGIN_NAME
    assert body["ok"] is True
    check = runner.invoke(main, ["check"])
    assert check.exit_code == 0
    plugins = runner.invoke(main, ["plugins"])
    assert PLUGIN_NAME in plugins.output


def test_cli_check_still_fail_closed_after_catalog_seal(initialized):
    seal_payload(
        load_settings(),
        plugin=PLUGIN_NAME,
        mode="fixture",
        scf_targets=[KNOWN_IN_REPO_TARGET],
        payload={"n": 1},
    )
    runner = CliRunner()
    result = runner.invoke(main, ["check"])
    assert result.exit_code != 0
    assert E_NO_CHECKPOINT in result.output
