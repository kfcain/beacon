"""SCF hub, offline bundle, API base override, unified collect targets."""

from __future__ import annotations

import json

import pytest

from beacon.config import DEFAULT_SCF_API_BASE, load_settings
from beacon.crypto.witness import check_chain, load_records
from beacon.plugins.spec import CollectContext
from beacon.errors import E_UNKNOWN_CONTROL, BeaconError
from beacon.scf.catalog_pin import vendored_catalog_dir
from beacon.scf.client import expected_version, fetch_control, summary
from beacon.scf.engine import collect_target
from beacon.workspace import seed_workspace, system_status


def test_offline_summary_is_seed_index_for_2026_3(beacon_home):
    data = summary(load_settings())
    assert data["role"] == "offline-seed-index"
    assert data["catalog_pin_version"] == "2026.3"
    assert "scf_version" not in data
    assert data["offline_controls"] == ["IAC-02", "CRY-07"]
    assert data["seed_control_count"] == 2
    assert "total_controls" not in data
    assert "total_families" not in data
    assert "https://hackidle.github.io" not in data["source"]
    assert "2026.3" in data["source"]
    pin = json.loads((vendored_catalog_dir() / "families.json").read_text(encoding="utf-8"))
    pin_counts = {
        row["family_code"]: row["control_count"]
        for row in pin["families"]
        if row["family_code"] in {"CRY", "IAC"}
    }
    seed_counts = {row["family_code"]: row["control_count"] for row in data["families"]}
    assert seed_counts == pin_counts == {"CRY": 27, "IAC": 123}
    assert expected_version() == "2026.1.1"
    status = system_status(load_settings())
    assert status["scf_offline"] is True
    assert status["scf_version"] == "2026.1.1"


def test_offline_controls_iac_01_and_cry_05(beacon_home):
    iac = fetch_control(load_settings(), "IAC-02")
    cry = fetch_control(load_settings(), "CRY-07")
    assert iac["control_id"] == "IAC-02"
    assert "Identity" in iac["title"]
    assert cry["control_id"] == "CRY-07"
    assert "Encrypt" in cry["title"] or "encrypt" in cry["title"].lower()


def test_scf_api_base_override(beacon_home, monkeypatch):
    monkeypatch.setenv("BEACON_SCF_API_BASE", "https://example.test/scf")
    settings = load_settings()
    assert settings.scf_api_base == "https://example.test/scf/"
    assert DEFAULT_SCF_API_BASE.startswith("https://hackidle.github.io/scf-api")


def test_invalid_control_id_rejected(beacon_home):
    with pytest.raises(BeaconError) as caught:
        fetch_control(load_settings(), "../crypto/tsa")
    assert caught.value.code == E_UNKNOWN_CONTROL


def test_collect_target_iac_01_selects_overlapping_inspectors(initialized):
    result = collect_target(
        load_settings(),
        "IAC-02",
        CollectContext(target="IAC-02", live=False),
        checkpoint=True,
    )
    assert set(result["plugins"]) == {
        "aws.inspector",
        "aws.lake.logs",
        "azure.inspector",
        "gcp.inspector",
    }
    assert result["control"]["control_id"] == "IAC-02"
    assert len(result["runs"]) == 4
    check_chain(load_settings())
    modes = {row.mode for row in load_records(load_settings())}
    assert "fixture" in modes


def test_collect_target_cry_05_seals_results(initialized):
    result = collect_target(
        load_settings(),
        "CRY-07",
        CollectContext(target="CRY-07", live=False),
        checkpoint=True,
    )
    assert "aws.inspector" in result["plugins"]
    assert result["checkpoint"]["to_seq"] >= 3
    check_chain(load_settings())


def test_seed_seals_fixtures(initialized):
    out = seed_workspace(load_settings())
    assert out["checkpoint"]
    records = load_records(load_settings())
    assert len(records) >= 3
    assert all(row.mode == "fixture" for row in records)
    check_chain(load_settings())
