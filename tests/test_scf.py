"""SCF hub, 2026.2 offline pin, sealed scf_binding, unified collect targets."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from beacon.config import DEFAULT_SCF_API_BASE, SCF_XLSX_SHA256, load_settings
from beacon.crypto.witness import check_chain, load_records
from beacon.plugins.spec import CollectContext
from beacon.errors import E_CONTROL_MISMATCH, E_UNKNOWN_CONTROL, BeaconError
from beacon.scf.binding import (
    FORBIDDEN_FRAMEWORK_IDS,
    OVERLAY_UNMAPPED_IDS,
    PILLAR_FRAMEWORK_IDS,
    UNPINNED_VERSION,
    binding_for_control,
    binding_for_targets,
    empty_binding,
)
from beacon.scf.client import expected_version, fetch_control, list_offline_control_ids, summary
from beacon.scf.engine import collect_named, collect_target
from beacon.workspace import seed_workspace


def test_offline_summary_is_scf_2026_2(beacon_home):
    data = summary(load_settings())
    assert data["scf_version"] == "2026.2"
    assert expected_version() == "2026.2"
    assert data["total_controls"] == 1534
    assert data["total_families"] == 34
    assert data["total_evidence_requests"] == 316
    assert data["total_crosswalk_frameworks"] == 249
    assert len(data["erl_ids"]) == 316
    assert data["erl_ids"][0] == "E-GOV-01"
    assert data["erl_ids"][-1] == "E-QTS-13"
    assert {row["family_code"] for row in data["families"]} >= {"IAC", "CRY", "QTS"}
    pin = data["pin"]
    assert pin["xlsx_sha256"] == SCF_XLSX_SHA256
    assert pin["xlsx_sha256"].startswith("9e0a4df4")
    assert pin["xlsx_sha256"].endswith("6835")
    assert "usa-federal-gsa-fedramp-20x-ksi" not in pin["pillar_framework_ids"]


def test_offline_controls_include_qts_family(beacon_home):
    ids = list_offline_control_ids()
    assert "IAC-01" in ids
    assert "CRY-05" in ids
    assert "QTS-01" in ids
    assert "QTS-06.3" in ids
    assert "QTS-06.10" in ids
    assert "QTS-08" in ids
    qts = [item for item in ids if item.startswith("QTS-")]
    assert len(qts) == 34
    iac = fetch_control(load_settings(), "IAC-01")
    cry = fetch_control(load_settings(), "CRY-05")
    qts01 = fetch_control(load_settings(), "QTS-01")
    qts011 = fetch_control(load_settings(), "QTS-01.1")
    assert iac["control_id"] == "IAC-01"
    assert "Identity" in iac["title"]
    assert cry["control_id"] == "CRY-05"
    assert "Encrypt" in cry["title"] or "encrypt" in cry["title"].lower()
    assert qts01["family"] == "QTS"
    assert qts01["title"] == "Quantum Risk Governance"
    assert "E-QTS-01" in qts01["evidence_requests"]
    assert qts011["control_id"] == "QTS-01.1"


def test_scf_api_base_override(beacon_home, monkeypatch):
    monkeypatch.setenv("BEACON_SCF_API_BASE", "https://example.test/scf")
    settings = load_settings()
    assert settings.scf_api_base == "https://example.test/scf/"
    assert DEFAULT_SCF_API_BASE.startswith("https://hackidle.github.io/scf-api")


def test_invalid_control_id_rejected(beacon_home):
    with pytest.raises(BeaconError) as caught:
        fetch_control(load_settings(), "../crypto/tsa")
    assert caught.value.code == E_UNKNOWN_CONTROL


def test_offline_unknown_control_fails_closed(beacon_home):
    with pytest.raises(BeaconError) as caught:
        fetch_control(load_settings(), "GOV-01")
    assert caught.value.code == E_UNKNOWN_CONTROL


def _assert_binding_shape(binding: dict, *, pinned: bool = True) -> None:
    assert binding["scf_id"]
    assert binding["scf_ids"] == [binding["scf_id"]]
    assert binding["scf_family"]
    assert isinstance(binding["erl_ids"], list)
    assert isinstance(binding["framework_hops"], list)
    assert binding["pinned"] is pinned
    if pinned:
        assert binding["scf_version"] == "2026.2"
    else:
        assert binding["scf_version"] != "2026.2"
    assert set(binding["overlay_unmapped"]) == set(OVERLAY_UNMAPPED_IDS)
    for overlay_id in OVERLAY_UNMAPPED_IDS:
        assert binding["overlay_unmapped"][overlay_id] == []
    for hop in binding["framework_hops"]:
        assert hop["framework_id"] in PILLAR_FRAMEWORK_IDS
        assert hop["framework_id"] not in FORBIDDEN_FRAMEWORK_IDS
        if pinned:
            assert hop["provenance"] == "scf-crosswalk"
        else:
            assert hop["provenance"] == "scf-live-crosswalk"
        assert hop["framework_control_ids"]
    dumped = json.dumps(binding)
    assert "usa-federal-gsa-fedramp-20x-ksi" not in dumped


def test_iac_01_pillar_hops_from_catalog(beacon_home):
    control = fetch_control(load_settings(), "IAC-01")
    binding = binding_for_control(control)
    _assert_binding_shape(binding)
    assert binding["scf_id"] == "IAC-01"
    assert binding["scf_family"] == "IAC"
    assert binding["erl_ids"] == ["E-AST-01", "E-IAM-05", "E-IAM-12", "E-MON-11"]
    hops = {item["framework_id"]: item["framework_control_ids"] for item in binding["framework_hops"]}
    assert hops["usa-federal-gsa-fedramp-5-high"] == ["AC-01", "IA-01"]
    assert hops["general-nist-800-53-r5-2"] == ["AC-01", "IA-01"]
    assert hops["usa-federal-dow-cmmc-2-level-2"] == ["ACL2.-3.1.1"]
    assert "CC6.1" in hops["general-aicpa-tsc-2017"]


def test_qts_01_has_empty_pillar_hops_not_guessed(beacon_home):
    control = fetch_control(load_settings(), "QTS-01")
    binding = binding_for_control(control)
    _assert_binding_shape(binding)
    assert binding["scf_family"] == "QTS"
    assert binding["framework_hops"] == []
    assert "E-QTS-01" in binding["erl_ids"]


def test_collect_target_iac_01_selects_overlapping_inspectors(initialized):
    settings = load_settings()
    result = collect_target(
        settings,
        "IAC-01",
        CollectContext(target="IAC-01", live=False),
        checkpoint=True,
    )
    assert set(result["plugins"]) == {"aws.inspector", "azure.inspector", "gcp.inspector"}
    assert result["control"]["control_id"] == "IAC-01"
    assert len(result["runs"]) == 3
    _assert_binding_shape(result["scf_binding"])
    assert result["scf_binding"]["scf_id"] == "IAC-01"
    check_chain(settings)
    modes = {row.mode for row in load_records(settings)}
    assert "fixture" in modes
    evidence = next(settings.evidence_dir.glob("*.json"))
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    _assert_binding_shape(payload["scf_binding"])
    assert payload["scf_binding"]["scf_version"] == "2026.2"


def test_collect_target_cry_05_seals_results(initialized):
    result = collect_target(
        load_settings(),
        "CRY-05",
        CollectContext(target="CRY-05", live=False),
        checkpoint=True,
    )
    assert "aws.inspector" in result["plugins"]
    assert result["checkpoint"]["to_seq"] >= 3
    assert result["scf_binding"]["scf_id"] == "CRY-05"
    assert "E-CRY-01" in result["scf_binding"]["erl_ids"]
    check_chain(load_settings())


def test_collect_target_qts_01_binds_without_guessed_hops(initialized):
    result = collect_target(
        load_settings(),
        "QTS-01",
        CollectContext(target="QTS-01", live=False),
        checkpoint=True,
    )
    assert result["control"]["control_id"] == "QTS-01"
    assert result["plugins"] == []
    assert result["runs"] == []
    _assert_binding_shape(result["scf_binding"])
    assert result["scf_binding"]["framework_hops"] == []


def test_seed_seals_fixtures(initialized):
    out = seed_workspace(load_settings())
    assert out["checkpoint"]
    records = load_records(load_settings())
    assert len(records) >= 3
    assert all(row.mode == "fixture" for row in records)
    check_chain(load_settings())
    for path in load_settings().evidence_dir.glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        binding = payload["scf_binding"]
        assert binding["scf_version"] == "2026.2"
        if binding.get("scf_id") == "IAC-01":
            assert "E-CRY-01" not in binding["erl_ids"]
        if binding.get("scf_id") == "CRY-05":
            assert "E-IAM-05" not in binding["erl_ids"]
        if not binding.get("scf_id"):
            assert set(binding.get("scf_ids") or []) == {"IAC-01", "CRY-05"}
            assert "controls" in binding
            for item in binding.get("controls") or []:
                if item["scf_id"] == "IAC-01":
                    assert "E-CRY-01" not in item["erl_ids"]
                    assert item["pinned"] is True
                if item["scf_id"] == "CRY-05":
                    assert "E-IAM-05" not in item["erl_ids"]
                    assert item["pinned"] is True


def test_multi_control_binding_keeps_per_control_ids(beacon_home):
    binding = binding_for_targets(load_settings(), ["IAC-01", "CRY-05"])
    assert binding["scf_id"] == ""
    assert binding["scf_ids"] == ["IAC-01", "CRY-05"]
    assert binding["erl_ids"] == []
    assert binding["framework_hops"] == []
    assert binding["pinned"] is True
    assert [item["scf_id"] for item in binding["controls"]] == ["IAC-01", "CRY-05"]
    assert "E-CRY-01" not in binding["controls"][0]["erl_ids"]
    assert "E-IAM-05" not in binding["controls"][1]["erl_ids"]


def test_unpinned_gov_01_does_not_claim_2026_2(beacon_home):
    binding = binding_for_control(
        {
            "control_id": "GOV-01",
            "title": "Cybersecurity & Data Protection Governance Program",
            "family": "GOV",
            "scf_version": "2026.1.1",
            "evidence_requests": ["E-GOV-01"],
            "crosswalks": {"general-nist-800-53-r5-2": ["PM-1"]},
        }
    )
    _assert_binding_shape(binding, pinned=False)
    assert binding["scf_id"] == "GOV-01"
    assert binding["scf_version"] == "2026.1.1"
    assert binding["erl_ids"] == ["E-GOV-01"]
    hops = {item["framework_id"]: item["framework_control_ids"] for item in binding["framework_hops"]}
    assert hops["general-nist-800-53-r5-2"] == ["PM-1"]


def test_live_payload_cannot_stamp_pin_version(beacon_home):
    binding = binding_for_control(
        {
            "control_id": "GOV-01",
            "family": "GOV",
            "scf_version": "2026.2",
            "evidence_requests": ["E-FAKE"],
        }
    )
    assert binding["pinned"] is False
    assert binding["scf_version"] == UNPINNED_VERSION
    assert binding["erl_ids"] == ["E-FAKE"]


def test_cached_control_outside_pin_binds(beacon_home, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BEACON_SCF_OFFLINE", "0")
    settings = load_settings()
    cache = settings.cache_dir / "scf"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "GOV-01.json").write_text(
        json.dumps(
            {
                "control_id": "GOV-01",
                "title": "Governance",
                "family": "GOV",
                "scf_version": "2026.1.1",
                "evidence_requests": ["E-GOV-01"],
                "crosswalks": {},
            }
        ),
        encoding="utf-8",
    )
    control = fetch_control(settings, "GOV-01")
    binding = binding_for_control(control)
    _assert_binding_shape(binding, pinned=False)
    assert binding["scf_id"] == "GOV-01"
    assert binding["scf_version"] == "2026.1.1"
    collect = collect_target(settings, "GOV-01", CollectContext(target="GOV-01", live=False), checkpoint=False)
    assert collect["scf_binding"]["scf_id"] == "GOV-01"
    assert collect["scf_binding"]["pinned"] is False


def test_echo_plugin_collects_gov_01_without_pin_file(initialized, monkeypatch: pytest.MonkeyPatch):
    example = Path(__file__).resolve().parents[1] / "examples" / "echo_platform.py"
    monkeypatch.setenv("BEACON_PLUGIN_PATH", str(example))
    settings = load_settings()
    result = collect_named(
        settings,
        "echo",
        CollectContext(target="GOV-01", live=False),
        checkpoint=True,
    )
    assert result["ok"] is True
    binding = result["scf_binding"]
    _assert_binding_shape(binding, pinned=False)
    assert binding["scf_id"] == "GOV-01"
    assert binding["scf_version"] == UNPINNED_VERSION
    assert binding["framework_hops"] == []
    assert binding["erl_ids"] == []
    seeded = seed_workspace(settings)
    assert seeded["ok"] is True
    check_chain(settings)


def test_empty_binding_does_not_claim_pin():
    binding = empty_binding()
    assert binding["pinned"] is False
    assert binding["scf_version"] == UNPINNED_VERSION
    assert binding["scf_id"] == ""
    assert binding["scf_ids"] == []


def test_mixed_pin_and_unpinned_targets(beacon_home):
    binding = binding_for_targets(load_settings(), ["IAC-01", "GOV-01"])
    assert binding["scf_id"] == ""
    assert binding["scf_ids"] == ["IAC-01", "GOV-01"]
    assert binding["pinned"] is False
    assert binding["scf_version"] == UNPINNED_VERSION
    by_id = {item["scf_id"]: item for item in binding["controls"]}
    assert by_id["IAC-01"]["pinned"] is True
    assert by_id["IAC-01"]["scf_version"] == "2026.2"
    assert by_id["GOV-01"]["pinned"] is False
    assert by_id["GOV-01"]["scf_version"] == UNPINNED_VERSION
    assert by_id["GOV-01"]["framework_hops"] == []


def test_cache_payload_cannot_retarget_pin(beacon_home, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BEACON_SCF_OFFLINE", "0")
    settings = load_settings()
    cache = settings.cache_dir / "scf"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "GOV-01.json").write_text(
        json.dumps(
            {
                "control_id": "IAC-01",
                "family": "IAC",
                "scf_version": "2026.2",
                "evidence_requests": ["E-FAKE"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(BeaconError) as caught:
        fetch_control(settings, "GOV-01")
    assert caught.value.code == E_CONTROL_MISMATCH
    binding = binding_for_targets(settings, ["GOV-01"])
    assert binding["scf_id"] == "GOV-01"
    assert binding["pinned"] is False
    assert binding["scf_version"] == UNPINNED_VERSION
    assert binding["erl_ids"] == []
