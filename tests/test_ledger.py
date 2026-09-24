"""Offline evidence ledger and Class C/D method counts. No network."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from beacon.assurance.index import CLAIM_WORDS, ledger_method_report
from beacon.canonical import dumps
from beacon.cli import main
from beacon.config import load_settings
from beacon.crypto.witness import CHAIN_VERSION, load_records, seal_payload
from beacon.errors import E_LEDGER, E_SCOPE, E_UNKNOWN_SCOPE
from beacon.push import write_pack
from beacon.scope.document import ScopeDocument
from beacon.scope.store import init_scope

SCOPE_ID = "prod-commercial"
KSI_OK = "fixture-ksi-1"
KSI_GAP = "fixture-ksi-2"
RECORD_KEYS = {
    "v",
    "seq",
    "ts",
    "evidence_id",
    "plugin",
    "mode",
    "scf_targets",
    "payload_sha256",
    "prev_sha256",
    "recorder_pub",
    "witness_pub",
    "recorder_sig",
    "witness_sig",
}


def _invoke(args: list[str]):
    return CliRunner().invoke(main, args)


def _document() -> ScopeDocument:
    init_scope(load_settings(), SCOPE_ID)
    path = load_settings().home / "scopes" / f"{SCOPE_ID}.json"
    return ScopeDocument.model_validate_json(path.read_text(encoding="utf-8"))


def _seal(
    document: ScopeDocument,
    *,
    plugin: str,
    targets: list[str],
    tags: list[str],
    ksi_id: str,
    scf: str | None = None,
    binding: dict[str, object] | None = None,
) -> None:
    payload: dict[str, object] = {
        "source": plugin,
        "tags": tags,
        "ksi_id": ksi_id,
        "scope_id": document.scope_id,
        "scope_sha256": document.content_sha256(),
    }
    if scf is not None:
        payload["scf"] = scf
    if binding is not None:
        payload["scf_binding"] = binding
    seal_payload(
        load_settings(),
        plugin=plugin,
        mode="fixture",
        scf_targets=targets,
        payload=payload,
    )


def test_ledger_show_indexes_scope_scf_tags_and_seal(initialized: Path):
    document = _document()
    _seal(
        document,
        plugin="aws.inspector",
        targets=["IAC-02", "CRY-07"],
        tags=["evidence:cloud_inspector", "automation:automated", "control:IAC-02", "control:CRY-07"],
        ksi_id=KSI_OK,
        scf="IAC-02",
    )
    _seal(
        document,
        plugin="scf.catalog.offline",
        targets=["GOV-02"],
        tags=["evidence:catalog_pin", "automation:automated", "control:GOV-02"],
        ksi_id=KSI_OK,
        binding={"scf_id": "GOV-02", "scf_ids": ["GOV-02"]},
    )
    shown = _invoke(["ledger", "show", "--scope", SCOPE_ID])
    assert shown.exit_code == 0, shown.output
    body = json.loads(shown.output)
    assert body["scope_id"] == SCOPE_ID
    assert body["scope_sha256"] == document.content_sha256()
    assert len(body["entries"]) == 2
    by_plugin = {row["plugin"]: row for row in body["entries"]}
    inspector = by_plugin["aws.inspector"]
    assert inspector["scf_ids"] == ["IAC-02", "CRY-07"]
    assert inspector["scope_id"] == SCOPE_ID
    assert "evidence:cloud_inspector" in inspector["tags"]
    assert inspector["seal_sha256"]
    assert "payload" not in inspector
    catalog = by_plugin["scf.catalog.offline"]
    assert catalog["scf_ids"] == ["GOV-02"]
    text = shown.output
    for word in CLAIM_WORDS:
        assert word not in text
    record = load_records(load_settings())[0]
    assert record.v == CHAIN_VERSION == 1
    assert set(record.to_dict()) == RECORD_KEYS


def test_class_c_pass_and_class_d_shortfall_under_scope(initialized: Path):
    document = _document()
    _seal(
        document,
        plugin="aws.inspector",
        targets=["IAC-02"],
        tags=["evidence:cloud_inspector", "automation:automated", "control:IAC-02"],
        ksi_id=KSI_OK,
        scf="IAC-02",
    )
    _seal(
        document,
        plugin="aws.lake.logs",
        targets=["IAC-02"],
        tags=["evidence:lake_log_extract", "automation:automated", "control:IAC-02"],
        ksi_id=KSI_OK,
        scf="IAC-02",
    )
    _seal(
        document,
        plugin="echo",
        targets=["CRY-07"],
        tags=["evidence:policy", "automation:manual", "control:CRY-07"],
        ksi_id=KSI_GAP,
        scf="CRY-07",
    )
    passed = _invoke(["ledger", "summary", "--scope", SCOPE_ID, "--class", "c", "--ksi", KSI_OK, "--ksi", KSI_GAP])
    assert passed.exit_code == 0, passed.output
    report = json.loads(passed.output)
    assert report["package_class"] == "c"
    assert report["minimum"] == 2
    by_id = {row["ksi_id"]: row for row in report["counts"]}
    assert by_id[KSI_OK]["automated_method_ids"] == ["cloud_inspector", "lake_log_extract"]
    assert by_id[KSI_OK]["automated_method_count"] == 2
    assert by_id[KSI_OK]["shortfall"] == 0
    assert by_id[KSI_GAP]["manual_method_ids"] == ["policy"]
    assert by_id[KSI_GAP]["automated_method_count"] == 0
    assert by_id[KSI_GAP]["shortfall"] == 2
    assert KSI_OK not in report["below_minimum"]
    assert KSI_GAP in report["below_minimum"]
    wide = ledger_method_report(
        load_settings(),
        package_class="d",
        scope_id=SCOPE_ID,
        required_ksi_ids=(KSI_OK,),
    )
    assert wide.minimum == 4
    assert wide.counts[0].automated_method_count == 2
    assert wide.counts[0].shortfall == 2
    for word in CLAIM_WORDS:
        assert word not in passed.output
        assert word not in json.dumps(wide.model_dump(mode="json"))


def test_duplicate_method_counts_once_and_class_d_pass(initialized: Path):
    document = _document()
    methods = (
        ("aws.inspector", "cloud_inspector", "IAC-02"),
        ("aws.lake.logs", "lake_log_extract", "IAC-02"),
        ("scf.catalog.offline", "catalog_pin", "GOV-02"),
        ("echo", "drop_in", "CRY-07"),
    )
    for plugin, method, scf in methods:
        _seal(
            document,
            plugin=plugin,
            targets=[scf],
            tags=[f"evidence:{method}", "automation:automated", f"control:{scf}"],
            ksi_id=KSI_OK,
            scf=scf,
        )
    _seal(
        document,
        plugin="aws.inspector",
        targets=["IAC-02"],
        tags=["evidence:cloud_inspector", "automation:automated", "control:IAC-02"],
        ksi_id=KSI_OK,
        scf="IAC-02",
    )
    report = ledger_method_report(load_settings(), package_class="d", scope_id=SCOPE_ID)
    assert report.counts[0].automated_method_count == 4
    assert report.counts[0].shortfall == 0
    assert report.counts[0].automated_method_ids == (
        "cloud_inspector",
        "lake_log_extract",
        "catalog_pin",
        "drop_in",
    )


def test_unknown_registry_value_fails_closed(initialized: Path):
    document = _document()
    _seal(
        document,
        plugin="aws.inspector",
        targets=["IAC-02"],
        tags=["evidence:not_a_method", "automation:automated", "control:IAC-02"],
        ksi_id=KSI_OK,
        scf="IAC-02",
    )
    unknown = _invoke(["ledger", "show", "--scope", SCOPE_ID])
    assert unknown.exit_code == 2
    assert E_LEDGER in unknown.output
    records = load_records(load_settings())
    assert records[0].v == 1


def test_unknown_control_tag_fails_closed(initialized: Path):
    document = _document()
    payload = {
        "source": "aws.inspector",
        "scf": "IAC-02",
        "tags": ["evidence:cloud_inspector", "automation:automated", "control:IAC-01"],
        "ksi_id": KSI_OK,
        "scope_id": document.scope_id,
        "scope_sha256": document.content_sha256(),
    }
    seal_payload(
        load_settings(),
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["IAC-02"],
        payload=payload,
    )
    refused = _invoke(["ledger", "summary", "--scope", SCOPE_ID, "--class", "c"])
    assert refused.exit_code == 2
    assert E_LEDGER in refused.output
    assert "unknown control tag" in refused.output
    shown = load_records(load_settings())
    assert shown[0].v == 1


def test_scope_hash_mismatch_and_missing_scope_fail_closed(initialized: Path):
    document = _document()
    _seal(
        document,
        plugin="aws.inspector",
        targets=["CRY-07"],
        tags=["evidence:cloud_inspector", "automation:automated", "control:CRY-07"],
        ksi_id=KSI_OK,
        scf="CRY-07",
    )
    path = load_settings().home / "scopes" / f"{SCOPE_ID}.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    body["data_classes"] = ["security-log"]
    path.write_bytes(dumps(body) + b"\n")
    mismatched = _invoke(["ledger", "show", "--scope", SCOPE_ID])
    assert mismatched.exit_code == 2
    assert E_SCOPE in mismatched.output
    path.unlink()
    missing = _invoke(["ledger", "summary", "--scope", SCOPE_ID, "--class", "c"])
    assert missing.exit_code == 2
    assert E_UNKNOWN_SCOPE in missing.output


def test_pack_summary_matches_chain(initialized: Path):
    document = _document()
    _seal(
        document,
        plugin="aws.inspector",
        targets=["GOV-02"],
        tags=["evidence:cloud_inspector", "automation:automated", "control:GOV-02"],
        ksi_id=KSI_OK,
        binding={"scf_id": "GOV-02", "scf_ids": ["GOV-02"]},
    )
    _seal(
        document,
        plugin="aws.lake.logs",
        targets=["GOV-02"],
        tags=["evidence:lake_log_extract", "automation:automated", "control:GOV-02"],
        ksi_id=KSI_OK,
        scf="GOV-02",
    )
    pack = write_pack(load_settings(), initialized / "pack.json")
    from_pack = _invoke(
        ["ledger", "summary", "--pack", str(pack.path), "--scope", SCOPE_ID, "--class", "c", "--scf", "GOV-02"]
    )
    assert from_pack.exit_code == 0, from_pack.output
    report = json.loads(from_pack.output)
    assert report["counts"][0]["automated_method_count"] == 2
    assert report["counts"][0]["shortfall"] == 0
    assert report["counts"][0]["ksi_id"] == KSI_OK
