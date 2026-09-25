"""Phase 2 scope bind: collect, check, and push."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from beacon.canonical import dumps
from beacon.cli import main
from beacon.config import load_settings
from beacon.crypto.witness import CHAIN_VERSION, check_chain, create_checkpoint, load_records, seal_payload
from beacon.errors import E_SCOPE, E_UNKNOWN_SCOPE, E_UNSAFE_SCOPE_ID
from beacon.plugins.spec import CollectContext
from beacon.push import write_pack
from beacon.scope.document import ScopeDocument
from beacon.scope.store import init_scope
from beacon.scf.engine import collect_named

SAFE_ID = "prod-commercial"
OTHER_ID = "prod-gov"
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


def _scope_file(home: Path, scope_id: str) -> Path:
    return home / "scopes" / f"{scope_id}.json"


def _payload(home: Path, evidence_id: str) -> dict:
    path = home / "evidence" / f"{evidence_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _widen_scope(path: Path) -> None:
    body = json.loads(path.read_text(encoding="utf-8"))
    body["data_classes"] = ["security-log"]
    path.write_bytes(dumps(body) + b"\n")


def test_collect_binds_scope_and_keeps_record_v1(initialized: Path):
    init_scope(load_settings(), SAFE_ID)
    document = ScopeDocument.model_validate_json(_scope_file(initialized, SAFE_ID).read_text(encoding="utf-8"))
    result = _invoke(
        ["collect", "--plugin", "aws.inspector", "--fixture", "--scope", SAFE_ID]
    )
    assert result.exit_code == 0, result.output
    records = load_records(load_settings())
    assert len(records) == 1
    record = records[0]
    assert record.v == CHAIN_VERSION == 1
    assert set(record.to_dict()) == RECORD_KEYS
    assert "scope_id" not in record.to_dict()
    payload = _payload(initialized, record.evidence_id)
    assert payload["scope_id"] == SAFE_ID
    assert payload["scope_sha256"] == document.content_sha256()
    assert "IAC-02" in record.scf_targets
    check = _invoke(["check", "--scope", SAFE_ID])
    assert check.exit_code == 0, check.output
    check_chain(load_settings())


def test_collect_target_iac02_binds_each_payload(initialized: Path):
    init_scope(load_settings(), SAFE_ID)
    digest = ScopeDocument.model_validate_json(
        _scope_file(initialized, SAFE_ID).read_text(encoding="utf-8")
    ).content_sha256()
    result = _invoke(["collect", "--target", "IAC-02", "--fixture", "--scope", SAFE_ID])
    assert result.exit_code == 0, result.output
    records = load_records(load_settings())
    assert records
    assert all(row.v == 1 for row in records)
    for record in records:
        payload = _payload(initialized, record.evidence_id)
        assert payload["scope_id"] == SAFE_ID
        assert payload["scope_sha256"] == digest
        assert "IAC-02" in record.scf_targets


def test_collect_without_scope_keeps_current_payload(initialized: Path):
    result = _invoke(["collect", "--plugin", "scf.catalog.offline", "--fixture"])
    assert result.exit_code == 0, result.output
    record = load_records(load_settings())[-1]
    payload = _payload(initialized, record.evidence_id)
    assert "scope_id" not in payload
    assert "scope_sha256" not in payload
    assert "GOV-02" in record.scf_targets
    check = _invoke(["check"])
    assert check.exit_code == 0, check.output


def test_check_fails_closed_on_hash_mismatch_and_missing_file(initialized: Path):
    init_scope(load_settings(), SAFE_ID)
    collected = _invoke(["collect", "--plugin", "aws.inspector", "--fixture", "--scope", SAFE_ID])
    assert collected.exit_code == 0, collected.output
    path = _scope_file(initialized, SAFE_ID)
    _widen_scope(path)
    mismatched = _invoke(["check"])
    assert mismatched.exit_code == 2
    assert E_SCOPE in mismatched.output
    named = _invoke(["check", "--scope", SAFE_ID])
    assert named.exit_code == 2
    assert E_SCOPE in named.output
    path.unlink()
    missing = _invoke(["check"])
    assert missing.exit_code == 2
    assert E_UNKNOWN_SCOPE in missing.output


def test_prebind_records_keep_current_check_rules(initialized: Path):
    settings = load_settings()
    seal_payload(
        settings,
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["IAC-02", "CRY-07"],
        payload={"control": "IAC-02"},
    )
    create_checkpoint(settings)
    assert _invoke(["check"]).exit_code == 0
    init_scope(settings, SAFE_ID)
    assert _invoke(["check", "--scope", SAFE_ID]).exit_code == 0
    _scope_file(initialized, SAFE_ID).unlink()
    missing_flag = _invoke(["check", "--scope", SAFE_ID])
    assert missing_flag.exit_code == 2
    assert E_UNKNOWN_SCOPE in missing_flag.output
    assert _invoke(["check"]).exit_code == 0


def test_partial_scope_pair_fails_closed(initialized: Path):
    settings = load_settings()
    seal_payload(
        settings,
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["CRY-07"],
        payload={"scope_id": SAFE_ID, "control": "CRY-07"},
    )
    create_checkpoint(settings)
    result = _invoke(["check"])
    assert result.exit_code == 2
    assert E_SCOPE in result.output


def test_collect_missing_scope_does_not_seal(initialized: Path):
    result = _invoke(["collect", "--plugin", "aws.inspector", "--fixture", "--scope", "missing-scope"])
    assert result.exit_code == 2
    assert E_UNKNOWN_SCOPE in result.output
    assert load_records(load_settings()) == []
    unsafe = _invoke(["collect", "--target", "IAC-02", "--fixture", "--scope", "../escape"])
    assert unsafe.exit_code == 2
    assert E_UNSAFE_SCOPE_ID in unsafe.output
    assert load_records(load_settings()) == []


def test_push_copies_pair_and_does_not_rewrite_a_different_scope(initialized: Path):
    settings = load_settings()
    first = init_scope(settings, SAFE_ID)
    second = init_scope(settings, OTHER_ID)
    collect_named(
        settings,
        "aws.inspector",
        CollectContext(live=False, target="IAC-02"),
        scope_id=SAFE_ID,
    )
    collect_named(
        settings,
        "scf.catalog.offline",
        CollectContext(live=False),
        scope_id=OTHER_ID,
    )
    written = write_pack(settings, initialized / "export" / "mixed.json")
    pack = json.loads(written.path.read_text(encoding="utf-8"))
    assert "scope_id" not in pack
    assert "scope_sha256" not in pack
    pairs = {(row["scope_id"], row["scope_sha256"]) for row in pack["evidence"]}
    assert pairs == {
        (SAFE_ID, first.content_sha256()),
        (OTHER_ID, second.content_sha256()),
    }
    for row in pack["evidence"]:
        body = json.loads(row["payload"])
        assert body["scope_id"] == row["scope_id"]
        assert body["scope_sha256"] == row["scope_sha256"]
    for record in pack["records"]:
        assert record["v"] == 1
        assert "scope_id" not in record
        assert "scope_sha256" not in record


def test_push_keeps_scope_on_rows_when_some_records_are_unbound(initialized: Path):
    settings = load_settings()
    document = init_scope(settings, SAFE_ID)
    seal_payload(
        settings,
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["IAC-02"],
        payload={"control": "IAC-02"},
    )
    collect_named(settings, "aws.inspector", CollectContext(live=False), scope_id=SAFE_ID)
    written = write_pack(settings, initialized / "export" / "one.json")
    pack = json.loads(written.path.read_text(encoding="utf-8"))
    assert "scope_id" not in pack
    assert "scope_sha256" not in pack
    unbound = [row for row in pack["evidence"] if "scope_id" not in row]
    bound = [row for row in pack["evidence"] if "scope_id" in row]
    assert len(unbound) == 1
    assert len(bound) == 1
    assert bound[0]["scope_sha256"] == document.content_sha256()


def test_require_scope_fails_closed_without_flag(initialized: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BEACON_REQUIRE_SCOPE", "1")
    init_scope(load_settings(), SAFE_ID)
    missing = _invoke(["collect", "--plugin", "aws.inspector", "--fixture"])
    assert missing.exit_code == 2
    assert E_SCOPE in missing.output
    assert "BEACON_REQUIRE_SCOPE" in missing.output
    assert load_records(load_settings()) == []
    bare_check = _invoke(["check"])
    assert bare_check.exit_code == 2
    assert E_SCOPE in bare_check.output
    bound = _invoke(["collect", "--plugin", "aws.inspector", "--fixture", "--scope", SAFE_ID])
    assert bound.exit_code == 0, bound.output
    checked = _invoke(["check", "--scope", SAFE_ID])
    assert checked.exit_code == 0, checked.output
