"""Advisory ingest keeps model checks unverified."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from beacon.advisory_ingest import SCHEMA_CICD, ingest_advisory
from beacon.canonical import sha256_bytes
from beacon.cli import main
from beacon.config import load_settings
from beacon.crypto.witness import check_chain, load_records
from beacon.errors import BeaconError

EXPORT_ROOT = "/opt/ai-gate-ledger"
FORBIDDEN = re.compile(r"\b(?:met|pass|satisfied|compliant|evidenced|proven)\b", re.IGNORECASE)
VERIFY_OK = """import json, sys
print(json.dumps({"ok": True, "failures": []}))
sys.exit(0)
"""
VERIFY_BAD = """import json, sys
print(json.dumps({"ok": False, "failures": ["tampered"]}))
sys.exit(1)
"""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _verdict(
    run_id: str = "run-1",
    *,
    flag: bool | None = False,
    held: str | None = None,
    scf: dict | None = None,
    check: str = "quiz_support",
) -> dict:
    row = {
        "unit": "q1",
        "check": check,
        "engine": "haiku",
        "model_id": "claude-haiku-5-5",
        "content_hash": "ab" * 32,
        "flag": flag,
        "held": held,
        "ts": "2026-10-07T00:00:00+00:00",
        "run_id": run_id,
        "receipt_status": "verified",
    }
    if scf:
        row.update(scf)
    return row


def _build(
    tmp_path: Path,
    *,
    verify_ok: bool = True,
    verdicts: list[dict] | None = None,
    subject_scf: dict | None = None,
    schema: str = "ai-gate-ledger/beacon-advisory@2",
    advisory: bool = True,
    evidence_class: str = "advisory",
    ledger_verify: str = "FAIL",
    receipt_tamper: bool = False,
    head_tamper: bool = False,
    outside_receipt: bool = False,
    cicd: list[dict] | str | None = None,
) -> tuple[Path, Path, Path | None]:
    root = tmp_path / "ledger"
    (root / "ledger").mkdir(parents=True)
    (root / "flags").mkdir()
    (root / "receipts").mkdir()
    ledger_line = b'{"type":"run","n":1}'
    flags_line = b'{"type":"flag","n":1}'
    (root / "ledger" / "2026-10.jsonl").write_bytes(ledger_line + b"\n")
    (root / "flags" / "flags.jsonl").write_bytes(flags_line + b"\n")
    receipt_body = b'{"run_id":"run-1"}\n'
    receipt_path = root / "receipts" / "run-1.json"
    receipt_path.write_bytes(receipt_body)
    if head_tamper:
        (root / "ledger" / "2026-10.jsonl").write_bytes(ledger_line + b'\n{"type":"run","n":2}\n')
    if receipt_tamper:
        receipt_path.write_bytes(receipt_body + b"x")
    (root / "verify.py").write_text(VERIFY_OK if verify_ok else VERIFY_BAD, encoding="utf-8")
    recorded = "/etc/passwd" if outside_receipt else f"{EXPORT_ROOT}/receipts/run-1.json"
    subject: dict = {
        "source": "proofyard",
        "subject": "demo-subject",
        "flags_open": 0,
        "verdicts": verdicts if verdicts is not None else [_verdict()],
    }
    if subject_scf:
        subject.update(subject_scf)
    export = {
        "schema": schema,
        "generated": "2026-10-07T01:02:03+00:00",
        "evidence_class": evidence_class,
        "advisory": advisory,
        "ledger_root": EXPORT_ROOT,
        "ledger_heads": {
            "ledger/2026-10.jsonl": _sha(ledger_line),
            "flags/flags.jsonl": _sha(flags_line),
        },
        "ledger_verify": ledger_verify,
        "receipts": {
            "run-1": {
                "source": "proofyard",
                "started": "2026-10-07T00:00:00+00:00",
                "ended": "2026-10-07T00:00:01+00:00",
                "path": recorded,
                "sha256": _sha(receipt_body),
                "status": "verified",
            }
        },
        "subjects": [subject],
    }
    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps(export), encoding="utf-8")
    cicd_path = None
    if cicd is not None:
        cicd_path = tmp_path / "cicd.jsonl"
        if cicd == "empty":
            cicd_path.write_bytes(b"")
        else:
            cicd_path.write_text("".join(json.dumps(row) + "\n" for row in cicd), encoding="utf-8")
    return export_path, root, cicd_path


def _ingest(export: Path, root: Path, cicd: Path | None = None, *, dry_run: bool = False) -> dict:
    return ingest_advisory(
        load_settings(),
        export_file=export,
        ledger_root=root,
        cicd_file=cicd,
        dry_run=dry_run,
    )


def _assert_clean(body: object) -> None:
    assert FORBIDDEN.search(json.dumps(body)) is None


def test_happy_path_writes_unverified_receipts(initialized: Path, tmp_path: Path):
    export, root, _cicd = _build(
        tmp_path,
        ledger_verify="FAIL",
        subject_scf={"scf_version": "2026.3", "scf_id": "IAC-02", "legacy_scf": "IAC-01"},
    )
    result = _ingest(export, root)
    _assert_clean(result)
    assert result["dry_run"] is False
    assert result["claim_status"] == "unverified"
    assert result["control_satisfied"] is False
    assert result["assurance_claim"] is False
    assert result["evidence_class"] == "advisory"
    assert result["runs"] == 1
    assert result["verdicts"] == 1
    assert result["advisory_observed"] == 1
    assert result["needs_review"] == 0
    assert result["mapped"] == 1
    assert result["unmapped"] == 0
    receipt = result["receipts"][0]
    assert receipt["kind"] == "model_advisory"
    assert receipt["schema_version"] == 1
    assert receipt["ledger_integrity"] == "verified"
    assert "receipt_status" not in receipt
    row = receipt["verdicts"][0]
    assert row["disposition"] == "advisory_observed"
    assert row["mapping"] == "mapped"
    assert row["scf_id"] == "IAC-02"
    assert row["scf_version"] == "2026.3"
    assert row["legacy_scf"] == "IAC-01"
    assert row["ledger_integrity"] == "verified"
    stored = initialized / "evidence" / "advisory" / "2026-10-07" / "run-1.json"
    assert sha256_bytes(stored.read_bytes()) == result["witness"]["receipts"][0]["sha256"]
    assert result["receipts"][0]["receipt_sha256"] == sha256_bytes((root / "receipts" / "run-1.json").read_bytes())
    records = load_records(load_settings())
    assert len(records) == 1
    assert records[0].plugin == "beacon.advisory-ingest"
    assert records[0].mode == "advisory"
    assert records[0].scf_targets == ["IAC-02"]
    witness = json.loads((initialized / "evidence" / f"{records[0].evidence_id}.json").read_bytes())
    assert witness["receipts"][0]["relpath"] == "advisory/2026-10-07/run-1.json"
    assert witness["control_satisfied"] is False
    assert witness["assurance_claim"] is False
    assert check_chain(load_settings())["ok"] is True
    _assert_clean(witness)


@pytest.mark.parametrize(
    ("schema", "advisory", "evidence_class"),
    [
        ("ai-gate-ledger/beacon-advisory@1", True, "advisory"),
        ("ai-gate-ledger/beacon-advisory@2", False, "advisory"),
        ("ai-gate-ledger/beacon-advisory@2", True, "finding"),
    ],
)
def test_wrong_schema_writes_nothing(beacon_home: Path, tmp_path: Path, schema: str, advisory: bool, evidence_class: str):
    export, root, _cicd = _build(tmp_path, schema=schema, advisory=advisory, evidence_class=evidence_class)
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root)
    assert caught.value.code == "E_ADVISORY"
    assert not (beacon_home / "evidence" / "advisory").exists()


def test_verify_failure_writes_nothing(beacon_home: Path, tmp_path: Path):
    export, root, _cicd = _build(tmp_path, verify_ok=False, ledger_verify="OK")
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root)
    assert caught.value.code == "E_ADVISORY"
    assert "not OK" in caught.value.message
    assert not (beacon_home / "evidence").exists()


def test_tampered_receipt_writes_nothing(beacon_home: Path, tmp_path: Path):
    export, root, _cicd = _build(tmp_path, receipt_tamper=True)
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root)
    assert "receipt sha256 mismatch" in caught.value.message
    assert not (beacon_home / "evidence").exists()


def test_tampered_ledger_head_writes_nothing(beacon_home: Path, tmp_path: Path):
    export, root, _cicd = _build(tmp_path, head_tamper=True)
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root)
    assert "ledger head sha256 mismatch" in caught.value.message
    assert not (beacon_home / "evidence").exists()


def test_outside_receipt_path_writes_nothing(beacon_home: Path, tmp_path: Path):
    export, root, _cicd = _build(tmp_path, outside_receipt=True)
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root)
    assert "outside" in caught.value.message
    assert not (beacon_home / "evidence").exists()


def test_held_string_needs_review(tmp_path: Path):
    export, root, _cicd = _build(tmp_path, verdicts=[_verdict(flag=False, held="model withheld the score")])
    result = _ingest(export, root, dry_run=True)
    row = result["receipts"][0]["verdicts"][0]
    assert row["disposition"] == "needs_review"
    assert row["held"] == "model withheld the score"
    assert result["needs_review"] == 1
    assert result["advisory_observed"] == 0
    _assert_clean(result)


def test_flag_needs_review(tmp_path: Path):
    export, root, _cicd = _build(tmp_path, verdicts=[_verdict(flag=True, held=None)])
    result = _ingest(export, root, dry_run=True)
    row = result["receipts"][0]["verdicts"][0]
    assert row["flag"] is True
    assert row["disposition"] == "needs_review"
    assert result["needs_review"] == 1
    _assert_clean(result)


def test_unknown_scf_id_dropped(tmp_path: Path):
    export, root, _cicd = _build(
        tmp_path,
        verdicts=[
            _verdict(
                scf={"scf_version": "2026.3", "scf_id": "NO-SUCH-01", "legacy_scf": "OLD-1"},
            ),
            _verdict(check="other-check", scf={"legacy_scf": "IAC-02"}),
        ],
    )
    result = _ingest(export, root, dry_run=True)
    rows = result["receipts"][0]["verdicts"]
    assert rows[0]["mapping"] == "unmapped"
    assert "scf_id" not in rows[0]
    assert "legacy_scf" not in rows[0]
    assert rows[0]["scf_drop_reason"] == "scf_id not in pinned SCF 2026.3 catalog"
    assert rows[1]["mapping"] == "unmapped"
    assert "scf_id" not in rows[1]
    assert rows[1]["scf_drop_reason"] == "scf_id absent"
    assert result["unmapped"] == 2
    assert result["mapped"] == 0
    assert "NO-SUCH-01" not in json.dumps(result)
    _assert_clean(result)


def test_no_claim_word_in_output(tmp_path: Path):
    export, root, _cicd = _build(
        tmp_path,
        verdicts=[
            _verdict(flag=True),
            _verdict(check="other-check", flag=False, held="model withheld the score"),
        ],
        subject_scf={"scf_version": "2026.3", "scf_id": "CRY-07"},
    )
    result = _ingest(export, root, dry_run=True)
    _assert_clean(result)
    text = json.dumps(result)
    assert "needs_review" in text
    assert "advisory_observed" in text
    assert "unverified" in text


def test_dry_run_writes_nothing(initialized: Path, tmp_path: Path):
    export, root, _cicd = _build(tmp_path)
    before = sorted(path.relative_to(initialized).as_posix() for path in initialized.rglob("*") if path.is_file())
    result = _ingest(export, root, dry_run=True)
    after = sorted(path.relative_to(initialized).as_posix() for path in initialized.rglob("*") if path.is_file())
    assert result["dry_run"] is True
    assert result["runs"] == 1
    assert "advisory/2026-10-07/run-1.json" in result["paths"]
    assert before == after
    assert load_records(load_settings()) == []
    assert not (initialized / "evidence" / "advisory").exists()


def test_cli_dry_run(initialized: Path, tmp_path: Path):
    export, root, _cicd = _build(tmp_path)
    result = CliRunner().invoke(
        main,
        ["advisory-ingest", "--file", str(export), "--ledger-root", str(root), "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    body = json.loads(result.output)
    assert body["claim_status"] == "unverified"
    assert body["control_satisfied"] is False
    _assert_clean(body)
    assert not (initialized / "evidence" / "advisory").exists()


def _cicd_row(root: Path, *, derived: list[str], match: bool = True, present: bool = True) -> dict:
    body = b'{"gate":"s06"}\n'
    dest = root / "ci" / "gate.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if present:
        dest.write_bytes(body)
    digest = _sha(body if match else body + b"no")
    path = f"{EXPORT_ROOT}/ci/gate.json" if present else f"{EXPORT_ROOT}/ci/missing.json"
    return {
        "schema": SCHEMA_CICD,
        "gate": "s06_iam",
        "scf": "IAC-02",
        "scf_version": "2026.3",
        "derived": derived,
        "ksi": "KSI-CNA",
        "receipt": {"path": path, "sha256": digest, "run_id": "ci-1"},
        "status": "verified",
        "evidence_class": "advisory",
    }


def test_cicd_zero_rows(tmp_path: Path):
    export, root, cicd = _build(tmp_path, cicd="empty")
    assert cicd is not None
    result = _ingest(export, root, cicd, dry_run=True)
    assert result["cicd_rows"] == 0
    assert result["cicd_verified"] == 0
    assert result["cicd"]["rows"] == []
    _assert_clean(result)


def test_cicd_verified_when_hash_matches(tmp_path: Path):
    export, root, _cicd = _build(tmp_path)
    row = _cicd_row(root, derived=["AC-6", "AC-02(01)"])
    cicd = tmp_path / "cicd.jsonl"
    cicd.write_text(json.dumps(row) + "\n", encoding="utf-8")
    result = _ingest(export, root, cicd, dry_run=True)
    mapped = result["cicd"]["rows"][0]
    assert mapped["ledger_integrity"] == "verified"
    assert mapped["derived"] == ["AC-6", "AC-02(01)"]
    assert mapped["scf_id"] == "IAC-02"
    assert mapped["mapping"] == "mapped"
    assert "status" not in mapped
    _assert_clean(result)


def test_cicd_unverified_when_hash_mismatches(tmp_path: Path):
    export, root, _cicd = _build(tmp_path)
    row = _cicd_row(root, derived=["AC-6"], match=False)
    cicd = tmp_path / "cicd.jsonl"
    cicd.write_text(json.dumps(row) + "\n", encoding="utf-8")
    result = _ingest(export, root, cicd, dry_run=True)
    assert result["cicd"]["rows"][0]["ledger_integrity"] == "unverified"
    assert result["cicd_verified"] == 0


def test_cicd_bad_derived_writes_nothing(beacon_home: Path, tmp_path: Path):
    export, root, _cicd = _build(tmp_path)
    row = _cicd_row(root, derived=["not-a-control"])
    cicd = tmp_path / "cicd.jsonl"
    cicd.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root, cicd)
    assert "800-53" in caught.value.message
    assert not (beacon_home / "evidence").exists()


def test_repeat_ingest_keeps_bytes_and_chain(initialized: Path, tmp_path: Path):
    export, root, _cicd = _build(tmp_path)
    first = _ingest(export, root)
    stored = initialized / "evidence" / "advisory" / "2026-10-07" / "run-1.json"
    digest = sha256_bytes(stored.read_bytes())
    second = _ingest(export, root)
    assert sha256_bytes(stored.read_bytes()) == digest
    assert first["witness"]["receipts"][0]["sha256"] == second["witness"]["receipts"][0]["sha256"]
    assert len(load_records(load_settings())) == 2
    assert check_chain(load_settings())["ok"] is True


def test_changed_rerun_does_not_overwrite(initialized: Path, tmp_path: Path):
    export, root, _cicd = _build(tmp_path)
    _ingest(export, root)
    stored = initialized / "evidence" / "advisory" / "2026-10-07" / "run-1.json"
    digest = sha256_bytes(stored.read_bytes())
    payload = json.loads(export.read_text(encoding="utf-8"))
    payload["subjects"][0]["verdicts"][0]["check"] = "other_check"
    export.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root)
    assert "different digest" in caught.value.message
    assert sha256_bytes(stored.read_bytes()) == digest
    assert len(load_records(load_settings())) == 1


def test_reserved_run_id_rejected(tmp_path: Path):
    export, root, _cicd = _build(tmp_path)
    payload = json.loads(export.read_text(encoding="utf-8"))
    payload["receipts"]["cicd"] = payload["receipts"].pop("run-1")
    payload["subjects"][0]["verdicts"][0]["run_id"] = "cicd"
    export.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root, dry_run=True)
    assert "safe file name" in caught.value.message


def test_subject_source_must_match_run(tmp_path: Path):
    export, root, _cicd = _build(tmp_path)
    payload = json.loads(export.read_text(encoding="utf-8"))
    payload["subjects"][0]["source"] = "other-source"
    export.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root, dry_run=True)
    assert "source does not match" in caught.value.message


def test_blank_held_rejected(tmp_path: Path):
    export, root, _cicd = _build(tmp_path, verdicts=[_verdict(held="")])
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root, dry_run=True)
    assert "held must be a reason string" in caught.value.message


def test_verify_failures_list_rejects(tmp_path: Path):
    export, root, _cicd = _build(tmp_path)
    (root / "verify.py").write_text(
        "import json, sys\nprint(json.dumps({'ok': True, 'failures': ['tampered']}))\nsys.exit(0)\n",
        encoding="utf-8",
    )
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root, dry_run=True)
    assert "not OK" in caught.value.message


def test_verify_symlink_outside_root_rejected(tmp_path: Path):
    export, root, _cicd = _build(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text(VERIFY_OK, encoding="utf-8")
    script = root / "verify.py"
    script.unlink()
    script.symlink_to(outside)
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root, dry_run=True)
    assert "verify.py" in caught.value.message


def test_require_scope_rejects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BEACON_REQUIRE_SCOPE", "1")
    export, root, _cicd = _build(tmp_path)
    with pytest.raises(BeaconError) as caught:
        _ingest(export, root, dry_run=True)
    assert caught.value.code == "E_SCOPE"
