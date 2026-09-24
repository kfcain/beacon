"""Local trust-center export, SCN draft, and inbox intake. No network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from beacon.assurance.inbox import intake_inbox_file
from beacon.assurance.scn import draft_scn
from beacon.assurance.trust_center import classify_relative, publish_bytes, publish_ledger_summary
from beacon.cli import main
from beacon.config import load_settings
from beacon.crypto.witness import CHAIN_VERSION
from beacon.errors import BeaconError

CLAIM_WORDS = ("compliant", "evidenced", "proven", "Implemented")
POINTER = "ab" * 32


def _settings(monkeypatch: pytest.MonkeyPatch, enabled: bool):
    if enabled:
        monkeypatch.setenv("BEACON_TRUST_CENTER_EXPORT", "1")
    else:
        monkeypatch.delenv("BEACON_TRUST_CENTER_EXPORT", raising=False)
    return load_settings()


def test_trust_publish_is_local_and_allowlisted(initialized: Path, monkeypatch: pytest.MonkeyPatch):
    settings = _settings(monkeypatch, True)
    out = initialized / "export" / "trust-center"
    body = json.dumps(
        {
            "format": "beacon-20x-draft/v1",
            "evidence": [{"sha256": POINTER, "payload": {"raw": True}}],
            "control_refs": ["IAC-02", "CRY-07"],
        }
    ).encode()
    record = publish_bytes(
        settings,
        relative="packs/cpo/v1/beacon-pack.json",
        body=body,
        out_dir=out,
    )
    written = json.loads(Path(record.path).read_text(encoding="utf-8"))
    assert record.hosted is False
    assert record.trust_center is True
    assert record.record_v == 1
    assert CHAIN_VERSION == 1
    assert written["trust_center"] is True
    assert written["evidence"] == [{"sha256": POINTER}]
    assert "payload" not in json.dumps(written)
    summary = publish_ledger_summary(settings, artifact_id="summary", out_dir=out, package_class="c")
    assert summary.relative == "ledger/summary/summary.json"
    assert classify_relative("activity-log/stamp-1.jsonl") == "report"
    for relative in (
        "observations/secret.json",
        "packs/bundle/v1/../beacon-pack.json",
        "scopes/prod.json",
        "packs/bundle/v1/notes.txt",
    ):
        with pytest.raises(BeaconError) as caught:
            publish_bytes(settings, relative=relative, body=b"{}", out_dir=out)
        assert caught.value.code == "E_TRUST"


def test_trust_publish_requires_the_export_flag(initialized: Path, monkeypatch: pytest.MonkeyPatch):
    settings = _settings(monkeypatch, False)
    with pytest.raises(BeaconError) as caught:
        publish_bytes(
            settings,
            relative="packs/bundle/v1/beacon-pack.json",
            body=b"{}",
            out_dir=initialized / "export" / "trust-center",
        )
    assert caught.value.code == "E_TRUST"
    assert "BEACON_TRUST_CENTER_EXPORT" in caught.value.message


def test_scn_draft_is_not_sent(initialized: Path, tmp_path: Path):
    settings = load_settings()
    changes = tmp_path / "changes.json"
    changes.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "changes": [
                    {
                        "change_id": "add-reader",
                        "summary": "Reader role added in the fixture scope",
                        "control_refs": ["IAC-02", "GOV-02"],
                        "evidence_sha256": POINTER,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    draft = draft_scn(settings, package_class="c", changes_path=changes)
    assert draft.mailed is False
    assert draft.delivery == "not-sent"
    assert draft.record_v == 1
    assert draft.items[-1].basis == "operator_file"
    text = json.dumps(draft.canonical_body())
    for word in CLAIM_WORDS:
        assert word not in text
    bad = tmp_path / "mail.json"
    bad.write_text(json.dumps({"schema_version": 1, "changes": [], "smtp": "mail"}), encoding="utf-8")
    with pytest.raises(BeaconError) as caught:
        draft_scn(settings, changes_path=bad)
    assert caught.value.code == "E_SCN"


def test_inbox_intake_fails_closed(tmp_path: Path):
    source = tmp_path / "inbox.json"
    source.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "messages": [
                    {
                        "schema_version": 1,
                        "shape": "evidence_candidate",
                        "message_id": "msg-1",
                        "subject": "Seal pointer",
                        "control_refs": ["CRY-07"],
                        "evidence_sha256": POINTER,
                    },
                    {
                        "schema_version": 1,
                        "shape": "ticket_candidate",
                        "message_id": "msg-2",
                        "subject": "Review the package gap",
                        "summary": "Operator asked for a review.",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    candidates, paths = intake_inbox_file(source, tmp_path / "out")
    assert [row.shape for row in candidates] == ["evidence_candidate", "ticket_candidate"]
    assert all(row.credential_used is False and row.mailed is False and row.record_v == 1 for row in candidates)
    assert len(paths) == 2
    source.write_text(json.dumps({"schema_version": 1, "shape": "mailbox", "message_id": "x"}), encoding="utf-8")
    with pytest.raises(BeaconError) as unknown:
        intake_inbox_file(source, tmp_path / "out")
    assert unknown.value.code == "E_INBOX"
    source.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "shape": "evidence_candidate",
                "message_id": "msg-3",
                "subject": "no",
                "password": "secret",
                "control_refs": ["IAC-02"],
                "evidence_sha256": POINTER,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(BeaconError) as secret:
        intake_inbox_file(source, tmp_path / "out")
    assert secret.value.code == "E_INBOX"


def test_cli_surfaces(initialized: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("BEACON_TRUST_CENTER_EXPORT", "1")
    pack = tmp_path / "pack.json"
    pack.write_text(json.dumps({"evidence": [{"sha256": POINTER}]}), encoding="utf-8")
    runner = CliRunner()
    published = runner.invoke(
        main,
        [
            "trust",
            "publish",
            "--file",
            str(pack),
            "--relative",
            "packs/security-decision-record/v1/beacon-pack.json",
        ],
    )
    assert published.exit_code == 0, published.output
    assert json.loads(published.output)["hosted"] is False
    dry = runner.invoke(main, ["scn", "draft", "--dry-run"])
    assert dry.exit_code == 0, dry.output
    body = json.loads(dry.output)
    assert body["dry_run"] is True
    assert body["mailed"] is False
    assert "path" not in body
    inbox = tmp_path / "inbox.json"
    inbox.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "shape": "ticket_candidate",
                "message_id": "msg-9",
                "subject": "Gap review",
                "summary": "Review the fixture gap.",
            }
        ),
        encoding="utf-8",
    )
    taken = runner.invoke(main, ["inbox", "intake", "--file", str(inbox)])
    assert taken.exit_code == 0, taken.output
    assert json.loads(taken.output)["credential_used"] is False
