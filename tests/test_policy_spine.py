"""Git policy path+hash and mapper candidate ingest. No network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from beacon.assurance.mapper_ingest import ingest_mapper_file
from beacon.assurance.policy import address_policy
from beacon.cli import main
from beacon.crypto.witness import CHAIN_VERSION
from beacon.errors import BeaconError

CLAIM_WORDS = ("compliant", "evidenced", "proven", "Implemented")


def _policy(**updates: object) -> dict:
    body: dict = {
        "schema_version": 1,
        "policy_id": "access-control",
        "title": "Access control policy",
        "people": [{"role": "owner", "name": "Identity"}],
        "process": [{"id": "disable-orphan", "summary": "Disable an orphan account"}],
        "technology": [{"id": "iam", "system": "workspace"}],
        "control_refs": ["IAC-02"],
        "scope_refs": ["prod-commercial"],
    }
    body.update(updates)
    return body


def _write(root: Path, relative: str, body: object) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body) + "\n", encoding="utf-8")
    return path


def test_policy_is_addressed_by_path_and_hash(tmp_path: Path):
    _write(tmp_path, "policies/access-control.json", _policy())
    document, custody = address_policy(tmp_path, "policies/access-control.json", git_sha=None)
    assert custody.path == "policies/access-control.json"
    assert custody.content_sha256 == document.content_sha256()
    assert custody.tag == "evidence:policy"
    assert custody.role == "candidate"
    assert custody.source_of_truth == "git"
    assert custody.record_v == 1
    assert CHAIN_VERSION == 1
    again, _again_custody = address_policy(
        tmp_path,
        "policies/access-control.json",
        expect_sha256=custody.content_sha256,
        git_sha="ab" * 20,
    )
    assert again.content_sha256() == custody.content_sha256
    spaced = tmp_path / "policies" / "spaced.json"
    spaced.write_text(json.dumps(_policy(), indent=2), encoding="utf-8")
    spaced_doc, spaced_custody = address_policy(tmp_path, "policies/spaced.json", git_sha=None)
    assert spaced_doc.content_sha256() == document.content_sha256()
    assert spaced_custody.file_sha256 != custody.file_sha256


def test_policy_fails_closed(tmp_path: Path):
    _write(tmp_path, "policies/access-control.json", _policy())
    _document, custody = address_policy(tmp_path, "policies/access-control.json", git_sha=None)
    with pytest.raises(BeaconError) as bad_hash:
        address_policy(
            tmp_path,
            "policies/access-control.json",
            expect_sha256="cd" * 32,
            git_sha=None,
        )
    assert bad_hash.value.code == "E_POLICY"
    for relative in ("policies/legacy.pdf", "policies/legacy.docx", "../secret.json", "/etc/passwd"):
        with pytest.raises(BeaconError) as refused:
            address_policy(tmp_path, relative, git_sha=None)
        assert refused.value.code == "E_POLICY"
    _write(tmp_path, "policies/bad-control.json", _policy(control_refs=["IAC-01"]))
    with pytest.raises(BeaconError) as bad_control:
        address_policy(tmp_path, "policies/bad-control.json", git_sha=None)
    assert bad_control.value.code == "E_POLICY"
    _write(tmp_path, "policies/extra.json", {**_policy(), "status": "Implemented"})
    with pytest.raises(BeaconError):
        address_policy(tmp_path, "policies/extra.json", git_sha=None)
    assert custody.content_sha256 != "cd" * 32


def test_mapper_report_is_a_candidate(tmp_path: Path):
    source = tmp_path / "report.json"
    source.write_text(
        json.dumps(
            {
                "doc_id": "pol-ac-001",
                "snapshot_id": "snap-1",
                "ingest": {
                    "source_path": "legacy/access.docx",
                    "source_hash": "ab" * 32,
                    "markdown": "Privileged accounts use a second factor.",
                },
                "statements": [
                    {
                        "statement": {
                            "statement_id": "stmt-1",
                            "text": "Privileged accounts use a second factor.",
                            "content_hash": "cd" * 32,
                        },
                        "mappings": [
                            {"source": "fixture", "framework": "fixture", "control_id": "IAC-02"}
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "store"
    candidate, written = ingest_mapper_file(source, out)
    raw = written.read_text(encoding="utf-8")
    for word in CLAIM_WORDS:
        assert word not in raw
    assert candidate.role == "candidate"
    assert candidate.shape == "mapping_report"
    assert candidate.legacy_bytes_are_source_of_truth is False
    assert candidate.claim is None
    assert candidate.record_v == 1
    assert candidate.mapper_control_labels == ("IAC-02",)
    assert candidate.policy_draft is not None
    assert candidate.policy_draft.control_refs == ()
    assert "Privileged" not in raw
    assert not (tmp_path / ".beacon" / "chain" / "records.jsonl").exists()


def test_mapper_ksi_and_links_and_unknown(tmp_path: Path):
    ksi = tmp_path / "ksi.json"
    ksi.write_text(
        json.dumps(
            {
                "source": {"title": "fixture"},
                "classes": {"c": {"name": "Class C"}},
                "domains": {
                    "fixture": {
                        "indicators": [{"id": "fixture-ksi-iam", "name": "fixture"}],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    candidate, _written = ingest_mapper_file(ksi, tmp_path / "out")
    assert candidate.shape == "ksi_catalog"
    assert candidate.mapper_indicator_ids == ("fixture-ksi-iam",)
    assert candidate.policy_draft is None
    links = tmp_path / "links.json"
    links.write_text(
        json.dumps(
            {
                "links": [
                    {
                        "link_id": "lnk-1",
                        "doc_id": "pol-ac-001",
                        "statement_anchor": "second factor",
                        "control_ids": ["fixture-label"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    linked, _path = ingest_mapper_file(links, tmp_path / "out")
    assert linked.shape == "policy_code_links"
    assert linked.mapper_control_labels == ("fixture-label",)
    unknown = tmp_path / "unknown.json"
    unknown.write_text(json.dumps({"hello": 1}), encoding="utf-8")
    with pytest.raises(BeaconError) as bad:
        ingest_mapper_file(unknown, tmp_path / "out")
    assert bad.value.code == "E_MAPPER"
    mixed = tmp_path / "mixed.json"
    mixed.write_text(
        json.dumps({"doc_id": "pol-ac-001", "snapshot_id": "snap-1", "domains": {}, "links": []}),
        encoding="utf-8",
    )
    with pytest.raises(BeaconError) as ambiguous:
        ingest_mapper_file(mixed, tmp_path / "out")
    assert ambiguous.value.code == "E_MAPPER"


def test_cli_policy_and_ingest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / ".beacon"
    monkeypatch.setenv("BEACON_HOME", str(home))
    monkeypatch.setenv("BEACON_SCF_OFFLINE", "1")
    _write(tmp_path, "policies/access-control.json", _policy(control_refs=["CRY-07", "GOV-02"]))
    runner = CliRunner()
    shown = runner.invoke(
        main,
        ["policy", "show", "--root", str(tmp_path), "--path", "policies/access-control.json"],
    )
    assert shown.exit_code == 0
    body = json.loads(shown.output)
    assert body["path"] == "policies/access-control.json"
    assert body["record_v"] == 1
    hashed = runner.invoke(
        main,
        ["policy", "hash", "--root", str(tmp_path), "--path", "policies/access-control.json"],
    )
    assert hashed.exit_code == 0
    assert hashed.output.strip() == body["content_sha256"]
    pdf = runner.invoke(
        main,
        ["policy", "show", "--root", str(tmp_path), "--path", "policies/legacy.pdf"],
    )
    assert pdf.exit_code == 2
    assert "E_POLICY" in pdf.output
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "doc_id": "pol-ac-001",
                "snapshot_id": "snap-1",
                "ingest": {
                    "source_path": "legacy/access.pdf",
                    "source_hash": "ef" * 32,
                    "markdown": "text",
                },
                "statements": [],
            }
        ),
        encoding="utf-8",
    )
    ingested = runner.invoke(main, ["ingest", "mapper", "--file", str(report)])
    assert ingested.exit_code == 0
    payload = json.loads(ingested.output)
    assert payload["role"] == "candidate"
    assert payload["record_v"] == 1
    stored = Path(payload["path"]).read_text(encoding="utf-8")
    for word in CLAIM_WORDS:
        assert word not in stored
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    refused = runner.invoke(main, ["ingest", "mapper", "--file", str(bad)])
    assert refused.exit_code == 2
    assert "E_MAPPER" in refused.output
