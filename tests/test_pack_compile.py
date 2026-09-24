"""Offline 20x pack compilers. Fixtures use IAC-02, CRY-07, and GOV-02 only."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from beacon.assurance.index import CLAIM_WORDS
from beacon.cli import main
from beacon.config import load_settings
from beacon.crypto.witness import CHAIN_VERSION, load_records, seal_payload
from beacon.errors import E_LEDGER
from beacon.scope.document import ScopeDocument
from beacon.scope.store import init_scope

SCOPE_ID = "prod-commercial"
KSI_OK = "fixture-ksi-1"
KSI_GAP = "fixture-ksi-2"
KINDS = ("cpo", "sdr", "ocr", "scg")
FORBIDDEN = (*CLAIM_WORDS, "authorized", "Partially Implemented", "Not Implemented")


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
    scf: str,
) -> None:
    seal_payload(
        load_settings(),
        plugin=plugin,
        mode="fixture",
        scf_targets=targets,
        payload={
            "source": plugin,
            "scf": scf,
            "tags": tags,
            "ksi_id": ksi_id,
            "scope_id": document.scope_id,
            "scope_sha256": document.content_sha256(),
        },
    )


def _seed(document: ScopeDocument) -> None:
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
    _seal(
        document,
        plugin="scf.catalog.offline",
        targets=["GOV-02"],
        tags=["evidence:catalog_pin", "automation:automated", "control:GOV-02"],
        ksi_id=KSI_GAP,
        scf="GOV-02",
    )


def test_compile_writes_four_drafts_and_reports_gaps(initialized: Path):
    document = _document()
    _seed(document)
    out = initialized / "20x"
    result = _invoke(
        [
            "pack",
            "compile",
            "--scope",
            SCOPE_ID,
            "--class",
            "c",
            "--fedramp-id",
            "FR0000000",
            "--out",
            str(out),
            "--ksi",
            KSI_OK,
            "--ksi",
            KSI_GAP,
        ]
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["draft"] is True
    assert summary["official_schema"] == "not-fetched"
    assert summary["scope_id"] == SCOPE_ID
    assert summary["scope_sha256"] == document.content_sha256()
    assert summary["kinds"] == ["cpo", "sdr", "ocr", "scg"]
    assert summary["package_gaps"][0]["ksi_id"] == KSI_GAP
    assert summary["package_gaps"][0]["shortfall"] == 1
    assert KSI_OK not in {row["ksi_id"] for row in summary["package_gaps"]}
    for word in FORBIDDEN:
        assert word not in result.output

    for kind in KINDS:
        body = json.loads((out / f"{kind}.json").read_text(encoding="utf-8"))
        markdown = (out / f"{kind}.md").read_text(encoding="utf-8")
        assert body["format"] == "beacon-20x-draft/v1"
        assert body["draft"] is True
        assert body["pack_kind"] == kind
        assert body["scope_id"] == SCOPE_ID
        assert body["scope_sha256"] == document.content_sha256()
        assert body["fedramp_id"] == "FR0000000"
        assert body["package_class"] == "c"
        assert body["minimum_automated_methods"] == 2
        assert body["emits_schema_status_words"] is False
        assert body["control_refs"] == ["CRY-07", "GOV-02", "IAC-02"]
        assert len(body["evidence"]) == 4
        assert "payload" not in json.dumps(body["evidence"])
        by_ksi = {row["ksi_id"]: row for row in body["method_counts"]}
        assert by_ksi[KSI_OK]["automated_method_count"] == 2
        assert by_ksi[KSI_OK]["shortfall"] == 0
        assert by_ksi[KSI_GAP]["automated_method_count"] == 1
        assert by_ksi[KSI_GAP]["manual_method_ids"] == ["policy"]
        assert by_ksi[KSI_GAP]["shortfall"] == 1
        assert body["below_minimum"] == [KSI_GAP]
        unset = set(body["unset_fields"])
        mapped = {row["guide_field"] for row in body["field_map"] if row["filled"] is False}
        assert unset <= mapped
        text = json.dumps(body) + markdown
        for word in FORBIDDEN:
            assert word not in text
        assert f"sha256: {body['evidence'][0]['sha256']}" in markdown
        assert f"{KSI_GAP}: shortfall 1" in markdown
    ocr = json.loads((out / "ocr.json").read_text(encoding="utf-8"))
    assert "reportableIncidents" in ocr["unset_fields"]
    assert "reportableIncidents" not in ocr
    scg = json.loads((out / "scg.json").read_text(encoding="utf-8"))
    assert "instructions_to_get_and_use" in scg["unset_fields"]
    assert "instructions_to_get_and_use" not in scg
    sdr = json.loads((out / "sdr.json").read_text(encoding="utf-8"))
    assert sdr["beacon_pack_type"] == "security-decision-record"
    assert sdr["guide_name"] == "Security Decision Record"
    record = load_records(load_settings())[0]
    assert record.v == CHAIN_VERSION == 1


def test_class_d_shortfall_and_scope_stamp_without_flag(initialized: Path):
    document = _document()
    _seed(document)
    out = initialized / "class-d"
    result = _invoke(["pack", "compile", "--kind", "sdr", "--class", "d", "--out", str(out)])
    assert result.exit_code == 0, result.output
    body = json.loads((out / "sdr.json").read_text(encoding="utf-8"))
    assert body["scope_id"] == document.scope_id
    assert body["scope_sha256"] == document.content_sha256()
    assert body["minimum_automated_methods"] == 4
    assert body["fedramp_id"] is None
    by_ksi = {row["ksi_id"]: row for row in body["method_counts"]}
    assert by_ksi[KSI_OK]["shortfall"] == 2
    assert by_ksi[KSI_GAP]["shortfall"] == 3
    assert set(body["below_minimum"]) == {KSI_OK, KSI_GAP}
    assert not (out / "cpo.json").exists()


def test_unknown_registry_tag_fails_closed(initialized: Path):
    document = _document()
    _seal(
        document,
        plugin="aws.inspector",
        targets=["IAC-02"],
        tags=["evidence:cloud_inspector", "automation:automated", "control:IAC-01"],
        ksi_id=KSI_OK,
        scf="IAC-02",
    )
    refused = _invoke(["pack", "compile", "--scope", SCOPE_ID, "--class", "c"])
    assert refused.exit_code == 2
    assert E_LEDGER in refused.output
    assert "unknown control tag" in refused.output
    assert load_records(load_settings())[0].v == 1
