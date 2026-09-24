"""Fixtures for the assurance-stack sketches. No network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from beacon.assurance.ledger import MethodRecord, ksi_method_report
from beacon.assurance.packs import EvidencePointer, compile_pack_draft
from beacon.assurance.pin_ids import SEEDED_CONTROL_IDS, pinned_framework_ids
from beacon.assurance.tags import parse_tag
from beacon.config import load_settings
from beacon.errors import BeaconError
from beacon.scope.document import Boundary, ScopeDocument
from beacon.scope.draft_v2 import ComponentService, FrameworkContext, ScopeDraftV2
from beacon.scope.store import load_scope
from beacon.scf.catalog_pin import PINNED_NOT_A_FRAMEWORK_IDS

FIXTURE = Path(__file__).parent / "fixtures" / "assurance" / "ledger_methods.json"
EVIDENCE_HASH = "ab" * 32
SCOPE_HASH = "cd" * 32
CLAIM_WORDS = ("compliant", "evidenced", "proven", "Implemented")


def _scope(**updates: object) -> ScopeDocument:
    body = {
        "scope_id": "prod-commercial",
        "catalog_pin_version": "2026.3",
        "frameworks": ["general-nist-800-53-r5-2"],
        "allowed_evidence_kinds": ["cloud_inspector"],
        "boundary": Boundary(systems=["evidence-lake"]),
    }
    body.update(updates)
    return ScopeDocument.model_validate(body)


def _draft() -> ScopeDraftV2:
    return ScopeDraftV2(
        scope=_scope(),
        components=(
            ComponentService(
                kind="service",
                id="evidence-lake",
                role="custody store",
                platform="aws",
                context="commercial partition",
                solutions_refs=("lake-log-extract",),
                risk_refs=("boundary-gap",),
                status="proposed",
                tags=("platform:aws", "evidence:lake_log_extract", "control:IAC-02"),
            ),
        ),
        tags=("framework:general-nist-800-53-r5-2", "automation:automated"),
        framework_context=(
            FrameworkContext(
                framework_id="general-nist-800-53-r5-2",
                required_components=("evidence-lake",),
                rules=("FRC-CSX-VVK",),
                tags=("framework:general-nist-800-53-r5-2",),
            ),
        ),
    )


def test_v1_scope_rejects_draft_fields_and_keeps_schema_1():
    scope = _scope()
    raw = scope.model_dump(mode="json")
    assert raw["schema_version"] == 1
    assert "components" not in raw
    again = ScopeDocument.model_validate_json(json.dumps(raw))
    assert again.content_sha256() == scope.content_sha256()
    raw["components"] = []
    with pytest.raises(ValidationError):
        ScopeDocument.model_validate(raw)
    raw.pop("components")
    raw["schema_version"] = 2
    with pytest.raises(ValidationError):
        ScopeDocument.model_validate(raw)


def test_scope_draft_v2_round_trip_and_pin_fail_closed():
    draft = _draft()
    again = ScopeDraftV2.model_validate_json(json.dumps(draft.canonical_body()))
    assert again == draft
    assert again.schema_version == 2
    assert again.content_sha256() == draft.content_sha256()
    assert again.scope.schema_version == 1
    blocked = PINNED_NOT_A_FRAMEWORK_IDS[0]
    assert blocked not in pinned_framework_ids()
    with pytest.raises(ValidationError):
        FrameworkContext(framework_id=blocked)
    with pytest.raises(ValidationError):
        _draft_with_framework("not-a-real-framework")


def _draft_with_framework(framework_id: str) -> ScopeDraftV2:
    return ScopeDraftV2(
        scope=_scope(frameworks=[framework_id]),
        framework_context=(FrameworkContext(framework_id=framework_id),),
    )


def test_load_scope_rejects_a_v2_draft_file(beacon_home: Path):
    settings = load_settings()
    path = beacon_home / "scopes" / "prod-commercial.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(_draft().canonical_body()), encoding="utf-8")
    with pytest.raises(BeaconError) as caught:
        load_scope(settings, "prod-commercial")
    assert caught.value.code == "E_SCOPE"


def test_tag_registry_fail_closed():
    assert parse_tag("platform:aws").value == "aws"
    assert parse_tag("evidence:policy").namespace == "evidence"
    assert parse_tag("control:CRY-07").value in SEEDED_CONTROL_IDS
    assert parse_tag("automation:manual").value == "manual"
    assert parse_tag("framework:usa-federal-dow-cmmc-2-level-2").namespace == "framework"
    assert parse_tag("owner:cso", known_owners=frozenset({"cso"})).value == "cso"
    with pytest.raises(ValueError, match="unknown tag namespace"):
        parse_tag("claim:met")
    with pytest.raises(ValueError, match="unknown control tag"):
        parse_tag("control:IAC-01")
    with pytest.raises(ValueError, match="unknown framework tag"):
        parse_tag("framework:usa-federal-gsa-fedramp-20x-ksi")
    with pytest.raises(ValueError, match="unknown risk tag"):
        parse_tag("risk:R-1")
    with pytest.raises(ValueError, match="unknown owner tag"):
        parse_tag("owner:cso")


def test_ksi_method_report_from_fixture():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    records = [MethodRecord.model_validate(row) for row in payload["records"]]
    report = ksi_method_report(
        records,
        package_class="c",
        required_ksi_ids=payload["required_ksi_ids"],
        not_before="2026-09-15T00:00:00Z",
    )
    assert report.required_list_supplied is True
    assert report.minimum == 2
    by_id = {row.ksi_id: row for row in report.counts}
    assert by_id["fixture-ksi-1"].automated_method_ids == ("method-a", "method-b")
    assert by_id["fixture-ksi-1"].shortfall == 0
    assert by_id["fixture-ksi-2"].automated_method_count == 0
    assert by_id["fixture-ksi-2"].manual_method_ids == ("method-c",)
    assert by_id["fixture-ksi-2"].shortfall == 2
    assert by_id["fixture-ksi-3"].automated_method_count == 0
    assert by_id["fixture-ksi-3"].shortfall == 2
    assert "fixture-ksi-2/method-a" in report.excluded_stale
    assert "fixture-ksi-2/method-d" in report.excluded_undated
    assert "fixture-ksi-2" in report.below_minimum
    assert "fixture-ksi-1" not in report.below_minimum

    wide = ksi_method_report(records, package_class="d", required_ksi_ids=["fixture-ksi-1"])
    assert wide.minimum == 4
    assert wide.counts[0].automated_method_count == 2
    assert wide.counts[0].shortfall == 2
    dumped = json.dumps(report.model_dump(mode="json"))
    for word in CLAIM_WORDS:
        assert word not in dumped
    with pytest.raises(ValueError, match="required ksi ids"):
        ksi_method_report(records, package_class="c", required_ksi_ids=[])
    with pytest.raises(ValueError, match="package class"):
        ksi_method_report(records, package_class="e")  # type: ignore[arg-type]


def test_pack_draft_pointers_have_no_claim_words():
    pointer = EvidencePointer(
        sha256=EVIDENCE_HASH,
        s3_uri="s3://bucket/t1/w1/exports/packs/security-decision-record/v1/beacon-pack.json",
        git_sha="a" * 40,
    )
    for kind, beacon_type in (
        ("cpo", None),
        ("sdr", "security-decision-record"),
        ("ocr", "ongoing-certification-report"),
        ("scg", "secure-configuration-guide"),
    ):
        draft = compile_pack_draft(
            kind,
            pointers=[pointer],
            scope_sha256=SCOPE_HASH,
            fedramp_id="FR0000000",
        )
        body = draft.canonical_body()
        assert body["draft"] is True
        assert body["beacon_pack_type"] == beacon_type
        assert body["evidence"][0]["sha256"] == EVIDENCE_HASH
        assert "payload" not in body
        text = json.dumps(body)
        for word in CLAIM_WORDS:
            assert word not in text
        if kind == "ocr":
            assert "reportableIncidents" in body["unset_fields"]
            assert body.get("reportableIncidents") is None
    with pytest.raises(ValidationError):
        EvidencePointer(sha256=EVIDENCE_HASH, s3_uri="s3://bucket/observations/raw.json")
    with pytest.raises(ValidationError):
        EvidencePointer(sha256=EVIDENCE_HASH, s3_uri="s3://bucket/observations%2Fraw.json")
    with pytest.raises(ValueError):
        compile_pack_draft("bundle", scope_sha256=SCOPE_HASH)
