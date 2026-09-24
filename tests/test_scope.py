"""Schema round-trip for assessment scope documents and judgment receipts."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from beacon.canonical import dumps
from beacon.scope.document import (
    DEFAULT_SCORE_MIN,
    Boundary,
    ChoiceResult,
    Exclusion,
    JudgmentReceipt,
    NoulResult,
    ScopeDocument,
    ScoreResult,
    decide_claim,
)

EVIDENCE_HASH = "ab" * 32
OTHER_HASH = "cd" * 32


def _scope() -> ScopeDocument:
    return ScopeDocument(
        scope_id="prod-commercial",
        catalog_pin_version="2026.3",
        frameworks=["general-nist-800-53-r5-2"],
        data_classes=["security-log"],
        exclusions=[
            Exclusion(kind="region", value="eu-west-1", reason="outside this instance"),
        ],
        allowed_evidence_kinds=["cloud_inspector", "lake_log_extract"],
        boundary=Boundary(accounts=["123456789012"], regions=["us-east-1"], systems=["evidence-lake"]),
    )


def _receipt(scope: ScopeDocument, *, coverage: float = 1.0, noul: str = "sufficient") -> JudgmentReceipt:
    return JudgmentReceipt(
        receipt_id="receipt-1",
        scope_id=scope.scope_id,
        scope_sha256=scope.content_sha256(),
        evidence_sha256=EVIDENCE_HASH,
        control_ref="IAC-02",
        choice=ChoiceResult(
            disposition="pick",
            candidate_id="aws.inspector",
            candidate_sha256=OTHER_HASH,
        ),
        score=ScoreResult(coverage=coverage),
        noul=NoulResult(disposition=noul),
    )


def test_scope_json_round_trip_and_stable_hash():
    scope = _scope()
    raw = dumps(scope.canonical_body())
    again = ScopeDocument.model_validate_json(raw)
    assert again == scope
    assert again.content_sha256() == scope.content_sha256()
    assert len(scope.content_sha256()) == 64


def test_scope_hash_changes_when_boundary_changes():
    scope = _scope()
    widened = scope.model_copy(update={"boundary": Boundary(accounts=["123456789012"], regions=["us-west-2"])})
    assert widened.content_sha256() != scope.content_sha256()


def test_scope_rejects_empty_boundary_and_claim_field():
    with pytest.raises(ValidationError):
        Boundary()
    body = _scope().canonical_body()
    body["compliant"] = True
    with pytest.raises(ValidationError):
        ScopeDocument.model_validate(body)


def test_scope_rejects_repeated_framework_and_unknown_evidence_kind():
    body = _scope().canonical_body()
    body["frameworks"] = ["general-nist-800-53-r5-2", "general-nist-800-53-r5-2"]
    with pytest.raises(ValidationError):
        ScopeDocument.model_validate(body)
    with pytest.raises(ValidationError):
        Exclusion(kind="evidence_kind", value="control-met", reason="not an evidence kind")


def test_receipt_json_round_trip_rejects_claim_field():
    scope = _scope()
    receipt = _receipt(scope)
    again = JudgmentReceipt.model_validate_json(dumps(receipt.canonical_body()))
    assert again == receipt
    assert again.content_sha256() == receipt.content_sha256()
    body = receipt.canonical_body()
    body["proven"] = True
    with pytest.raises(ValidationError):
        JudgmentReceipt.model_validate(body)


def test_no_match_choice_has_no_candidate():
    ChoiceResult(disposition="no_match")
    with pytest.raises(ValidationError):
        ChoiceResult(disposition="no_match", candidate_id="aws.inspector", candidate_sha256=OTHER_HASH)
    with pytest.raises(ValidationError):
        ChoiceResult(disposition="pick")


def test_decide_claim_fail_closed_reasons():
    scope = _scope()
    receipt = _receipt(scope)
    scope_hash = scope.content_sha256()
    assert decide_claim(None).reason == "missing_receipt"
    assert decide_claim(receipt, expected_evidence_sha256=EVIDENCE_HASH).reason == "unbound_scope"
    assert decide_claim(receipt, expected_scope_sha256=scope_hash).reason == "unbound_evidence"
    assert (
        decide_claim(
            receipt,
            expected_scope_sha256=OTHER_HASH,
            expected_evidence_sha256=EVIDENCE_HASH,
        ).reason
        == "scope_hash_mismatch"
    )
    assert (
        decide_claim(
            receipt,
            expected_scope_sha256=scope_hash,
            expected_evidence_sha256=OTHER_HASH,
        ).reason
        == "evidence_hash_mismatch"
    )
    no_match = receipt.model_copy(
        update={"choice": ChoiceResult(disposition="no_match")}
    )
    assert (
        decide_claim(
            no_match,
            expected_scope_sha256=scope_hash,
            expected_evidence_sha256=EVIDENCE_HASH,
        ).reason
        == "choice_no_match"
    )
    abstain = _receipt(scope, noul="abstain")
    assert (
        decide_claim(
            abstain,
            expected_scope_sha256=scope_hash,
            expected_evidence_sha256=EVIDENCE_HASH,
        ).reason
        == "noul_abstain"
    )
    low = _receipt(scope, coverage=0.5)
    assert (
        decide_claim(
            low,
            expected_scope_sha256=scope_hash,
            expected_evidence_sha256=EVIDENCE_HASH,
        ).reason
        == "score_below_min"
    )
    assert DEFAULT_SCORE_MIN == 1.0


def test_decide_claim_permits_only_a_linked_passing_receipt():
    scope = _scope()
    receipt = _receipt(scope)
    decision = decide_claim(
        receipt,
        expected_scope_sha256=scope.content_sha256(),
        expected_evidence_sha256=EVIDENCE_HASH,
    )
    assert decision.permitted is True
    assert decision.receipt_id == "receipt-1"
    assert decision.reason == "thresholds_met"
    assert decision.reason not in {"compliant", "evidenced", "proven"}


def test_decide_claim_rejects_bad_threshold():
    with pytest.raises(ValueError):
        decide_claim(_receipt(_scope()), score_min=1.5)
    with pytest.raises(ValueError):
        decide_claim(_receipt(_scope()), score_min=float("nan"))
    with pytest.raises(ValidationError):
        ScoreResult(coverage=float("nan"))
