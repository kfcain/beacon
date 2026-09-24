"""Assessment scope document and judgment receipt schema.

This module validates and hashes scope documents. It does not collect, seal,
push, or call Jev. See docs/architecture/assessment-scope-and-jev.md.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from beacon.canonical import sha256_obj

SCHEMA_VERSION = 1
# Fail closed until a later phase stores an operator minimum in Beacon config.
DEFAULT_SCORE_MIN = 1.0

SCOPE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

EvidenceKind = Literal[
    "cloud_inspector",
    "lake_log_extract",
    "catalog_pin",
    "drop_in",
]
EVIDENCE_KINDS: tuple[EvidenceKind, ...] = (
    "cloud_inspector",
    "lake_log_extract",
    "catalog_pin",
    "drop_in",
)

ExclusionKind = Literal[
    "account",
    "subscription",
    "project",
    "region",
    "system",
    "evidence_kind",
    "framework",
]
ChoiceDisposition = Literal["pick", "no_match"]
NoulDisposition = Literal["sufficient", "insufficient", "abstain"]
ClaimReason = Literal[
    "missing_receipt",
    "unbound_scope",
    "unbound_evidence",
    "scope_hash_mismatch",
    "evidence_hash_mismatch",
    "choice_no_match",
    "missing_candidate",
    "noul_abstain",
    "noul_insufficient",
    "score_below_min",
    "thresholds_met",
]


def _never(value: object) -> NoReturn:
    raise AssertionError(f"unhandled value: {value!r}")


def _nonblank_token(value: str, *, label: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{label} must be non-blank and must not have surrounding space")
    if "/" in value or "\\" in value or ".." in value:
        raise ValueError(f"{label} must not contain a path segment")
    return value


class Boundary(BaseModel):
    """Accounts, subscriptions, projects, regions, and systems in the instance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    accounts: list[str] = Field(default_factory=list)
    subscriptions: list[str] = Field(default_factory=list)
    projects: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    systems: list[str] = Field(default_factory=list)

    @field_validator("accounts", "subscriptions", "projects", "regions", "systems")
    @classmethod
    def entries_are_tokens(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in values:
            text = _nonblank_token(item, label="boundary entry")
            if text in seen:
                raise ValueError("boundary entries must not repeat")
            seen.add(text)
            cleaned.append(text)
        return cleaned

    @model_validator(mode="after")
    def require_a_boundary(self) -> Boundary:
        if not (
            self.accounts
            or self.subscriptions
            or self.projects
            or self.regions
            or self.systems
        ):
            raise ValueError(
                "boundary must name at least one account, subscription, project, region, or system"
            )
        return self


class Exclusion(BaseModel):
    """One item the instance must not treat as in scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ExclusionKind
    value: str = Field(min_length=1)
    reason: str = Field(min_length=1)

    @field_validator("value", "reason")
    @classmethod
    def text_is_token(cls, value: str) -> str:
        return _nonblank_token(value, label="exclusion text")

    @model_validator(mode="after")
    def evidence_kind_is_known(self) -> Exclusion:
        match self.kind:
            case "evidence_kind":
                if self.value not in EVIDENCE_KINDS:
                    raise ValueError("evidence_kind exclusion must name an evidence kind")
            case "account" | "subscription" | "project" | "region" | "system" | "framework":
                pass
            case _ as unknown:
                _never(unknown)
        return self


class ScopeDocument(BaseModel):
    """Operator boundary for one Beacon instance. This is not a control catalog."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = SCHEMA_VERSION
    scope_id: str
    catalog_pin_version: str = Field(min_length=1)
    frameworks: list[str] = Field(min_length=1)
    data_classes: list[str] = Field(default_factory=list)
    exclusions: list[Exclusion] = Field(default_factory=list)
    allowed_evidence_kinds: list[EvidenceKind] = Field(min_length=1)
    boundary: Boundary

    @field_validator("scope_id")
    @classmethod
    def check_scope_id(cls, value: str) -> str:
        if not SCOPE_ID_RE.fullmatch(value):
            raise ValueError("scope_id must match the safe id pattern")
        return value

    @field_validator("catalog_pin_version")
    @classmethod
    def pin_is_label(cls, value: str) -> str:
        return _nonblank_token(value, label="catalog_pin_version")

    @field_validator("frameworks", "data_classes")
    @classmethod
    def labels_are_unique(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in values:
            text = _nonblank_token(item, label="label")
            if text in seen:
                raise ValueError("labels must not repeat")
            seen.add(text)
            cleaned.append(text)
        return cleaned

    @field_validator("allowed_evidence_kinds")
    @classmethod
    def kinds_are_unique(cls, values: list[EvidenceKind]) -> list[EvidenceKind]:
        if len(values) != len(set(values)):
            raise ValueError("allowed_evidence_kinds must not repeat")
        return list(values)

    def canonical_body(self) -> dict:
        return self.model_dump(mode="json")

    def content_sha256(self) -> str:
        return sha256_obj(self.canonical_body())


class ChoiceResult(BaseModel):
    """Jev Choice. pick names one Beacon candidate. no_match names none."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    disposition: ChoiceDisposition
    candidate_id: str | None = None
    candidate_sha256: str | None = None

    @model_validator(mode="after")
    def choice_shape(self) -> ChoiceResult:
        match self.disposition:
            case "pick":
                if not self.candidate_id or not self.candidate_sha256:
                    raise ValueError("pick requires candidate_id and candidate_sha256")
                if not SCOPE_ID_RE.fullmatch(self.candidate_id):
                    raise ValueError("candidate_id must match the safe id pattern")
                if not SHA256_RE.fullmatch(self.candidate_sha256):
                    raise ValueError("candidate_sha256 must be 64 lowercase hex characters")
            case "no_match":
                if self.candidate_id is not None or self.candidate_sha256 is not None:
                    raise ValueError("no_match must not name a candidate")
            case _ as unknown:
                _never(unknown)
        return self


class ScoreResult(BaseModel):
    """Jev Score. coverage is a number from 0 through 1. It is not a pass mark."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    coverage: float = Field(ge=0.0, le=1.0)

    @field_validator("coverage")
    @classmethod
    def coverage_is_finite(cls, value: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError("coverage must be a finite number from 0 through 1")
        return float(value)


class NoulResult(BaseModel):
    """Jev Noul. sufficiency under the scope. It is not a compliance word."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    disposition: NoulDisposition


class JudgmentReceipt(BaseModel):
    """One Jev judgment linked to a scope hash and an evidence hash.

    The receipt has no compliance-claim field. Beacon code decides claims.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = SCHEMA_VERSION
    receipt_id: str
    scope_id: str
    scope_sha256: str
    evidence_sha256: str
    control_ref: str = Field(min_length=1)
    choice: ChoiceResult
    score: ScoreResult
    noul: NoulResult

    @field_validator("receipt_id", "scope_id")
    @classmethod
    def ids_are_safe(cls, value: str) -> str:
        if not SCOPE_ID_RE.fullmatch(value):
            raise ValueError("id must match the safe id pattern")
        return value

    @field_validator("scope_sha256", "evidence_sha256")
    @classmethod
    def hashes_are_sha256(cls, value: str) -> str:
        if not SHA256_RE.fullmatch(value):
            raise ValueError("hash must be 64 lowercase hex characters")
        return value

    @field_validator("control_ref")
    @classmethod
    def control_ref_is_label(cls, value: str) -> str:
        return _nonblank_token(value, label="control_ref")

    def canonical_body(self) -> dict:
        return self.model_dump(mode="json")

    def content_sha256(self) -> str:
        return sha256_obj(self.canonical_body())


@dataclass(frozen=True)
class ClaimDecision:
    """Code gate result. permitted is true only when a receipt is linked and thresholds pass."""

    permitted: bool
    receipt_id: str | None
    reason: ClaimReason


def _check_score_min(score_min: float) -> float:
    if isinstance(score_min, bool) or not isinstance(score_min, (int, float)):
        raise ValueError("score_min must be a number from 0 through 1")
    value = float(score_min)
    if not math.isfinite(value) or value < 0.0 or value > 1.0:
        raise ValueError("score_min must be a number from 0 through 1")
    return value


def _hash_matches(expected: str, actual: str) -> bool:
    return bool(SHA256_RE.fullmatch(expected) and expected == actual)


def decide_claim(
    receipt: JudgmentReceipt | None,
    *,
    score_min: float = DEFAULT_SCORE_MIN,
    expected_scope_sha256: str | None = None,
    expected_evidence_sha256: str | None = None,
) -> ClaimDecision:
    """Return whether code may attach a positive claim to this receipt.

    The caller must pass the scope hash and the evidence hash from the seal.
    This function does not emit claim words. A later phase may emit those words
    only when permitted is true and the caller also shows receipt_id.
    """
    minimum = _check_score_min(score_min)
    if receipt is None:
        return ClaimDecision(permitted=False, receipt_id=None, reason="missing_receipt")
    receipt_id = receipt.receipt_id
    if expected_scope_sha256 is None:
        return ClaimDecision(permitted=False, receipt_id=receipt_id, reason="unbound_scope")
    if expected_evidence_sha256 is None:
        return ClaimDecision(permitted=False, receipt_id=receipt_id, reason="unbound_evidence")
    if not _hash_matches(expected_scope_sha256, receipt.scope_sha256):
        return ClaimDecision(permitted=False, receipt_id=receipt_id, reason="scope_hash_mismatch")
    if not _hash_matches(expected_evidence_sha256, receipt.evidence_sha256):
        return ClaimDecision(
            permitted=False, receipt_id=receipt_id, reason="evidence_hash_mismatch"
        )
    match receipt.choice.disposition:
        case "no_match":
            return ClaimDecision(permitted=False, receipt_id=receipt_id, reason="choice_no_match")
        case "pick":
            if not receipt.choice.candidate_id or not receipt.choice.candidate_sha256:
                return ClaimDecision(
                    permitted=False, receipt_id=receipt_id, reason="missing_candidate"
                )
        case _ as unknown_choice:
            _never(unknown_choice)
    match receipt.noul.disposition:
        case "abstain":
            return ClaimDecision(permitted=False, receipt_id=receipt_id, reason="noul_abstain")
        case "insufficient":
            return ClaimDecision(
                permitted=False, receipt_id=receipt_id, reason="noul_insufficient"
            )
        case "sufficient":
            pass
        case _ as unknown_noul:
            _never(unknown_noul)
    coverage = receipt.score.coverage
    if (
        isinstance(coverage, bool)
        or not isinstance(coverage, (int, float))
        or not math.isfinite(float(coverage))
        or float(coverage) < 0.0
        or float(coverage) > 1.0
        or float(coverage) < minimum
    ):
        return ClaimDecision(permitted=False, receipt_id=receipt_id, reason="score_below_min")
    return ClaimDecision(permitted=True, receipt_id=receipt_id, reason="thresholds_met")
