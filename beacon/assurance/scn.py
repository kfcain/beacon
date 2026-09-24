"""Draft a significant-change notice from seals and package gaps.

The object is custody metadata. This module does not send mail.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from beacon.assurance.compile import PackageGap
from beacon.assurance.index import ledger_method_report, load_evidence_ledger
from beacon.assurance.ledger import PackageClass
from beacon.assurance.packs import EvidencePointer
from beacon.assurance.pin_ids import SEEDED_CONTROL_IDS
from beacon.canonical import dumps, sha256_bytes
from beacon.config import Settings
from beacon.crypto.witness import CHAIN_VERSION
from beacon.errors import E_LEDGER, E_SCN, BeaconError, fail
from beacon.scope.document import SCOPE_ID_RE, SHA256_RE

SCN_FORMAT = "beacon-scn-draft/v1"
Basis = Literal["package_gap", "sealed_observation", "operator_file"]
CLAIM_MARKERS = ("compliant", "evidenced", "proven", "Implemented", " met", '"met"')
_SECRET_KEYS = frozenset({"password", "secret", "token", "smtp", "imap", "mailbox", "to", "recipient"})


def _scn_fail(message: str) -> None:
    fail(E_SCN, message)


def _no_claim(body: object) -> None:
    text = json.dumps(body)
    for word in CLAIM_MARKERS:
        if word in text:
            _scn_fail("SCN draft must not contain a claim word")


class ScnItem(BaseModel):
    """One custody row. The row is not a mailed sentence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    basis: Basis
    change_id: str
    summary: str
    evidence_sha256: str | None = None
    control_refs: tuple[str, ...] = ()
    shortfall: int | None = Field(default=None, ge=0)

    @field_validator("change_id")
    @classmethod
    def change_id_is_safe(cls, value: str) -> str:
        if not SCOPE_ID_RE.fullmatch(value):
            raise ValueError("change_id must match the safe id pattern")
        return value

    @field_validator("summary")
    @classmethod
    def summary_is_present(cls, value: str) -> str:
        if not value or value != value.strip():
            raise ValueError("summary must be non-blank")
        return value

    @field_validator("evidence_sha256")
    @classmethod
    def hash_is_sha256(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not SHA256_RE.fullmatch(value):
            raise ValueError("evidence_sha256 must be 64 lowercase hex characters")
        return value

    @field_validator("control_refs")
    @classmethod
    def refs_are_seeded(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        seen: set[str] = set()
        for item in value:
            if item not in SEEDED_CONTROL_IDS:
                raise ValueError("control_refs accepts only the seeded control ids")
            if item in seen:
                raise ValueError("control_refs must not repeat")
            seen.add(item)
        return value


class ScnDraft(BaseModel):
    """Structured notice. ``mailed`` stays false. A human sends any later notice."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format: Literal["beacon-scn-draft/v1"] = SCN_FORMAT
    draft: Literal[True] = True
    mailed: Literal[False] = False
    delivery: Literal["not-sent"] = "not-sent"
    record_v: Literal[1] = 1
    scope_id: str | None = None
    scope_sha256: str | None = None
    package_class: PackageClass
    package_gaps: tuple[PackageGap, ...] = ()
    evidence: tuple[EvidencePointer, ...] = ()
    items: tuple[ScnItem, ...] = ()
    unset_fields: tuple[str, ...] = ("recipient", "sent_at", "message_id")

    def canonical_body(self) -> dict:
        return self.model_dump(mode="json")


def _operator_items(path: Path | None) -> tuple[ScnItem, ...]:
    if path is None:
        return ()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _scn_fail(f"operator change file is not JSON: {exc}")
        raise AssertionError("unreachable")
    if not isinstance(raw, dict) or set(raw) - {"schema_version", "changes"}:
        _scn_fail("operator change file has an unknown shape")
    if raw.get("schema_version") != 1 or not isinstance(raw.get("changes"), list):
        _scn_fail("operator change file has an unknown shape")
    items: list[ScnItem] = []
    for row in raw["changes"]:
        if not isinstance(row, dict) or _SECRET_KEYS.intersection(row):
            _scn_fail("operator change file has an unknown shape")
        allowed = {"change_id", "summary", "evidence_sha256", "control_refs"}
        if set(row) - allowed or "change_id" not in row or "summary" not in row:
            _scn_fail("operator change file has an unknown shape")
        refs = row.get("control_refs") or []
        if not isinstance(refs, list):
            _scn_fail("operator change file has an unknown shape")
        try:
            items.append(
                ScnItem(
                    basis="operator_file",
                    change_id=row["change_id"],
                    summary=row["summary"],
                    evidence_sha256=row.get("evidence_sha256"),
                    control_refs=tuple(refs),
                )
            )
        except ValidationError as exc:
            _scn_fail(str(exc))
    return tuple(items)


def draft_scn(
    settings: Settings,
    *,
    package_class: PackageClass = "c",
    scope_id: str | None = None,
    pack_path: Path | None = None,
    scf_id: str | None = None,
    changes_path: Path | None = None,
) -> ScnDraft:
    """Build one SCN draft. The function does not open a socket."""
    try:
        ledger = load_evidence_ledger(
            settings,
            scope_id=scope_id,
            pack_path=pack_path,
            scf_id=scf_id,
        )
        report = ledger_method_report(
            settings,
            package_class=package_class,
            scope_id=scope_id,
            pack_path=pack_path,
            scf_id=scf_id,
        )
    except BeaconError as exc:
        if exc.code == E_LEDGER:
            raise
        _scn_fail(str(exc))
        raise AssertionError("unreachable")
    gaps = tuple(
        PackageGap(
            ksi_id=row.ksi_id,
            automated_method_ids=row.automated_method_ids,
            manual_method_ids=row.manual_method_ids,
            automated_method_count=row.automated_method_count,
            minimum=row.minimum,
            shortfall=row.shortfall,
        )
        for row in report.counts
        if row.shortfall > 0
    )
    pointers: list[EvidencePointer] = []
    seal_items: list[ScnItem] = []
    for entry in ledger.entries:
        try:
            pointers.append(EvidencePointer(sha256=entry.seal_sha256))
        except ValidationError as exc:
            _scn_fail(str(exc))
        refs = tuple(item for item in entry.scf_ids if item in SEEDED_CONTROL_IDS)
        seal_items.append(
            ScnItem(
                basis="sealed_observation",
                change_id=f"seal-{entry.seq}",
                summary=f"Sealed observation {entry.evidence_id}",
                evidence_sha256=entry.seal_sha256,
                control_refs=refs,
            )
        )
    gap_items = [
        ScnItem(
            basis="package_gap",
            change_id=f"gap-{gap.ksi_id}",
            summary=f"Package gap for {gap.ksi_id}",
            shortfall=gap.shortfall,
        )
        for gap in gaps
    ]
    draft = ScnDraft(
        scope_id=ledger.scope_id,
        scope_sha256=ledger.scope_sha256,
        package_class=report.package_class,
        package_gaps=gaps,
        evidence=tuple(pointers),
        items=tuple(gap_items) + tuple(seal_items) + _operator_items(changes_path),
    )
    _no_claim(draft.canonical_body())
    if draft.record_v != CHAIN_VERSION:
        _scn_fail("record version must stay 1")
    return draft


def write_scn(draft: ScnDraft, out_dir: Path) -> Path:
    """Write the draft JSON. This function does not send the notice."""
    if draft.mailed or draft.delivery != "not-sent":
        _scn_fail("SCN draft must stay unsent")
    out_dir.mkdir(parents=True, exist_ok=True)
    digest = sha256_bytes(dumps(draft.canonical_body()))
    path = out_dir / f"scn-{digest[:16]}.json"
    path.write_bytes(dumps(draft.canonical_body()) + b"\n")
    return path
