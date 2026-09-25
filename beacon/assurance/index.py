"""Index sealed observations. Custody metadata only. This module does not claim a control."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from beacon.assurance.ledger import LedgerGapReport, MethodRecord, PackageClass, ksi_method_report
from beacon.assurance.tags import Tag, parse_tag
from beacon.canonical import sha256_bytes
from beacon.config import Settings
from beacon.crypto.witness import Record, load_records
from beacon.errors import E_LEDGER, E_SCOPE, BeaconError, fail
from beacon.scope.bind import scope_pair_from_payload
from beacon.scope.document import SCOPE_ID_RE, ScopeDocument
from beacon.scope.store import load_scope
from beacon.locking import locked
from beacon.assurance.admission import verified_snapshot, eligibility

SourceKind = Literal["chain", "pack"]

# Substrings that must not appear in ledger JSON. A count is not a claim.
CLAIM_WORDS: tuple[str, ...] = ("compliant", "evidenced", "proven", "Implemented", " met", "\"met\"")


class EvidenceIndexEntry(BaseModel):
    """One sealed observation. The observation body stays out of this entry."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str
    seq: int = Field(ge=1)
    plugin: str
    scf_ids: tuple[str, ...]
    scope_id: str | None = None
    scope_sha256: str | None = None
    tags: tuple[str, ...] = ()
    seal_sha256: str
    sealed_at: str
    eligible: bool = False
    exclusion_reasons: tuple[str, ...] = ()


class EvidenceLedger(BaseModel):
    """Custody index for one local chain or one pack file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: SourceKind
    scope_id: str | None = None
    scope_sha256: str | None = None
    entries: tuple[EvidenceIndexEntry, ...]


def _ledger_fail(message: str) -> None:
    fail(E_LEDGER, message)


def assert_no_claim_words(body: object) -> None:
    """Refuse ledger JSON that contains a claim word."""
    text = json.dumps(body)
    for word in CLAIM_WORDS:
        if word in text:
            _ledger_fail("ledger output contains a claim word")


def _safe_scf_id(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if not SCOPE_ID_RE.fullmatch(value):
        _ledger_fail("scf id must match the safe id pattern")
    return value


def _scf_ids_from_payload(payload: dict[str, Any], record: Record) -> tuple[str, ...]:
    found: list[str] = []
    for item in record.scf_targets:
        scf_id = _safe_scf_id(item)
        if scf_id is not None and scf_id not in found:
            found.append(scf_id)
    top = _safe_scf_id(payload.get("scf"))
    if top is not None and top not in found:
        found.append(top)
    binding = payload.get("scf_binding")
    if isinstance(binding, dict):
        single = _safe_scf_id(binding.get("scf_id"))
        if single is not None and single not in found:
            found.append(single)
        many = binding.get("scf_ids")
        if isinstance(many, list):
            for item in many:
                scf_id = _safe_scf_id(item)
                if scf_id is not None and scf_id not in found:
                    found.append(scf_id)
    return tuple(found)


def _parse_tags(payload: dict[str, Any]) -> tuple[Tag, ...]:
    raw = payload.get("tags")
    if raw is None:
        return ()
    if not isinstance(raw, list):
        _ledger_fail("payload tags must be a list")
    parsed: list[Tag] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            _ledger_fail("payload tag must be a string")
        try:
            tag = parse_tag(item)
        except ValueError as exc:
            _ledger_fail(str(exc))
        if tag.text() in seen:
            _ledger_fail("payload tags must not repeat")
        seen.add(tag.text())
        parsed.append(tag)
    return tuple(parsed)


def _payload_bytes(body: object) -> bytes:
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    _ledger_fail("sealed observation payload is missing")
    raise AssertionError("unreachable")


def _load_payload(body: object, record: Record) -> dict[str, Any]:
    raw = _payload_bytes(body)
    if sha256_bytes(raw) != record.payload_sha256:
        _ledger_fail(f"seq {record.seq} seal digest does not match the observation")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _ledger_fail(f"seq {record.seq} observation payload is not JSON")
    if not isinstance(parsed, dict):
        _ledger_fail(f"seq {record.seq} observation payload is not an object")
    return parsed


def _require_complete_method_tags(seq: int, tags: tuple[Tag, ...]) -> None:
    evidence = [tag for tag in tags if tag.namespace == "evidence"]
    automation = [tag for tag in tags if tag.namespace == "automation"]
    if not evidence and not automation:
        return
    if not evidence or len(automation) != 1:
        _ledger_fail(f"seq {seq} method tags are incomplete")


def _entry_from_payload(record: Record, payload: dict[str, Any]) -> tuple[EvidenceIndexEntry, tuple[Tag, ...]]:
    try:
        pair = scope_pair_from_payload(payload)
    except BeaconError:
        raise
    tags = _parse_tags(payload)
    _require_complete_method_tags(record.seq, tags)
    scf_ids = list(_scf_ids_from_payload(payload, record))
    for tag in tags:
        if tag.namespace == "control" and tag.value not in scf_ids:
            scf_ids.append(tag.value)
    scope_id = pair[0] if pair is not None else None
    scope_sha256 = pair[1] if pair is not None else None
    entry = EvidenceIndexEntry(
        evidence_id=record.evidence_id,
        seq=record.seq,
        plugin=record.plugin,
        scf_ids=tuple(scf_ids),
        scope_id=scope_id,
        scope_sha256=scope_sha256,
        tags=tuple(sorted(tag.text() for tag in tags)),
        seal_sha256=record.payload_sha256,
        sealed_at=record.ts,
    )
    return entry, tags


def _chain_bodies(settings: Settings) -> list[tuple[Record, object]]:
    rows: list[tuple[Record, object]] = []
    for record in load_records(settings):
        path = settings.evidence_dir / f"{record.evidence_id}.json"
        if not path.is_file():
            _ledger_fail(f"seq {record.seq} observation file is missing")
        rows.append((record, path.read_bytes()))
    return rows


def _pack_bodies(pack_path: Path) -> list[tuple[Record, object]]:
    try:
        pack = json.loads(pack_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _ledger_fail(f"pack file cannot be read: {exc}")
    if not isinstance(pack, dict):
        _ledger_fail("pack file is not an object")
    raw_records = pack.get("records")
    raw_evidence = pack.get("evidence")
    if not isinstance(raw_records, list) or not isinstance(raw_evidence, list):
        _ledger_fail("pack file has no records and evidence lists")
    by_id: dict[str, object] = {}
    for row in raw_evidence:
        if not isinstance(row, dict) or not isinstance(row.get("evidence_id"), str):
            _ledger_fail("pack evidence row is not an object")
        by_id[row["evidence_id"]] = row.get("payload")
    bodies: list[tuple[Record, object]] = []
    for row in raw_records:
        if not isinstance(row, dict):
            _ledger_fail("pack record is not an object")
        if row.get("v") != 1:
            _ledger_fail("pack record version must stay 1")
        try:
            record = Record.from_dict(row)
        except (KeyError, TypeError, ValueError) as exc:
            _ledger_fail(f"pack record cannot be read: {exc}")
        if record.evidence_id not in by_id:
            _ledger_fail(f"seq {record.seq} pack evidence is missing")
        bodies.append((record, by_id[record.evidence_id]))
    return bodies


def _scope_document(settings: Settings, scope_id: str | None) -> ScopeDocument | None:
    if scope_id is None:
        return None
    return load_scope(settings, scope_id)


@locked
def load_evidence_ledger(
    settings: Settings,
    *,
    scope_id: str | None = None,
    pack_path: Path | None = None,
    scf_id: str | None = None,
) -> EvidenceLedger:
    """Index local seals or one pack. ``--scope`` reuses the scope bind pair."""
    if scf_id is not None and _safe_scf_id(scf_id) is None:
        _ledger_fail("scf filter must match the safe id pattern")
    document = _scope_document(settings, scope_id)
    expected_hash = document.content_sha256() if document is not None else None
    source: SourceKind = "pack" if pack_path is not None else "chain"
    snapshot = verified_snapshot(settings, pack_path=pack_path)
    bodies = [(record, snapshot.payloads[record.evidence_id]) for record in snapshot.records]
    entries: list[EvidenceIndexEntry] = []
    for record, body in bodies:
        if record.v != 1:
            _ledger_fail("record version must stay 1")
        payload = body
        entry, _tags = _entry_from_payload(record, payload)
        reasons = eligibility(settings, record, payload)
        entry = entry.model_copy(update={"eligible": not reasons, "exclusion_reasons": reasons})
        if document is not None:
            if entry.scope_id is None:
                continue
            if entry.scope_id != document.scope_id:
                continue
            if entry.scope_sha256 != expected_hash:
                fail(E_SCOPE, f"seq {record.seq} scope hash mismatch")
        if scf_id is not None and scf_id not in entry.scf_ids:
            continue
        entries.append(entry)
    ledger = EvidenceLedger(
        source=source,
        scope_id=document.scope_id if document is not None else None,
        scope_sha256=expected_hash,
        entries=tuple(entries),
    )
    assert_no_claim_words(ledger.model_dump(mode="json"))
    return ledger


def method_records_for_entries(
    entries: tuple[EvidenceIndexEntry, ...] | list[EvidenceIndexEntry],
    payloads: dict[str, dict[str, Any]],
) -> list[MethodRecord]:
    """Build method rows from evidence tags on seals that share a scope pair.

    An evidence tag without an automation tag fails closed. A manual tag is
    kept and does not count. This function does not invent a KSI id.
    """
    records: list[MethodRecord] = []
    for entry in entries:
        if not entry.eligible:
            continue
        payload = payloads.get(entry.evidence_id)
        if payload is None:
            _ledger_fail(f"seq {entry.seq} observation payload is missing")
        tags = _parse_tags(payload)
        evidence = [tag for tag in tags if tag.namespace == "evidence"]
        automation = [tag for tag in tags if tag.namespace == "automation"]
        controls = [tag for tag in tags if tag.namespace == "control"]
        if not evidence and not automation:
            continue
        _require_complete_method_tags(entry.seq, tags)
        if entry.scope_id is None or entry.scope_sha256 is None:
            _ledger_fail(f"seq {entry.seq} method bind requires a scope pair")
        ksi_id = payload.get("ksi_id")
        if ksi_id is None:
            # A supporting observation without an approved crosswalk is still
            # evidence, but does not invent a KSI relationship.
            continue
        if not isinstance(ksi_id, str) or not SCOPE_ID_RE.fullmatch(ksi_id):
            _ledger_fail(f"seq {entry.seq} ksi id must match the safe id pattern")
        automated = automation[0].value == "automated"
        refs: list[str | None] = [tag.value for tag in controls] or [None]
        for method in evidence:
            for control_ref in refs:
                try:
                    records.append(
                        MethodRecord(
                            scope_id=entry.scope_id,
                            ksi_id=ksi_id,
                            method_id=method.value,
                            automated=automated,
                            evidence_sha256=entry.seal_sha256,
                            control_ref=control_ref,
                            sealed_at=entry.sealed_at,
                        )
                    )
                except ValidationError as exc:
                    _ledger_fail(f"seq {entry.seq} method record is not valid: {exc}")
    return records


def _payloads_for(
    settings: Settings,
    *,
    pack_path: Path | None,
    entries: tuple[EvidenceIndexEntry, ...],
) -> dict[str, dict[str, Any]]:
    wanted = {entry.evidence_id for entry in entries}
    bodies = _pack_bodies(pack_path) if pack_path is not None else _chain_bodies(settings)
    found: dict[str, dict[str, Any]] = {}
    for record, body in bodies:
        if record.evidence_id not in wanted:
            continue
        found[record.evidence_id] = _load_payload(body, record)
    return found


@locked
def ledger_method_report(
    settings: Settings,
    *,
    package_class: PackageClass,
    scope_id: str | None = None,
    pack_path: Path | None = None,
    scf_id: str | None = None,
    required_ksi_ids: list[str] | tuple[str, ...] | None = None,
    not_before: str | None = None,
) -> LedgerGapReport:
    """Count distinct automated evidence methods on seals under one scope."""
    ledger = load_evidence_ledger(
        settings,
        scope_id=scope_id,
        pack_path=pack_path,
        scf_id=scf_id,
    )
    payloads = _payloads_for(settings, pack_path=pack_path, entries=ledger.entries)
    records = method_records_for_entries(ledger.entries, payloads)
    seen_ksi_ids = sorted({p["ksi_id"] for p in payloads.values()
                           if isinstance(p.get("ksi_id"), str) and SCOPE_ID_RE.fullmatch(p["ksi_id"])})
    supplied = required_ksi_ids is not None
    if scf_id is not None:
        records = [row for row in records if row.control_ref == scf_id]
    try:
        report = ksi_method_report(
            records,
            package_class=package_class,
            required_ksi_ids=required_ksi_ids if supplied else (seen_ksi_ids or None),
            not_before=not_before,
        )
    except ValueError as exc:
        _ledger_fail(str(exc))
        raise AssertionError("unreachable")
    report = report.model_copy(update={"required_list_supplied": supplied,
        "excluded_ineligible": tuple(f"{entry.evidence_id}:{','.join(entry.exclusion_reasons)}"
                                     for entry in ledger.entries if not entry.eligible)})
    assert_no_claim_words(report.model_dump(mode="json"))
    return report
