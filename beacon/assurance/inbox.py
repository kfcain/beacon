"""Intake a local FedRAMP security-inbox file.

A known message becomes a digest and a candidate. An unknown shape fails closed.
This module does not open a mailbox and does not read mailbox credentials.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from beacon.assurance.pin_ids import SEEDED_CONTROL_IDS
from beacon.canonical import dumps, sha256_bytes, sha256_obj
from beacon.crypto.witness import CHAIN_VERSION
from beacon.errors import E_INBOX, fail
from beacon.scope.document import SCOPE_ID_RE, SHA256_RE

InboxShape = Literal["evidence_candidate", "ticket_candidate"]
_SECRET_KEYS = frozenset(
    {"password", "secret", "token", "smtp", "imap", "mailbox", "credential", "api_key"}
)
CLAIM_MARKERS = ("compliant", "evidenced", "proven", "Implemented", " met", '"met"')


def _inbox_fail(message: str) -> None:
    fail(E_INBOX, message)


class InboxCandidate(BaseModel):
    """One digested message. ``role`` stays candidate. No reply is sent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    role: Literal["candidate"] = "candidate"
    shape: InboxShape
    message_id: str
    input_sha256: str
    subject: str
    control_refs: tuple[str, ...] = ()
    evidence_sha256: str | None = None
    summary: str | None = None
    ticket_id: str | None = None
    mailed: Literal[False] = False
    credential_used: Literal[False] = False
    record_v: Literal[1] = 1

    @field_validator("message_id", "ticket_id")
    @classmethod
    def id_is_safe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not SCOPE_ID_RE.fullmatch(value):
            raise ValueError("id must match the safe id pattern")
        return value

    @field_validator("input_sha256", "evidence_sha256")
    @classmethod
    def hash_is_sha256(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not SHA256_RE.fullmatch(value):
            raise ValueError("digest must be 64 lowercase hex characters")
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


def _messages(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict) and set(raw) == {"schema_version", "messages"}:
        if raw.get("schema_version") != 1 or not isinstance(raw.get("messages"), list):
            _inbox_fail("inbox file has an unknown shape")
        rows = raw["messages"]
    elif isinstance(raw, dict):
        rows = [raw]
    else:
        _inbox_fail("inbox file has an unknown shape")
        raise AssertionError("unreachable")
    if not rows:
        _inbox_fail("inbox file has no messages")
    cleaned: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            _inbox_fail("inbox file has an unknown shape")
        if _SECRET_KEYS.intersection(row):
            _inbox_fail("inbox file refuses credential fields")
        cleaned.append(row)
    return cleaned


def _one(row: dict[str, Any]) -> InboxCandidate:
    shape = row.get("shape")
    digest = sha256_obj(row)
    if shape == "evidence_candidate":
        allowed = {"schema_version", "shape", "message_id", "subject", "control_refs", "evidence_sha256"}
        if set(row) - allowed or row.get("schema_version") != 1:
            _inbox_fail("inbox file has an unknown shape")
        refs = row.get("control_refs") or []
        if not isinstance(refs, list) or not isinstance(row.get("evidence_sha256"), str):
            _inbox_fail("inbox file has an unknown shape")
        try:
            return InboxCandidate(
                shape="evidence_candidate",
                message_id=row["message_id"],
                input_sha256=digest,
                subject=row["subject"],
                control_refs=tuple(refs),
                evidence_sha256=row["evidence_sha256"],
            )
        except (ValidationError, KeyError) as exc:
            _inbox_fail(str(exc))
    if shape == "ticket_candidate":
        allowed = {"schema_version", "shape", "message_id", "subject", "summary"}
        if set(row) - allowed or row.get("schema_version") != 1:
            _inbox_fail("inbox file has an unknown shape")
        try:
            message_id = row["message_id"]
            return InboxCandidate(
                shape="ticket_candidate",
                message_id=message_id,
                input_sha256=digest,
                subject=row["subject"],
                summary=row["summary"],
                ticket_id=f"ticket-{message_id}",
            )
        except (ValidationError, KeyError) as exc:
            _inbox_fail(str(exc))
    _inbox_fail("inbox file has an unknown shape")
    raise AssertionError("unreachable")


def intake_inbox_file(path: Path, out_dir: Path) -> tuple[tuple[InboxCandidate, ...], tuple[Path, ...]]:
    """Digest each known message and write a candidate file. Unknown shapes fail closed."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _inbox_fail(f"inbox file is not JSON: {exc}")
        raise AssertionError("unreachable")
    candidates = tuple(_one(row) for row in _messages(raw))
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for candidate in candidates:
        body = candidate.model_dump(mode="json")
        text = json.dumps(body)
        for word in CLAIM_MARKERS:
            if word in text:
                _inbox_fail("inbox candidate must not contain a claim word")
        if candidate.record_v != CHAIN_VERSION or candidate.credential_used or candidate.mailed:
            _inbox_fail("inbox candidate must stay local and unsent")
        payload = dumps(body) + b"\n"
        target = out_dir / f"{candidate.shape}-{sha256_bytes(payload)[:16]}.json"
        target.write_bytes(payload)
        written.append(target)
    return candidates, tuple(written)
