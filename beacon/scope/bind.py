"""Copy and check the assessment scope pair on sealed observations.

Phase 2 puts ``scope_id`` and ``scope_sha256`` in the observation payload.
The witness ``Record`` stays version 1. This module does not call Jev.
"""

from __future__ import annotations

import json
from typing import Any

from beacon.config import Settings
from beacon.errors import E_SCOPE, fail
from beacon.scope.document import ScopeDocument
from beacon.scope.store import load_scope

SCOPE_ID_FIELD = "scope_id"
SCOPE_HASH_FIELD = "scope_sha256"


def collect_scope(settings: Settings, scope_id: str | None) -> ScopeDocument | None:
    """Load the scope for a collect run. A missing file fails closed."""
    if scope_id is None:
        if settings.require_scope:
            fail(E_SCOPE, "BEACON_REQUIRE_SCOPE=1 requires --scope")
        return None
    return load_scope(settings, scope_id)


def bind_observation_payload(payload: dict[str, Any], document: ScopeDocument) -> dict[str, Any]:
    """Copy the scope pair into one observation payload.

    A payload that already carries a different pair is left unchanged and
    the call fails closed. This function does not rewrite that pair.
    """
    bound = dict(payload)
    scope_id = document.scope_id
    digest = document.content_sha256()
    has_id = SCOPE_ID_FIELD in bound
    has_hash = SCOPE_HASH_FIELD in bound
    if has_id or has_hash:
        if not has_id or not has_hash:
            fail(E_SCOPE, "observation payload scope bind is incomplete")
        if bound[SCOPE_ID_FIELD] != scope_id or bound[SCOPE_HASH_FIELD] != digest:
            fail(E_SCOPE, "observation payload already has a different scope")
        return bound
    bound[SCOPE_ID_FIELD] = scope_id
    bound[SCOPE_HASH_FIELD] = digest
    return bound


def scope_pair_from_payload(payload: object) -> tuple[str, str] | None:
    """Return the sealed pair. A partial pair fails closed.

    A payload with neither field has no bind. Check keeps the current rules
    for that record.
    """
    if not isinstance(payload, dict):
        return None
    has_id = SCOPE_ID_FIELD in payload
    has_hash = SCOPE_HASH_FIELD in payload
    if not has_id and not has_hash:
        return None
    if not has_id or not has_hash:
        fail(E_SCOPE, "observation payload scope bind is incomplete")
    scope_id = payload[SCOPE_ID_FIELD]
    digest = payload[SCOPE_HASH_FIELD]
    if not isinstance(scope_id, str) or not isinstance(digest, str):
        fail(E_SCOPE, "observation payload scope bind must be strings")
    if not scope_id or not digest:
        fail(E_SCOPE, "observation payload scope bind is empty")
    return scope_id, digest


def scope_pair_from_bytes(payload_bytes: bytes) -> tuple[str, str] | None:
    """Read a pair from sealed observation bytes.

    Bytes that are not a JSON object have no bind. The hash check still
    applies to those bytes.
    """
    try:
        parsed = json.loads(payload_bytes)
    except json.JSONDecodeError:
        return None
    return scope_pair_from_payload(parsed)


def verify_payload_scope(
    settings: Settings,
    seq: int,
    payload_bytes: bytes,
    *,
    requested: ScopeDocument | None,
) -> None:
    """Reload the scope file and compare ``content_sha256()`` to the payload.

    ``requested`` is the document named by ``--scope``. A record with no pair
    stays on the current check rules.
    """
    pair = scope_pair_from_bytes(payload_bytes)
    if pair is None:
        return
    got_id, got_hash = pair
    if requested is not None and got_id != requested.scope_id:
        fail(E_SCOPE, f"seq {seq} scope id does not match --scope")
    document = requested if requested is not None else load_scope(settings, got_id)
    if got_hash != document.content_sha256():
        fail(E_SCOPE, f"seq {seq} scope hash mismatch")
