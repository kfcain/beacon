"""Local assessment scope files.

Phase 1 writes and reads ``.beacon/scopes/{scope_id}.json``.
This module does not collect, seal, push, or call Jev.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import ValidationError

from beacon.canonical import dumps
from beacon.config import Settings
from beacon.errors import E_SCOPE, E_UNKNOWN_SCOPE, E_UNSAFE_SCOPE_ID, fail
from beacon.scope.document import SCOPE_ID_RE, EVIDENCE_KINDS, Boundary, ScopeDocument
from beacon.scf.catalog_pin import PINNED_PILLAR_FRAMEWORK_IDS, PINNED_SCF_VERSION
from beacon.scope.v2 import parse_scope
from beacon.locking import locked

# Pillar framework id already on the 2026.3 pin. Not an SCF control id.
STARTER_FRAMEWORK = "general-nist-800-53-r5-2"
# Local label only. Init does not copy a cloud account or a credential.
STARTER_SYSTEM = "workspace"


def scopes_dir(settings: Settings) -> Path:
    return settings.home / "scopes"


def check_scope_id(scope_id: str) -> str:
    """Reject an id that is not a single safe path segment."""
    if not isinstance(scope_id, str) or not SCOPE_ID_RE.fullmatch(scope_id):
        fail(E_UNSAFE_SCOPE_ID, "scope id must match the safe id pattern")
    return scope_id


def scope_path(settings: Settings, scope_id: str) -> Path:
    """Return the scope file path. The id cannot leave ``scopes/``."""
    safe = check_scope_id(scope_id)
    root = scopes_dir(settings).resolve()
    path = (root / f"{safe}.json").resolve()
    if path.parent != root:
        fail(E_UNSAFE_SCOPE_ID, "scope id must not contain a path segment")
    return path


def new_scope_document(scope_id: str) -> ScopeDocument:
    """Build a schema version 1 document for one safe id.

    ``catalog_pin_version`` is the label already pinned in code.
    This function does not read or write ``PIN.json``.
    """
    safe = check_scope_id(scope_id)
    if STARTER_FRAMEWORK not in PINNED_PILLAR_FRAMEWORK_IDS:
        fail(E_SCOPE, "starter framework id is not on the pinned pillar list")
    return ScopeDocument(
        scope_id=safe,
        catalog_pin_version=PINNED_SCF_VERSION,
        frameworks=(STARTER_FRAMEWORK,),
        data_classes=(),
        exclusions=(),
        allowed_evidence_kinds=EVIDENCE_KINDS,
        boundary=Boundary(systems=(STARTER_SYSTEM,)),
    )


@locked
def init_scope(settings: Settings, scope_id: str) -> ScopeDocument:
    """Create the scope file. An existing file is left unchanged."""
    path = scope_path(settings, scope_id)
    if path.exists():
        fail(E_SCOPE, "scope file already exists")
    document = new_scope_document(scope_id)
    if document.scope_id != scope_id:
        fail(E_SCOPE, "scope id mismatch")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dumps(document.canonical_body()) + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    try:
        os.link(temporary, path)
    except FileExistsError:
        temporary.unlink(missing_ok=True)
        fail(E_SCOPE, "scope file already exists")
    temporary.unlink(missing_ok=True)
    return document


@locked
def import_scope(settings: Settings, raw: str) -> ScopeDocument:
    """Explicit operator enrollment; sealed scopes are immutable by id."""
    try:
        document = parse_scope(raw)
    except (ValueError, ValidationError) as exc:
        fail(E_SCOPE, f"invalid scope: {exc}")
    from beacon.scf.catalog_pin import PINNED_SCF_VERSION
    from beacon.assurance.pin_ids import framework_id_on_pin
    if document.catalog_pin_version != PINNED_SCF_VERSION or any(
        not framework_id_on_pin(item) for item in document.frameworks
    ):
        fail(E_SCOPE, "catalog or framework is outside the reviewed pin")
    path = scope_path(settings, document.scope_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(dumps(document.canonical_body()) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        fail(E_SCOPE, "scope already exists; use a new id for revisions")
    return document


def list_scopes(settings: Settings) -> list[dict]:
    return [{"scope_id": document.scope_id, "scope_sha256": document.content_sha256(),
             "schema_version": document.schema_version, "boundary": document.boundary.model_dump(mode="json")}
            for path in sorted(scopes_dir(settings).glob("*.json"))
            for document in [load_scope(settings, path.stem)]]


def load_scope(settings: Settings, scope_id: str) -> ScopeDocument:
    """Load one scope file. A missing or mismatched file fails closed."""
    path = scope_path(settings, scope_id)
    if not path.is_file():
        fail(E_UNKNOWN_SCOPE, "unknown scope id; scope file is missing")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(E_SCOPE, f"scope file cannot be read: {exc}")
    try:
        document = parse_scope(raw)
    except (ValidationError, ValueError):
        fail(E_SCOPE, "scope file is not a valid scope document")
    if document.scope_id != scope_id:
        fail(E_SCOPE, "scope id in the file does not match the requested id")
    return document


def scope_content_sha256(settings: Settings, scope_id: str) -> str:
    """Return ``ScopeDocument.content_sha256()`` for the stored document."""
    return load_scope(settings, scope_id).content_sha256()
