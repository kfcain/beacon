"""Write allowlisted pack and report copies on the local trust-center tree.

The relative keys match the lake prefix ``public/trust-center/``.
This module does not open a network connection and does not host a site.
``BEACON_TRUST_CENTER_EXPORT=1`` is required before a file is written.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from beacon.assurance.index import assert_no_claim_words, ledger_method_report
from beacon.canonical import dumps, sha256_bytes
from beacon.config import PACK_TYPES, Settings
from beacon.crypto.witness import CHAIN_VERSION
from beacon.locking import locked
from beacon.errors import E_TRUST, BeaconError, fail
from beacon.scope.document import SCOPE_ID_RE
from beacon.storage.s3 import (
    TRUST_CENTER_KINDS,
    _reject_secret_bytes,
    assert_key_kind_allowed,
    trust_center_object_key,
)

ExportKind = Literal["pack", "report"]
LOCAL_PACK_FOLDERS = PACK_TYPES | frozenset({"cpo"})
_ARTIFACT_ID = SCOPE_ID_RE
_STRIP_KEYS = frozenset(
    {
        "payload",
        "observation",
        "observations",
        "private_key",
        "pem",
        "secret",
        "password",
        "token",
    }
)


def _trust_fail(message: str) -> None:
    fail(E_TRUST, message)


class TrustExport(BaseModel):
    """One local copy. ``hosted`` stays false. The bytes are not a public site."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    trust_center: Literal[True] = True
    hosted: Literal[False] = False
    kind: ExportKind
    relative: str
    object_key: str | None = None
    sha256: str
    path: str
    record_v: Literal[1] = 1
    content_type: str

    @field_validator("relative")
    @classmethod
    def relative_is_allowlisted(cls, value: str) -> str:
        classify_relative(value)
        return value


def classify_relative(relative: str) -> ExportKind:
    """Return pack or report. Any other relative key fails closed."""
    try:
        key = trust_center_object_key("local", "local", relative)
    except BeaconError as exc:
        _trust_fail(str(exc))
        raise AssertionError("unreachable")
    parts = [part for part in relative.replace("\\", "/").split("/") if part not in {"", "."}]
    kind = _allowlisted_kind(parts)
    assert_key_kind_allowed(key, kind, tenant_id="local", workspace_id="local")
    if kind not in TRUST_CENTER_KINDS:
        _trust_fail("trust-center allowlist is pack and report only")
    return kind


def _allowlisted_kind(parts: list[str]) -> ExportKind:
    if len(parts) == 4 and parts[0] == "packs":
        folder, artifact_id, name = parts[1], parts[2], parts[3]
        if folder not in LOCAL_PACK_FOLDERS or not _ARTIFACT_ID.fullmatch(artifact_id):
            _trust_fail("trust-center pack path is outside the allowlist")
        if name == "beacon-pack.json":
            return "pack"
        if name == "report.md":
            return "report"
        _trust_fail("trust-center pack path is outside the allowlist")
    if len(parts) == 2 and parts[0] == "activity-log" and parts[1].endswith(".jsonl"):
        artifact_id = parts[1][: -len(".jsonl")]
        if _ARTIFACT_ID.fullmatch(artifact_id):
            return "report"
    if len(parts) == 3 and parts[0] == "ledger" and parts[2] == "summary.json":
        if _ARTIFACT_ID.fullmatch(parts[1]):
            return "report"
    _trust_fail("trust-center path is outside the allowlist")
    raise AssertionError("unreachable")


def _require_export_flag(settings: Settings) -> None:
    if not settings.trust_center_export:
        _trust_fail("set BEACON_TRUST_CENTER_EXPORT=1 to write the local trust-center tree")


def _contained(root: Path, relative: str) -> Path:
    root_resolved = root.resolve()
    target = (root_resolved / relative).resolve()
    if not target.is_relative_to(root_resolved):
        _trust_fail("trust-center path escapes the export root")
    return target


def _object_key(settings: Settings, relative: str) -> str | None:
    if not settings.tenant_id or not settings.workspace_id:
        return None
    return trust_center_object_key(
        settings.tenant_id,
        settings.workspace_id,
        relative,
        prefix=settings.s3_prefix,
    )


def _strip(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _strip(item) for key, item in value.items() if key not in _STRIP_KEYS}
    if isinstance(value, list):
        return [_strip(item) for item in value]
    return value


def _public_json(body: bytes) -> bytes:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _trust_fail("trust-center pack must be JSON")
    if not isinstance(data, dict):
        _trust_fail("trust-center pack must be a JSON object")
    try:
        _reject_secret_bytes(body, name="trust-center pack")
    except BeaconError as exc:
        _trust_fail(str(exc))
    public = _strip(data)
    rows = []
    for row in public.get("evidence") or []:
        if not isinstance(row, dict):
            _trust_fail("trust-center evidence row must be an object")
        pointer = {}
        if isinstance(row.get("sha256"), str):
            pointer["sha256"] = row["sha256"]
        if isinstance(row.get("evidence_id"), str):
            pointer["evidence_id"] = row["evidence_id"]
        if isinstance(row.get("git_sha"), str):
            pointer["git_sha"] = row["git_sha"]
        rows.append(pointer)
    if "evidence" in public:
        public["evidence"] = rows
    public["trust_center"] = True
    public["hosted"] = False
    public["record_v"] = CHAIN_VERSION
    public["assurance_claim"] = False
    public["content_verification"] = "operator_supplied_draft"
    try:
        assert_no_claim_words(public)
    except BeaconError as exc:
        _trust_fail(str(exc))
    return dumps(public)


def _public_markdown(body: bytes) -> bytes:
    try:
        _reject_secret_bytes(body, name="trust-center report")
    except BeaconError as exc:
        _trust_fail(str(exc))
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        _trust_fail("trust-center report must be UTF-8 text")
    if re.search(r"(?i)observations/", text):
        _trust_fail("trust-center report refuses an observations path")
    try:
        assert_no_claim_words({"markdown": text})
    except BeaconError as exc:
        _trust_fail(str(exc))
    return text.encode("utf-8")


@locked
def publish_bytes(
    settings: Settings,
    *,
    relative: str,
    body: bytes,
    out_dir: Path,
) -> TrustExport:
    """Write one allowlisted object under ``out_dir``. A bad relative key fails closed."""
    _require_export_flag(settings)
    from beacon.assurance.admission import verified_snapshot
    verified_snapshot(settings)
    kind = classify_relative(relative)
    if kind == "pack" or relative.endswith(".json"):
        export_body = _public_json(body)
        content_type = "application/json"
    elif relative.endswith(".md"):
        export_body = _public_markdown(body)
        content_type = "text/markdown; charset=utf-8"
    elif relative.endswith(".jsonl"):
        try:
            _reject_secret_bytes(body, name="trust-center activity log")
        except BeaconError as exc:
            _trust_fail(str(exc))
        export_body = body
        content_type = "application/x-ndjson"
    else:
        _trust_fail("trust-center path is outside the allowlist")
        raise AssertionError("unreachable")
    target = _contained(out_dir, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(export_body)
    digest = sha256_bytes(export_body)
    record = TrustExport(
        kind=kind,
        relative=relative,
        object_key=_object_key(settings, relative),
        sha256=digest,
        path=str(target),
        content_type=content_type,
    )
    return record


def publish_ledger_summary(
    settings: Settings,
    *,
    artifact_id: str,
    out_dir: Path,
    package_class: str = "c",
    scope_id: str | None = None,
    pack_path: Path | None = None,
    scf_id: str | None = None,
) -> TrustExport:
    """Publish one ledger gap report. The file has no observation body."""
    match package_class:
        case "c" | "d":
            chosen_class = package_class
        case _:
            _trust_fail("package class must be c or d")
            raise AssertionError("unreachable")
    report = ledger_method_report(
        settings,
        package_class=chosen_class,
        scope_id=scope_id,
        pack_path=pack_path,
        scf_id=scf_id,
    )
    body = {
        "schema_version": 1,
        "draft": True,
        "kind": "ledger-summary",
        "package_class": report.package_class,
        "minimum": report.minimum,
        "required_list_supplied": report.required_list_supplied,
        "counts": [row.model_dump(mode="json") for row in report.counts],
        "below_minimum": list(report.below_minimum),
        "record_v": CHAIN_VERSION,
    }
    relative = f"ledger/{artifact_id}/summary.json"
    return publish_bytes(settings, relative=relative, body=dumps(body), out_dir=out_dir)
