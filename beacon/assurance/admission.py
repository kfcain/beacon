"""Verified snapshots and explicit evidence eligibility for every output path."""
from __future__ import annotations

import datetime as dt
import json
import shutil
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from beacon.canonical import dumps, sha256_obj
from beacon.config import ensure_layout, parse_iso8601
from beacon.crypto.trust import read_trust, atomic_write, ZERO
from beacon.crypto.witness import Record, check_chain, load_records
from beacon.errors import BeaconError, fail
from beacon.locking import locked
from beacon.scope.bind import scope_pair_from_payload
from beacon.scope.enforce import boundary_reasons, validate_plugin_scope
from beacon.scope.store import load_scope


@dataclass(frozen=True)
class VerifiedSnapshot:
    records: tuple[Record, ...]
    payloads: dict[str, dict]
    verification: dict


@locked
def verified_snapshot(settings, *, pack_path: Path | None = None) -> VerifiedSnapshot:
    # Whole-chain integrity is independent of a UI's selected scope. Every
    # bound payload is still checked against its own persisted scope document.
    verification = check_chain(replace(settings, require_scope=False))
    records = load_records(settings)
    if pack_path is None:
        payloads = {r.evidence_id: json.loads((settings.evidence_dir / f"{r.evidence_id}.json").read_bytes())
                    for r in records}
    else:
        try:
            pack = json.loads(pack_path.read_bytes())
            if pack.get("format") != "beacon-pack/v1":
                raise ValueError("unsupported pack format")
            selected = [Record.from_dict(row) for row in pack["records"]]
            if len(selected) > len(records) or any(sha256_obj(a.to_dict()) != sha256_obj(b.to_dict())
                                                   for a, b in zip(selected, records)):
                raise ValueError("pack is not a prefix of this workspace's trusted history")
            by_id = {row["evidence_id"]: row["payload"] for row in pack["evidence"]}
            if len(by_id) != len(pack["evidence"]) or set(by_id) != {r.evidence_id for r in selected}:
                raise ValueError("duplicate, missing, or extra pack evidence")
            with tempfile.TemporaryDirectory(prefix="beacon-pack-check-") as tmp:
                stage = replace(settings, home=Path(tmp), trust_file=None, anchor_dir=None,
                                require_external_anchor=False, require_scope=False)
                ensure_layout(stage)
                # Only verifier-owned public anchors are copied. The pack cannot
                # nominate its own trusted keys or timestamp certificate.
                (stage.keys_dir / "tsa.crt").write_bytes((settings.keys_dir / "tsa.crt").read_bytes())
                trust = read_trust(settings)
                atomic_write(stage.home / "trust.json", dumps(trust))
                atomic_write(stage.home / "retained-head.json", dumps({"schema_version": 1,
                    "workspace_id": trust["workspace_id"], "seq": 0, "sha256": ZERO}))
                if (settings.home / "scopes").exists():
                    shutil.copytree(settings.home / "scopes", stage.home / "scopes")
                stage.chain_path.write_bytes(b"".join(dumps(r.to_dict()) + b"\n" for r in selected))
                stage.checkpoints_path.write_bytes(b"".join(dumps(c) + b"\n" for c in pack["checkpoints"]))
                for record in selected:
                    # Membership above ensures evidence_id came from validated history.
                    body = by_id[record.evidence_id]
                    if not isinstance(body, str):
                        raise ValueError("pack evidence must contain the original UTF-8 payload")
                    (stage.evidence_dir / f"{record.evidence_id}.json").write_text(body, encoding="utf-8")
                check_chain(stage)
            records = selected
            payloads = {key: json.loads(body) for key, body in by_id.items()}
        except (OSError, ValueError, KeyError, TypeError) as exc:
            fail("E_PACK", f"pack verification failed: {exc}")
    for record in records:
        payload = payloads[record.evidence_id]
        if not isinstance(payload, dict):
            fail("E_BAD_CHAIN", "evidence payload must be an object")
        if settings.require_scope and scope_pair_from_payload(payload) is None:
            fail("E_SCOPE", "strict scope mode rejects unbound evidence")
    return VerifiedSnapshot(tuple(records), payloads, verification)


def eligibility(settings, record: Record, payload: dict, *, now=None, max_age_seconds=86400) -> tuple[str, ...]:
    """Integrity is established by verified_snapshot before this predicate runs.

    Local custody does not independently authenticate a remote collector. The
    configured collector and workspace administration remain trust boundaries.
    """
    reasons = []
    expected_cloud = {"aws.inspector": "aws", "aws.ebs.encryption": "aws", "aws.lake.logs": "aws",
                      "azure.inspector": "azure", "gcp.inspector": "gcp"}.get(record.plugin)
    if expected_cloud and payload.get("cloud") != expected_cloud:
        reasons.append("source_cloud_missing_or_mismatched")
    if record.plugin == "scf.catalog.offline":
        reasons.append("catalog_reference_only")
    if record.mode != "live" or payload.get("mode") != "live":
        reasons.append("not_live")
    if payload.get("ok") is not True or payload.get("collection_complete") is not True:
        reasons.append("collection_incomplete")
    if payload.get("source") != record.plugin:
        reasons.append("source_mismatch")
    pair = scope_pair_from_payload(payload)
    if pair is None:
        reasons.append("unbound_scope")
    else:
        document = load_scope(settings, pair[0])
        try:
            validate_plugin_scope(document, record.plugin)
        except BeaconError:
            reasons.append("evidence_kind_or_catalog_rejected")
        reasons.extend(boundary_reasons(document, payload))
    try:
        observed = payload["observed_at"]
        if not isinstance(observed, str) or dt.datetime.fromisoformat(observed.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("observation timestamp must carry a timezone")
        instant = parse_iso8601(observed)
        current = now or dt.datetime.now(dt.timezone.utc)
        age = (current - instant).total_seconds()
        if age < -60:
            reasons.append("observation_in_future")
        if age > max_age_seconds:
            reasons.append("evidence_stale")
        if instant > parse_iso8601(record.ts) + dt.timedelta(seconds=60):
            reasons.append("observation_after_seal")
    except (KeyError, TypeError, ValueError):
        reasons.append("observation_time_invalid")
    return tuple(sorted(set(reasons)))
