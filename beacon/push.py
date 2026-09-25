"""Export a sealed evidence pack for Push."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from beacon import __version__
from beacon.canonical import dumps
from beacon.config import PACK_TYPES, Settings
from beacon.crypto.witness import load_checkpoints, load_records
from beacon.errors import E_NOT_INITIALIZED, E_REMOTE, E_SCOPE, fail
from beacon.scope.bind import SCOPE_HASH_FIELD, SCOPE_ID_FIELD, scope_pair_from_payload
from beacon.storage import publish_pack
from beacon.locking import locked


@dataclass
class PackWrite:
    path: Path
    remote: dict[str, Any] | None = None


def _pack_markdown(pack: dict[str, Any], *, pack_type: str) -> str:
    title = {
        "bundle": "Evidence bundle",
        "ongoing-certification-report": "Ongoing Certification Report",
        "secure-configuration-guide": "Secure Configuration Guide",
        "security-decision-record": "Security Decision Record",
    }.get(pack_type, "Evidence bundle")
    lines = [
        f"# {title}",
        "",
        f"- pack_type: {pack_type}",
        f"- format: {pack.get('format')}",
        f"- version: {pack.get('version')}",
        f"- exported_at: {pack.get('exported_at')}",
        "",
        "## Records",
        "",
    ]
    for row in pack.get("records") or []:
        lines.append(
            f"- seq {row.get('seq')} plugin={row.get('plugin')} "
            f"evidence_id={row.get('evidence_id')} "
            f"payload_sha256={row.get('payload_sha256')} "
            f"prev_sha256={row.get('prev_sha256')}"
        )
    lines.extend(
        [
            "",
            "This export is JSON plus Markdown. It does not include private keys.",
            "",
        ]
    )
    return "\n".join(lines)


def _pair_from_evidence_body(body: str | None) -> tuple[str, str] | None:
    """Copy a scope pair from one sealed payload. Do not invent a scope."""
    if body is None:
        return None
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        fail(E_SCOPE, "sealed observation payload is not JSON")
    return scope_pair_from_payload(parsed)


@locked
def write_pack(
    settings: Settings,
    out_path: Path | None = None,
    *,
    pack_type: str | None = None,
    draft: bool | None = None,
) -> PackWrite:
    from beacon.assurance.admission import verified_snapshot
    snapshot = verified_snapshot(settings)
    rec_pub = settings.keys_dir / "recorder.pub"
    wit_pub = settings.keys_dir / "witness.pub"
    tsa_crt = settings.keys_dir / "tsa.crt"
    if not rec_pub.exists():
        fail(E_NOT_INITIALIZED, "run `beacon init` first")
    chosen_type = (pack_type or settings.pack_type or "bundle").strip().lower()
    if chosen_type not in PACK_TYPES:
        fail(
            E_REMOTE,
            "BEACON_PACK_TYPE must be bundle, ongoing-certification-report, "
            "secure-configuration-guide, or security-decision-record",
        )
    records = load_records(settings)
    checkpoints = load_checkpoints(settings)
    evidence = []
    bound_pairs: list[tuple[str, str]] = []
    for record in records:
        path = settings.evidence_dir / f"{record.evidence_id}.json"
        body = path.read_text(encoding="utf-8") if path.exists() else None
        row: dict[str, Any] = {"evidence_id": record.evidence_id, "payload": body}
        pair = _pair_from_evidence_body(body)
        if pair is not None:
            row[SCOPE_ID_FIELD] = pair[0]
            row[SCOPE_HASH_FIELD] = pair[1]
            bound_pairs.append(pair)
        evidence.append(row)
    pack = {
        "format": "beacon-pack/v1",
        "version": __version__,
        "pack_type": chosen_type,
        "exported_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
        "recorder_pub_pem": rec_pub.read_text(encoding="utf-8"),
        "witness_pub_pem": wit_pub.read_text(encoding="utf-8"),
        "tsa_cert_pem": tsa_crt.read_text(encoding="utf-8") if tsa_crt.exists() else None,
        "records": [row.to_dict() for row in records],
        "checkpoints": [row.to_dict() for row in checkpoints],
        "evidence": evidence,
        "verification": snapshot.verification,
        "assurance_claim": False,
    }
    # One shared pair can sit on the pack. Mixed pairs stay on each evidence
    # row so push does not replace one sealed scope with another.
    if len(bound_pairs) == len(records) and len(set(bound_pairs)) == 1:
        scope_id, scope_sha256 = bound_pairs[0]
        pack[SCOPE_ID_FIELD] = scope_id
        pack[SCOPE_HASH_FIELD] = scope_sha256
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if out_path is None:
        out_path = settings.export_dir / f"beacon-pack-{stamp}.json"
    else:
        name = Path(out_path).name
        if name.startswith("beacon-pack-") and name.endswith(".json"):
            stamp = name[len("beacon-pack-") : -len(".json")]
    out_path.write_bytes(dumps(pack))
    md_path = out_path.with_suffix(".md")
    md_path.write_text(_pack_markdown(pack, pack_type=chosen_type), encoding="utf-8")
    remote = publish_pack(
        settings,
        out_path,
        stamp=stamp,
        markdown_path=md_path,
        pack_type=chosen_type,
        draft=draft,
    )
    return PackWrite(path=out_path, remote=remote)
