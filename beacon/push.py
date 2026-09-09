"""Export a sealed evidence pack for Push."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from beacon import __version__
from beacon.canonical import dumps
from beacon.config import Settings
from beacon.crypto.witness import load_checkpoints, load_records
from beacon.errors import E_NOT_INITIALIZED, fail
from beacon.storage import publish_pack


@dataclass
class PackWrite:
    path: Path
    remote: dict[str, Any] | None = None


def write_pack(settings: Settings, out_path: Path | None = None) -> PackWrite:
    rec_pub = settings.keys_dir / "recorder.pub"
    wit_pub = settings.keys_dir / "witness.pub"
    tsa_crt = settings.keys_dir / "tsa.crt"
    if not rec_pub.exists():
        fail(E_NOT_INITIALIZED, "run `beacon init` first")
    records = load_records(settings)
    checkpoints = load_checkpoints(settings)
    evidence = []
    for record in records:
        path = settings.evidence_dir / f"{record.evidence_id}.json"
        body = path.read_text(encoding="utf-8") if path.exists() else None
        evidence.append({"evidence_id": record.evidence_id, "payload": body})
    pack = {
        "format": "beacon-pack/v1",
        "version": __version__,
        "exported_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
        "recorder_pub_pem": rec_pub.read_text(encoding="utf-8"),
        "witness_pub_pem": wit_pub.read_text(encoding="utf-8"),
        "tsa_cert_pem": tsa_crt.read_text(encoding="utf-8") if tsa_crt.exists() else None,
        "records": [row.to_dict() for row in records],
        "checkpoints": [row.to_dict() for row in checkpoints],
        "evidence": evidence,
    }
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if out_path is None:
        out_path = settings.export_dir / f"beacon-pack-{stamp}.json"
    else:
        name = Path(out_path).name
        if name.startswith("beacon-pack-") and name.endswith(".json"):
            stamp = name[len("beacon-pack-") : -len(".json")]
    out_path.write_bytes(dumps(pack))
    remote = publish_pack(settings, out_path, stamp=stamp)
    return PackWrite(path=out_path, remote=remote)
