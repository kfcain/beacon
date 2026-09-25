"""Workspace bootstrap: keys, TSA, layout."""

from __future__ import annotations

import json

from beacon import __version__
from beacon.config import Settings, ensure_layout, observation_expires_at, observation_is_expired
from beacon.crypto.keys import generate_distinct_roles, load_roles
from beacon.crypto.tsa import generate_tsa
from beacon.crypto.trust import initialize_trust
from beacon.locking import locked
from beacon.crypto.witness import check_chain, checkpoint_status, load_checkpoints, load_records
from beacon.errors import E_ALREADY_INITIALIZED, BeaconError, fail
from beacon.plugins.loader import load_plugins
from beacon.plugins.spec import CollectContext
from beacon.scf.client import expected_version, summary
from beacon.scf.engine import collect_all
from beacon.storage.s3 import remote_ready


@locked
def init_workspace(settings: Settings) -> dict:
    ensure_layout(settings)
    if (settings.keys_dir / "recorder.pem").exists():
        fail(E_ALREADY_INITIALIZED, "workspace already initialized; remove .beacon/keys to recreate")
    recorder, witness = generate_distinct_roles(settings.keys_dir)
    generate_tsa(settings.keys_dir)
    initialize_trust(settings, recorder.fingerprint(), witness.fingerprint())
    meta = {
        "version": __version__,
        "recorder_fingerprint": recorder.fingerprint(),
        "witness_fingerprint": witness.fingerprint(),
        "scf_version": expected_version(),
    }
    (settings.home / "config.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta


def seed_workspace(settings: Settings) -> dict:
    ensure_layout(settings)
    load_roles(settings.keys_dir)
    ctx = CollectContext(live=False, extra={"force_fixture": True})
    return collect_all(settings, ctx, checkpoint=True)


def system_status(settings: Settings) -> dict:
    initialized = (settings.keys_dir / "recorder.pem").exists()
    recorder_fp = witness_fp = None
    if initialized:
        recorder, witness = load_roles(settings.keys_dir)
        recorder_fp = recorder.fingerprint()
        witness_fp = witness.fingerprint()
    chain = checkpoint_status(settings) if initialized else {}
    plugins = []
    if initialized:
        plugins = [
            {
                "name": plugin.spec.name,
                "version": plugin.spec.version,
                "scf_targets": list(plugin.spec.scf_targets),
                "tools": list(plugin.spec.tools),
            }
            for plugin in load_plugins(settings).values()
        ]
    scf = summary(settings)
    return {
        "initialized": initialized,
        "home": str(settings.home),
        "version": __version__,
        "recorder_fingerprint": recorder_fp,
        "witness_fingerprint": witness_fp,
        "keys_distinct": bool(recorder_fp and witness_fp and recorder_fp != witness_fp),
        "scf_offline": settings.scf_offline,
        "scf_api_base": settings.scf_api_base,
        "scf_version": scf.get("scf_version", expected_version()),
        "chain": chain,
        "plugins": plugins,
        "records": len(load_records(settings)) if initialized else 0,
        "checkpoints": len(load_checkpoints(settings)) if initialized else 0,
        "storage": {
            "enabled": bool(settings.s3_bucket),
            "s3_bucket": settings.s3_bucket,
            "s3_prefix": settings.s3_prefix or None,
            "ddb_table": settings.ddb_table,
            "kms_key_arn": settings.kms_key_arn,
            "tenant_id": settings.tenant_id,
            "workspace_id": settings.workspace_id,
            "require_remote": settings.require_remote,
            "object_lock_mode": settings.object_lock_mode,
            "object_lock_days": settings.object_lock_days,
            "pack_type": settings.pack_type,
            "trust_center_export": settings.trust_center_export,
        },
    }


def freshness(settings: Settings) -> list[dict]:
    records = load_records(settings)
    latest: dict[str, dict] = {}
    for record in records:
        try:
            expires_at = observation_expires_at(record.ts)
            expired = observation_is_expired(record.ts)
        except ValueError:
            expires_at = ""
            expired = True
        latest[record.plugin] = {
            "plugin": record.plugin,
            "seq": record.seq,
            "ts": record.ts,
            "sealed_at": record.ts,
            "expires_at": expires_at,
            "expired": expired,
            "mode": record.mode,
            "evidence_id": record.evidence_id,
            "scf_targets": record.scf_targets,
        }
    rows = list(latest.values())
    if settings.s3_bucket:
        try:
            lake = remote_ready(settings)
        except BeaconError:
            lake = None
        if lake is not None:
            remote = {str(item.get("plugin") or ""): item for item in lake.query_freshness()}
            for row in rows:
                extra = remote.get(row["plugin"])
                if not extra:
                    continue
                if extra.get("expires_at"):
                    row["expires_at"] = extra["expires_at"]
                if "expired" in extra:
                    row["expired"] = extra["expired"]
                row["remote"] = True
    return rows


def validation(settings: Settings) -> dict:
    try:
        result = check_chain(settings)
        return {"ok": True, "code": "OK", **result}
    except Exception as exc:
        code = getattr(exc, "code", "E_CHECK")
        return {"ok": False, "code": code, "message": str(exc)}
