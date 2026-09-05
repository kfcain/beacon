"""Workspace bootstrap: keys, TSA, layout."""

from __future__ import annotations

import json

from beacon import __version__
from beacon.config import Settings, ensure_layout
from beacon.crypto.keys import generate_distinct_roles, load_roles
from beacon.crypto.tsa import generate_tsa
from beacon.crypto.witness import check_chain, checkpoint_status, load_checkpoints, load_records
from beacon.plugins.loader import load_plugins
from beacon.plugins.spec import CollectContext
from beacon.scf.client import expected_version, summary
from beacon.scf.engine import collect_all


def init_workspace(settings: Settings) -> dict:
    ensure_layout(settings)
    recorder, witness = generate_distinct_roles(settings.keys_dir)
    generate_tsa(settings.keys_dir)
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
    }


def freshness(settings: Settings) -> list[dict]:
    records = load_records(settings)
    latest: dict[str, dict] = {}
    for record in records:
        latest[record.plugin] = {
            "plugin": record.plugin,
            "seq": record.seq,
            "ts": record.ts,
            "mode": record.mode,
            "evidence_id": record.evidence_id,
            "scf_targets": record.scf_targets,
        }
    return list(latest.values())


def validation(settings: Settings) -> dict:
    try:
        result = check_chain(settings)
        return {"ok": True, "code": "OK", **result}
    except Exception as exc:
        code = getattr(exc, "code", "E_CHECK")
        return {"ok": False, "code": code, "message": str(exc)}
