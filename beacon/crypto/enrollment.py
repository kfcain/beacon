"""Explicit migration and external-head enrollment with operator-supplied pins."""
from dataclasses import replace
import shutil
import tempfile
from pathlib import Path

from beacon.canonical import dumps, sha256_obj
from beacon.config import ensure_layout
from beacon.crypto.trust import atomic_write, read_trust, trust_path, local_head, external_head, ZERO
from beacon.crypto.witness import check_chain, load_records
from beacon.errors import fail
from beacon.locking import locked


@locked
def enroll(settings, *, recorder: str, witness: str, tsa_sha256: str, workspace_id: str,
           expected_seq: int, expected_head: str) -> dict:
    if trust_path(settings).exists() or local_head(settings).exists():
        fail("E_TRUST", "registry or retained head already exists; enrollment cannot reset trust")
    if settings.trust_file is not None:
        fail("E_TRUST", "enroll locally before configuring an independently managed trust file")
    trust = {"schema_version": 1, "workspace_id": workspace_id,
             "recorder": recorder, "witness": witness, "tsa_sha256": tsa_sha256}
    records = load_records(settings)
    digest = sha256_obj(records[-1].to_dict()) if records else ZERO
    if expected_seq != len(records) or expected_head != digest:
        fail("E_CONTINUITY", "operator-supplied head does not match this history")
    head = {"schema_version": 1, "workspace_id": workspace_id, "seq": expected_seq, "sha256": digest}
    with tempfile.TemporaryDirectory(prefix="beacon-enroll-") as tmp:
        stage = replace(settings, home=Path(tmp), anchor_dir=None, trust_file=None,
                        require_external_anchor=False, require_scope=False)
        ensure_layout(stage)
        atomic_write(trust_path(stage), dumps(trust))
        atomic_write(local_head(stage), dumps(head))
        read_trust(stage)
        shutil.copyfile(settings.keys_dir / "tsa.crt", stage.keys_dir / "tsa.crt")
        for src, dst in ((settings.chain_path, stage.chain_path), (settings.checkpoints_path, stage.checkpoints_path)):
            if src.exists():
                shutil.copyfile(src, dst)
        shutil.copytree(settings.evidence_dir, stage.evidence_dir, dirs_exist_ok=True)
        if (settings.home / "scopes").exists():
            shutil.copytree(settings.home / "scopes", stage.home / "scopes")
        verification = check_chain(stage)
    anchor = external_head(settings, trust)
    if anchor is not None:
        if anchor.exists():
            fail("E_CONTINUITY", "external head exists; refusing to replace it")
        atomic_write(anchor, dumps(head))
    atomic_write(trust_path(settings), dumps(trust))
    atomic_write(local_head(settings), dumps(head))
    return {"ok": True, "workspace_id": workspace_id, "head": head, "verification": verification}


@locked
def enroll_anchor(settings) -> dict:
    trust = read_trust(settings)
    anchor = external_head(settings, trust)
    if anchor is None:
        fail("E_CONTINUITY", "set BEACON_ANCHOR_DIR to an independently retained directory")
    if anchor.exists():
        fail("E_CONTINUITY", "external head already exists; refusing to replace it")
    check_chain(replace(settings, anchor_dir=None, require_external_anchor=False, require_scope=False))
    records = load_records(settings)
    head = {"schema_version": 1, "workspace_id": trust["workspace_id"], "seq": len(records),
            "sha256": sha256_obj(records[-1].to_dict()) if records else ZERO}
    atomic_write(anchor, dumps(head))
    atomic_write(local_head(settings), dumps(head))
    return {"ok": True, "head": head, "anchor": str(anchor)}
