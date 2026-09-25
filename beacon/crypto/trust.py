"""Explicit signer pins and retained chain heads. No trust-on-first-use on reads.

The default head detects chain-only rollback. An external head must be retained
under separate administration to detect restoration of an entire workspace.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

from beacon.canonical import dumps, sha256_bytes, sha256_obj
from beacon.errors import fail

ZERO = "0" * 64


def atomic_write(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def trust_path(settings) -> Path:
    return settings.trust_file or settings.home / "trust.json"


def read_trust(settings) -> dict:
    try:
        data = json.loads(trust_path(settings).read_bytes())
        if set(data) != {"schema_version", "workspace_id", "recorder", "witness", "tsa_sha256"}:
            raise ValueError("unexpected trust fields")
        if data["schema_version"] != 1 or not isinstance(data["workspace_id"], str):
            raise ValueError("invalid trust version")
        for key in ("recorder", "witness", "tsa_sha256"):
            value = data[key]
            if not isinstance(value, str) or len(value) != 64 or bytes.fromhex(value).hex() != value:
                raise ValueError("invalid pin")
        if data["recorder"] == data["witness"]:
            raise ValueError("roles collide")
        return data
    except (OSError, ValueError, TypeError, KeyError) as exc:
        fail("E_TRUST", f"trusted signer registry missing or invalid: {exc}; explicitly enroll trusted public keys")


def local_head(settings) -> Path:
    return settings.home / "retained-head.json"


def external_head(settings, trust: dict) -> Path | None:
    if settings.anchor_dir is None:
        if settings.require_external_anchor:
            fail("E_CONTINUITY", "BEACON_REQUIRE_EXTERNAL_ANCHOR requires BEACON_ANCHOR_DIR")
        return None
    root = settings.anchor_dir.resolve()
    if root == settings.home.resolve() or root.is_relative_to(settings.home.resolve()):
        fail("E_CONTINUITY", "external anchor directory must be outside the workspace")
    # Hash the registry identity so a registry value cannot choose a path.
    return root / (sha256_bytes(trust["workspace_id"].encode()) + ".json")


def initialize_trust(settings, recorder: str, witness: str) -> dict:
    if settings.trust_file is not None:
        fail("E_TRUST", "initialize locally, then configure the independently managed trust file")
    target = trust_path(settings)
    if target.exists() or local_head(settings).exists():
        fail("E_TRUST", "trust state already exists; refusing to replace it")
    trust = {"schema_version": 1, "workspace_id": str(uuid4()), "recorder": recorder,
             "witness": witness, "tsa_sha256": sha256_bytes((settings.keys_dir / "tsa.crt").read_bytes())}
    atomic_write(target, dumps(trust))
    head = {"schema_version": 1, "workspace_id": trust["workspace_id"], "seq": 0, "sha256": ZERO}
    atomic_write(local_head(settings), dumps(head))
    anchor = external_head(settings, trust)
    if anchor is not None:
        if anchor.exists():
            fail("E_CONTINUITY", "external anchor already exists")
        atomic_write(anchor, dumps(head))
    return trust


def assert_signers(record, trust: dict) -> None:
    if record.recorder_pub != trust["recorder"] or record.witness_pub != trust["witness"]:
        fail("E_UNTRUSTED_SIGNER", f"seq {record.seq} is not signed by the registered recorder and witness")


def assert_continuity(settings, records, trust: dict | None = None) -> None:
    trust = trust or read_trust(settings)
    paths = [local_head(settings)]
    anchor = external_head(settings, trust)
    if anchor is not None:
        paths.append(anchor)
    for path in paths:
        try:
            head = json.loads(path.read_bytes())
            seq = head["seq"]
            if (head.get("schema_version") != 1 or head["workspace_id"] != trust["workspace_id"]
                    or type(seq) is not int or seq < 0 or seq > len(records)):
                raise ValueError("head is missing from the presented history")
            expected = sha256_obj(records[seq - 1].to_dict()) if seq else ZERO
            if head["sha256"] != expected:
                raise ValueError("retained head differs from the presented history")
        except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
            fail("E_CONTINUITY", f"cannot establish retained history: {exc}")


def advance_head(settings, records) -> None:
    trust = read_trust(settings)
    assert_continuity(settings, records, trust)
    head = {"schema_version": 1, "workspace_id": trust["workspace_id"], "seq": len(records),
            "sha256": sha256_obj(records[-1].to_dict()) if records else ZERO}
    # External first: a failure never silently advances only the local copy.
    anchor = external_head(settings, trust)
    if anchor is not None:
        atomic_write(anchor, dumps(head))
    atomic_write(local_head(settings), dumps(head))
