"""Seal bytes from an explicitly approved Git commit, never the working tree."""
import datetime as dt
import re
import subprocess
from pathlib import Path, PurePosixPath

from beacon.assurance.policy import PolicyObject
from beacon.canonical import sha256_bytes
from beacon.crypto.witness import seal_payload, create_checkpoint
from beacon.errors import fail
from beacon.locking import locked
from beacon.scope.bind import bind_observation_payload
from beacon.scope.enforce import validate_plugin_scope
from beacon.scope.store import load_scope


@locked
def capture_policy(settings, *, scope_id: str, root: Path, path: str, commit: str) -> dict:
    scope = load_scope(settings, scope_id)
    validate_plugin_scope(scope, "git.policy")
    parameters = getattr(scope, "parameters", {})
    source = next((item for item in parameters.get("policy_sources", []) if isinstance(item, dict)
                   and item.get("path") == path and item.get("commit") == commit), None)
    if source is None or source.get("system_id") not in scope.boundary.systems:
        fail("E_POLICY", "policy path, commit, and system must be approved in scope parameters")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        fail("E_POLICY", "policy source requires an exact Git commit id")
    if (not path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
            or "\\" in path or not path.endswith(".json")):
        fail("E_POLICY", "policy path must be a relative JSON path")
    try:
        object_name = f"{commit}:{path}"
        size = subprocess.run(["git", "-C", str(root), "cat-file", "-s", object_name],
                              check=True, capture_output=True, timeout=5)
        if int(size.stdout) > 16384:
            fail("E_POLICY", "policy exceeds the 16 KiB evidence limit")
        raw = subprocess.run(["git", "-C", str(root), "cat-file", "blob", object_name],
                             check=True, capture_output=True, timeout=5).stdout
        if sha256_bytes(raw) != source.get("file_sha256"):
            fail("E_POLICY", "policy bytes differ from the approved file digest")
        document = PolicyObject.model_validate_json(raw)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        fail("E_POLICY", f"cannot read approved Git policy: {exc}")
    if scope_id not in document.scope_refs:
        fail("E_POLICY", "policy does not name this scope")
    payload = bind_observation_payload({"format": "beacon.git-policy/v1", "source": "git.policy",
        "mode": "live", "ok": True, "collection_complete": True,
        "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "identity": {"system_id": source["system_id"]}, "git_commit": commit, "path": path,
        "file_sha256": sha256_bytes(raw), "content": raw.decode("utf-8"),
        "policy": document.canonical_body(), "tags": ["evidence:policy", "automation:manual"]}, scope)
    record = seal_payload(settings, plugin="git.policy", mode="live",
                          scf_targets=list(document.control_refs), payload=payload)
    create_checkpoint(settings)
    return {"ok": True, "evidence_id": record.evidence_id, "file_sha256": payload["file_sha256"],
            "scope_sha256": scope.content_sha256(), "assurance_claim": False}
