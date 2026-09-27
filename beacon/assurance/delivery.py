"""Seal three delivery facts from an approved Git commit.

The facts are the change-gate posture, the release-image identity, and the
cluster-admin boundary. The seal stores those facts. It does not store the
file bytes. A seal is not a statement that a control is met.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import subprocess
from pathlib import Path
from typing import NoReturn

from beacon.scope.delivery_source import DELIVERY_KINDS, source_error
from beacon.canonical import sha256_bytes
from beacon.crypto.witness import create_checkpoint, seal_payload
from beacon.errors import E_DELIVERY, fail
from beacon.locking import locked
from beacon.scope.bind import bind_observation_payload
from beacon.scope.enforce import validate_plugin_scope
from beacon.scope.store import load_scope

MAX_BYTES = 65536
_STEP_RE = re.compile(r"(?m)^[ \t]*-[ \t]+(?:name|uses|run|id):")
_EXIT_RE = re.compile(r"(?:exit-code:\s*|--exit-code(?:=|\s+))['\"]?(\d+)", re.IGNORECASE)
_SOFT_FAIL_RE = re.compile(
    r"soft[-_]fail:\s*['\"]?true['\"]?|--soft-fail\b",
    re.IGNORECASE,
)
_CONTINUE_RE = re.compile(r"continue-on-error:\s*['\"]?true['\"]?", re.IGNORECASE)
_AUDIT_LEVEL_RE = re.compile(
    r"--audit-level(?:=|\s+)(none|low|moderate|high|critical)\b",
    re.IGNORECASE,
)
_IMAGE_RE = re.compile(
    r"""(?m)^[ \t]*image:[ \t]*(?:"([^"]*)"|'([^']*)'|(\S+))[ \t]*$"""
)
_REPO_RE = re.compile(r"(?m)^[ \t]*repository:[ \t]*['\"]?([^'\"\s]+)['\"]?[ \t]*$")
_TAG_RE = re.compile(r"(?m)^[ \t]*tag:[ \t]*['\"]?([^'\"\s]+)['\"]?[ \t]*$")
_LEAK_RE = re.compile(
    r"arn:[A-Za-z0-9-]+:|\b(?:\d{1,3}\.){3}\d{1,3}\b|(?<![A-Fa-f0-9])\d{12}(?!\d)"
)


def _never(value: object) -> NoReturn:
    raise AssertionError(f"unhandled value: {value!r}")


def _delivery_fail(message: str) -> NoReturn:
    fail(E_DELIVERY, message)


def _chunks(text: str) -> list[str]:
    starts = [match.start() for match in _STEP_RE.finditer(text)]
    if not starts:
        return [text]
    return [text[start:starts[i + 1]] if i + 1 < len(starts) else text[start:]
            for i, start in enumerate(starts)]


def _invocation(chunk: str) -> str:
    """Step body without the display name. Tool names in a title are not gates."""
    return "\n".join(line for line in chunk.splitlines() if not re.match(r"^[ \t]*-[ \t]+name:", line))


def _tools_in(chunk: str) -> list[str]:
    lowered = _invocation(chunk).lower()
    found: list[str] = []
    if "checkov" in lowered:
        found.append("checkov")
    if "trivy" in lowered:
        found.append("trivy")
    if re.search(r"npm\s+audit\b", lowered):
        found.append("npm-audit")
    return found


def _posture(chunk: str, tool: str) -> str:
    body = _invocation(chunk)
    if _CONTINUE_RE.search(body):
        return "advisory"
    match tool:
        case "npm-audit":
            level = _AUDIT_LEVEL_RE.search(body)
            if level is None:
                return "unknown"
            return "advisory" if level.group(1).lower() == "none" else "blocking"
        case "checkov" | "trivy":
            if _SOFT_FAIL_RE.search(body):
                return "advisory"
            exit_code = _EXIT_RE.search(body)
            if exit_code is None:
                return "unknown"
            return "blocking" if int(exit_code.group(1)) > 0 else "advisory"
        case _ as unknown:
            _never(unknown)


def _workflow(text: str) -> tuple[dict, list[str]]:
    text = "\n".join(line for line in text.splitlines() if not line.strip().startswith("#"))
    gates = [{"tool": tool, "posture": _posture(chunk, tool)}
             for chunk in _chunks(text) for tool in _tools_in(chunk)]
    gaps = [f"gate_not_blocking:{gate['tool']}" for gate in gates if gate["posture"] == "advisory"]
    gaps.extend(f"gate_posture_unknown:{gate['tool']}" for gate in gates if gate["posture"] == "unknown")
    if not gates:
        gaps.append("security_gate_missing")
    return {"gates": gates}, gaps


def _identity(reference: str) -> str:
    if not reference.strip():
        return "rejected"
    if "{{" in reference or "}}" in reference:
        return "unresolved"
    digest = reference.rsplit("@sha256:", 1)
    if len(digest) == 2:
        return "digest" if re.fullmatch(r"[0-9a-f]{64}", digest[1]) else "rejected"
    tag = reference.rsplit(":", 1)[-1]
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", tag):
        return "git_sha"
    return "floating"


def _manifest(text: str) -> tuple[dict, list[str]]:
    scalar = [next(part for part in match.groups() if part is not None) for match in _IMAGE_RE.finditer(text)]
    repositories = _REPO_RE.findall(text)
    tags = _TAG_RE.findall(text)
    if scalar and (repositories or tags):
        return {"images": []}, ["image_reference_ambiguous"]
    if repositories or tags:
        if len(repositories) != 1 or len(tags) != 1:
            return {"images": []}, ["image_reference_ambiguous"]
        scalar = [f"{repositories[0]}:{tags[0]}"]
    if not scalar:
        return {"images": []}, ["image_reference_missing"]
    images = [{"identity": _identity(reference)} for reference in scalar]
    gaps: list[str] = []
    for image in images:
        match image["identity"]:
            case "floating":
                gaps.append("floating_image_tag")
            case "unresolved":
                gaps.append("image_reference_unresolved")
            case "rejected":
                gaps.append("image_reference_rejected")
            case "digest" | "git_sha":
                continue
            case _ as unknown:
                _never(unknown)
    return {"images": images}, list(dict.fromkeys(gaps))


def _cluster(text: str) -> tuple[dict, list[str]]:
    text = "\n".join(
        line for line in text.splitlines()
        if not line.strip().startswith("#") and not line.strip().startswith("//")
    )
    opened = re.findall(r"cluster_endpoint_public_access\s*=\s*(true|false)", text)
    if opened == ["true"]:
        public_endpoint = "enabled"
    elif opened == ["false"]:
        public_endpoint = "disabled"
    else:
        public_endpoint = "unknown"
    cidr = re.search(
        r"cluster_endpoint_public_access_cidrs\s*=\s*(var\.[A-Za-z0-9_]+|\[.*?\])",
        text,
        re.DOTALL,
    )
    if cidr is None:
        api_cidr_source = "absent"
    elif "var." in cidr.group(1):
        api_cidr_source = "variable"
    elif '"' in cidr.group(1) or "'" in cidr.group(1):
        api_cidr_source = "literal"
    else:
        api_cidr_source = "absent"
    principals = re.findall(r"principal_arn\s*=\s*(var\.[A-Za-z0-9_]+|\"[^\"]*\")", text)
    if any(item.startswith('"') for item in principals) or "arn:aws:iam:" in text:
        admin_principal_source = "literal"
    elif principals:
        admin_principal_source = "variable"
    else:
        admin_principal_source = "absent"
    private = re.search(r"subnet_ids\s*=\s*[^\n]*private_subnets", text) is not None
    public = re.search(r"subnet_ids\s*=\s*[^\n]*public_subnets", text) is not None
    if private and public:
        node_subnets = "conflict"
    elif private:
        node_subnets = "private"
    elif public:
        node_subnets = "public"
    else:
        node_subnets = "unknown"
    broad_admin = "AmazonEKSClusterAdminPolicy" in text
    open_world = re.search(r"""(?<![\w.])(?:0\.0\.0\.0/0|::/0)(?![\w:])""", text) is not None
    facts = {
        "public_endpoint": public_endpoint,
        "api_cidr_source": api_cidr_source,
        "api_open_to_world": open_world,
        "admin_principal_source": admin_principal_source,
        "node_subnets": node_subnets,
        "broad_cluster_admin_policy": broad_admin,
    }
    gaps: list[str] = []
    if public_endpoint == "unknown":
        gaps.append("api_exposure_unknown")
    if open_world:
        gaps.append("api_open_to_world")
    if public_endpoint == "enabled" and api_cidr_source == "literal":
        gaps.append("api_cidr_committed")
    if public_endpoint == "enabled" and api_cidr_source == "absent":
        gaps.append("api_cidr_missing")
    if admin_principal_source == "literal":
        gaps.append("admin_arn_committed")
    if admin_principal_source == "absent":
        gaps.append("admin_principal_missing")
    match node_subnets:
        case "public":
            gaps.append("nodes_on_public_subnets")
        case "unknown":
            gaps.append("node_subnet_unknown")
        case "conflict":
            gaps.append("node_subnet_conflict")
        case "private":
            pass
        case _ as unknown:
            _never(unknown)
    if broad_admin:
        gaps.append("broad_cluster_admin_policy")
    return facts, gaps


def extract_delivery(kind: str, raw: bytes) -> tuple[dict, list[str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        _delivery_fail("delivery file must be UTF-8 text")
    if "\x00" in text:
        _delivery_fail("delivery file must be UTF-8 text")
    match kind:
        case "change_workflow":
            facts, gaps = _workflow(text)
        case "release_manifest":
            facts, gaps = _manifest(text)
        case "cluster_boundary":
            facts, gaps = _cluster(text)
        case _ as unknown:
            _never(unknown)
    if _LEAK_RE.search(json.dumps({"facts": facts, "gaps": gaps})):
        _delivery_fail("delivery facts must not copy account, network, or ARN literals")
    return facts, gaps


def _read_blob(root: Path, commit: str, path: str) -> bytes:
    object_name = f"{commit}:{path}"
    try:
        size = subprocess.run(
            ["git", "-C", str(root), "cat-file", "-s", object_name],
            check=True, capture_output=True, timeout=5,
        )
        if int(size.stdout) > MAX_BYTES:
            _delivery_fail("delivery file exceeds the 64 KiB evidence limit")
        return subprocess.run(
            ["git", "-C", str(root), "cat-file", "blob", object_name],
            check=True, capture_output=True, timeout=5,
        ).stdout
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        _delivery_fail(f"cannot read approved Git file: {exc}")


@locked
def capture_delivery(settings, *, scope_id: str, root: Path, path: str, commit: str) -> dict:
    """Seal facts from the approved commit. Working-tree edits are ignored."""
    scope = load_scope(settings, scope_id)
    validate_plugin_scope(scope, "git.delivery")
    parameters = getattr(scope, "parameters", {})
    sources = parameters.get("delivery_sources", [])
    if not isinstance(sources, list):
        _delivery_fail("delivery sources must be approved in scope parameters")
    matches = [item for item in sources if isinstance(item, dict)
               and item.get("path") == path and item.get("commit") == commit]
    if len(matches) != 1:
        _delivery_fail("delivery path and commit must match one approved source")
    source = matches[0]
    message = source_error(source)
    if message is not None or source.get("kind") not in DELIVERY_KINDS:
        _delivery_fail(message or "delivery source kind is unknown")
    if source.get("system_id") not in scope.boundary.systems:
        _delivery_fail("delivery system must be inside the scope boundary")
    raw = _read_blob(root, commit, path)
    if sha256_bytes(raw) != source.get("file_sha256"):
        _delivery_fail("delivery bytes differ from the approved file digest")
    facts, gaps = extract_delivery(source["kind"], raw)
    payload = bind_observation_payload({
        "format": "beacon.git-delivery/v1",
        "source": "git.delivery",
        "mode": "live",
        "ok": True,
        "collection_complete": True,
        "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "identity": {"system_id": source["system_id"]},
        "git_commit": commit,
        "path": path,
        "file_sha256": sha256_bytes(raw),
        "kind": source["kind"],
        "facts": facts,
        "gaps": gaps,
        "assurance_claim": False,
        "tags": ["evidence:drop_in", "automation:automated"],
    }, scope)
    record = seal_payload(
        settings, plugin="git.delivery", mode="live", scf_targets=[], payload=payload,
    )
    create_checkpoint(settings)
    return {
        "ok": True,
        "evidence_id": record.evidence_id,
        "file_sha256": payload["file_sha256"],
        "kind": source["kind"],
        "facts": facts,
        "gaps": gaps,
        "scope_sha256": scope.content_sha256(),
        "assurance_claim": False,
    }
