"""Approved Git source for one delivery fact. This module does not read Git."""

from __future__ import annotations

import re
from typing import Literal, NoReturn

DeliveryKind = Literal["change_workflow", "release_manifest", "cluster_boundary"]
DELIVERY_KINDS: tuple[DeliveryKind, ...] = (
    "change_workflow",
    "release_manifest",
    "cluster_boundary",
)
DELIVERY_FIELDS = frozenset({"path", "commit", "file_sha256", "system_id", "kind"})
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SYSTEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


def _never(value: object) -> NoReturn:
    raise AssertionError(f"unhandled value: {value!r}")


def suffixes_for(kind: str) -> tuple[str, ...]:
    match kind:
        case "change_workflow" | "release_manifest":
            return (".yml", ".yaml")
        case "cluster_boundary":
            return (".tf",)
        case _ as unknown:
            _never(unknown)


def source_error(source: object) -> str | None:
    """Return a reason the source cannot be enrolled. ``None`` means the shape is valid."""
    if not isinstance(source, dict):
        return "delivery source must be an object"
    if set(source) != DELIVERY_FIELDS:
        return "delivery source fields are fixed"
    kind = source["kind"]
    if not isinstance(kind, str) or kind not in DELIVERY_KINDS:
        return "delivery source kind is unknown"
    commit = source["commit"]
    if not isinstance(commit, str) or not _COMMIT_RE.fullmatch(commit):
        return "delivery source commit must be an exact Git id"
    digest = source["file_sha256"]
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        return "delivery source file_sha256 must be a SHA-256 digest"
    system_id = source["system_id"]
    if not isinstance(system_id, str) or not _SYSTEM_RE.fullmatch(system_id):
        return "delivery source system_id must match the safe id pattern"
    path = source["path"]
    if not isinstance(path, str) or path != path.strip() or not path:
        return "delivery path must be a relative file"
    if path.startswith("/") or path.startswith("-") or "\\" in path or ":" in path:
        return "delivery path must be a relative file"
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return "delivery path must be a relative file"
    if not path.endswith(suffixes_for(kind)):
        return "delivery path suffix does not match the kind"
    return None
