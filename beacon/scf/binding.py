"""SCF 2026.2 evidence binding. The pin is the offline catalog, not live HackIDLE."""

from __future__ import annotations

from typing import Any

from beacon.config import SCF_VERSION, Settings
from beacon.errors import E_CONTROL_MISMATCH, E_UNKNOWN_CONTROL, BeaconError
from beacon.scf.client import fetch_control, normalize_control_id, try_offline_control

PILLAR_FRAMEWORK_IDS: tuple[str, ...] = (
    "usa-federal-gsa-fedramp-5-high",
    "general-nist-800-53-r5-2",
    "usa-federal-dow-cmmc-2-level-2",
    "general-aicpa-tsc-2017",
)

FORBIDDEN_FRAMEWORK_IDS = frozenset({"usa-federal-gsa-fedramp-20x-ksi"})

OVERLAY_UNMAPPED_IDS: tuple[str, ...] = (
    "KSI-CNA-OFA",
    "KSI-PIY-RES",
    "SA-09(07)",
    "SC-12(06)",
)

PROVENANCE_CROSSWALK = "scf-crosswalk"
PROVENANCE_LIVE_CROSSWALK = "scf-live-crosswalk"
UNPINNED_VERSION = "unpinned"


def overlay_unmapped() -> dict[str, list[str]]:
    """Return overlay IDs with empty maps. Do not guess SCF links."""
    return {overlay_id: [] for overlay_id in OVERLAY_UNMAPPED_IDS}


def _as_id_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        item = value.strip()
        return [item] if item else []
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in value:
        item = str(raw).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def empty_binding() -> dict[str, Any]:
    return {
        "scf_version": UNPINNED_VERSION,
        "scf_id": "",
        "scf_ids": [],
        "scf_family": "",
        "erl_ids": [],
        "framework_hops": [],
        "overlay_unmapped": overlay_unmapped(),
        "pinned": False,
    }


def framework_hops_from_control(control: dict[str, Any], provenance: str) -> list[dict[str, Any]]:
    crosswalks = control.get("crosswalks") or {}
    hops: list[dict[str, Any]] = []
    if not isinstance(crosswalks, dict):
        return hops
    for framework_id in PILLAR_FRAMEWORK_IDS:
        if framework_id in FORBIDDEN_FRAMEWORK_IDS:
            continue
        ids = _as_id_list(crosswalks.get(framework_id))
        if not ids:
            continue
        hops.append(
            {
                "framework_id": framework_id,
                "framework_control_ids": ids,
                "provenance": provenance,
            }
        )
    return hops


def _family_from_control(control: dict[str, Any], scf_id: str) -> str:
    family = str(control.get("family") or control.get("scf_family") or "").strip()
    if family:
        return family
    return scf_id.split("-", 1)[0]


def _unpinned_version(control: dict[str, Any]) -> str:
    raw = str(control.get("scf_version") or "").strip()
    if not raw or raw == SCF_VERSION:
        return UNPINNED_VERSION
    return raw


def _binding_from_catalog_control(
    control: dict[str, Any],
    *,
    scf_version: str,
    pinned: bool,
) -> dict[str, Any]:
    scf_id = str(control.get("control_id") or "").upper()
    hop_provenance = PROVENANCE_CROSSWALK if pinned else PROVENANCE_LIVE_CROSSWALK
    return {
        "scf_version": scf_version,
        "scf_id": scf_id,
        "scf_ids": [scf_id] if scf_id else [],
        "scf_family": _family_from_control(control, scf_id),
        "erl_ids": _as_id_list(control.get("evidence_requests")),
        "framework_hops": framework_hops_from_control(control, provenance=hop_provenance),
        "overlay_unmapped": overlay_unmapped(),
        "pinned": pinned,
    }


def id_only_control(control_id: str) -> dict[str, Any]:
    cid = normalize_control_id(control_id)
    return {
        "control_id": cid,
        "family": cid.split("-", 1)[0],
        "evidence_requests": [],
        "crosswalks": {},
    }


def resolve_control_for_binding(settings: Settings, control_id: str) -> dict[str, Any]:
    """Prefer the 2026.2 pin, then live/cache, then an ID-only record. Do not invent hops."""
    cid = normalize_control_id(control_id)
    pinned = try_offline_control(cid)
    if pinned is not None:
        return pinned
    if not settings.scf_offline:
        try:
            resolved = fetch_control(settings, cid)
        except BeaconError as exc:
            if exc.code not in {E_UNKNOWN_CONTROL, E_CONTROL_MISMATCH}:
                raise
            resolved = None
        if resolved is not None:
            got = str(resolved.get("control_id") or "").strip().upper()
            if got == cid:
                return resolved
    return id_only_control(cid)


def binding_for_control(control: dict[str, Any]) -> dict[str, Any]:
    raw = str(control.get("control_id") or "").strip()
    if not raw:
        return empty_binding()
    scf_id = normalize_control_id(raw)
    pinned = try_offline_control(scf_id)
    if pinned is not None:
        return _binding_from_catalog_control(pinned, scf_version=SCF_VERSION, pinned=True)
    merged = dict(control)
    merged["control_id"] = scf_id
    return _binding_from_catalog_control(
        merged,
        scf_version=_unpinned_version(control),
        pinned=False,
    )


def binding_for_targets(
    settings: Settings,
    targets: list[str],
    *,
    primary: str | None = None,
) -> dict[str, Any]:
    ids = [str(item).strip().upper() for item in targets if str(item).strip()]
    if primary and primary.strip():
        return binding_for_control(resolve_control_for_binding(settings, primary))
    if len(ids) == 1:
        return binding_for_control(resolve_control_for_binding(settings, ids[0]))
    if not ids:
        return empty_binding()
    per_control = [binding_for_control(resolve_control_for_binding(settings, control_id)) for control_id in ids]
    binding = empty_binding()
    binding["scf_ids"] = [item["scf_id"] for item in per_control if item.get("scf_id")]
    binding["controls"] = per_control
    binding["pinned"] = bool(per_control) and all(bool(item.get("pinned")) for item in per_control)
    binding["scf_version"] = SCF_VERSION if binding["pinned"] else UNPINNED_VERSION
    return binding


def attach_binding(payload: dict[str, Any], binding: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["scf_binding"] = binding
    return out
