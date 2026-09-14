"""SCF 2026.2 evidence binding. The pin is the offline catalog, not live HackIDLE."""

from __future__ import annotations

from typing import Any

from beacon.config import SCF_VERSION, Settings
from beacon.scf.client import fetch_pinned_control

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
        "scf_version": SCF_VERSION,
        "scf_id": "",
        "scf_family": "",
        "erl_ids": [],
        "framework_hops": [],
        "overlay_unmapped": overlay_unmapped(),
    }


def framework_hops_from_control(control: dict[str, Any]) -> list[dict[str, Any]]:
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
                "provenance": PROVENANCE_CROSSWALK,
            }
        )
    return hops


def binding_for_control(control: dict[str, Any]) -> dict[str, Any]:
    scf_id = str(control.get("control_id") or "").upper()
    pinned = fetch_pinned_control(scf_id)
    family = str(pinned.get("family") or pinned.get("scf_family") or "")
    if not family:
        family = scf_id.split("-", 1)[0]
    return {
        "scf_version": SCF_VERSION,
        "scf_id": str(pinned.get("control_id") or scf_id).upper(),
        "scf_family": family,
        "erl_ids": _as_id_list(pinned.get("evidence_requests")),
        "framework_hops": framework_hops_from_control(pinned),
        "overlay_unmapped": overlay_unmapped(),
    }


def binding_for_targets(
    _settings: Settings,
    targets: list[str],
    *,
    primary: str | None = None,
) -> dict[str, Any]:
    ids = [str(item).strip().upper() for item in targets if str(item).strip()]
    if primary and primary.strip():
        return binding_for_control(fetch_pinned_control(primary))
    if len(ids) == 1:
        return binding_for_control(fetch_pinned_control(ids[0]))
    if not ids:
        return empty_binding()
    per_control = [binding_for_control(fetch_pinned_control(control_id)) for control_id in ids]
    binding = empty_binding()
    binding["controls"] = per_control
    return binding


def attach_binding(payload: dict[str, Any], binding: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["scf_binding"] = binding
    return out
