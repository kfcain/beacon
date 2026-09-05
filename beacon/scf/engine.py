"""Unified framework engine: SCF target -> overlapping fetchers -> seal."""

from __future__ import annotations

from typing import Any

from beacon.config import Settings
from beacon.crypto.witness import create_checkpoint, seal_payload
from beacon.plugins.loader import get_plugin, load_plugins, plugins_for_target
from beacon.plugins.spec import CollectContext, CollectResult, Plugin
from beacon.scf.client import fetch_control


def collect_plugin(
    settings: Settings,
    plugin: Plugin,
    ctx: CollectContext,
) -> CollectResult:
    extra = dict(ctx.extra)
    extra.setdefault("force_fixture", settings.force_fixture)
    bound = CollectContext(target=ctx.target, live=ctx.live, extra=extra)
    return plugin.collect(bound)


def seal_result(
    settings: Settings,
    plugin: Plugin,
    result: CollectResult,
) -> dict[str, Any]:
    targets = list(result.scf_targets or plugin.spec.scf_targets)
    record = seal_payload(
        settings,
        plugin=plugin.spec.name,
        mode=result.mode,
        scf_targets=targets,
        payload=result.payload,
    )
    return {
        "plugin": plugin.spec.name,
        "ok": result.ok,
        "mode": result.mode,
        "error": result.error,
        "evidence_id": record.evidence_id,
        "seq": record.seq,
        "scf_targets": targets,
    }


def collect_named(
    settings: Settings,
    name: str,
    ctx: CollectContext,
    *,
    checkpoint: bool = True,
) -> dict[str, Any]:
    plugin = get_plugin(settings, name)
    result = collect_plugin(settings, plugin, ctx)
    sealed = seal_result(settings, plugin, result)
    if checkpoint:
        cp = create_checkpoint(settings)
        sealed["checkpoint"] = {"merkle_root": cp.merkle_root, "to_seq": cp.to_seq}
    return sealed


def collect_target(
    settings: Settings,
    target: str,
    ctx: CollectContext | None = None,
    *,
    checkpoint: bool = True,
) -> dict[str, Any]:
    control = fetch_control(settings, target)
    ctx = ctx or CollectContext(target=target)
    ctx.target = target
    selected = plugins_for_target(settings, target)
    runs = []
    for plugin in selected:
        result = collect_plugin(settings, plugin, ctx)
        runs.append(seal_result(settings, plugin, result))
    out: dict[str, Any] = {
        "target": target.upper(),
        "control": {
            "control_id": control.get("control_id"),
            "title": control.get("title"),
            "family": control.get("family"),
            "description": control.get("description"),
        },
        "plugins": [plugin.spec.name for plugin in selected],
        "runs": runs,
    }
    if checkpoint and runs:
        cp = create_checkpoint(settings)
        out["checkpoint"] = {"merkle_root": cp.merkle_root, "to_seq": cp.to_seq}
    return out


def collect_all(
    settings: Settings,
    ctx: CollectContext | None = None,
    *,
    checkpoint: bool = True,
) -> dict[str, Any]:
    ctx = ctx or CollectContext()
    runs = []
    for plugin in load_plugins(settings).values():
        result = collect_plugin(settings, plugin, ctx)
        runs.append(seal_result(settings, plugin, result))
    out: dict[str, Any] = {"runs": runs}
    if checkpoint and runs:
        cp = create_checkpoint(settings)
        out["checkpoint"] = {"merkle_root": cp.merkle_root, "to_seq": cp.to_seq}
    return out
