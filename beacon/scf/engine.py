"""Unified framework engine: SCF target -> overlapping fetchers -> seal."""

from __future__ import annotations

from typing import Any

from beacon.config import Settings
from beacon.crypto.witness import create_checkpoint, seal_payload
from beacon.plugins.loader import get_plugin, load_plugins, plugins_for_target
from beacon.plugins.spec import CollectContext, CollectResult, Plugin
from beacon.scf.client import fetch_control
from beacon.storage import publish_collect_run


def collect_plugin(
    settings: Settings,
    plugin: Plugin,
    ctx: CollectContext,
) -> CollectResult:
    extra = dict(ctx.extra)
    if ctx.live is not True:
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
    cp = None
    if checkpoint:
        cp = create_checkpoint(settings)
        sealed["checkpoint"] = {"merkle_root": cp.merkle_root, "to_seq": cp.to_seq}
    remote = publish_collect_run(settings, evidence_ids=[sealed["evidence_id"]], checkpoint=cp)
    if remote:
        sealed["remote"] = remote
    return sealed


def collect_target(
    settings: Settings,
    target: str,
    ctx: CollectContext | None = None,
    *,
    checkpoint: bool = True,
) -> dict[str, Any]:
    control = fetch_control(settings, target)
    bound = CollectContext(target=target, live=(ctx.live if ctx else None), extra=dict(ctx.extra) if ctx else {})
    selected = plugins_for_target(settings, target)
    runs = []
    for plugin in selected:
        result = collect_plugin(settings, plugin, bound)
        runs.append(seal_result(settings, plugin, result))
    out: dict[str, Any] = {
        "target": target.upper(),
        "ok": all(item["ok"] for item in runs) if runs else True,
        "control": {
            "control_id": control.get("control_id"),
            "title": control.get("title"),
            "family": control.get("family"),
            "description": control.get("description"),
        },
        "plugins": [plugin.spec.name for plugin in selected],
        "runs": runs,
    }
    cp = None
    if checkpoint and runs:
        cp = create_checkpoint(settings)
        out["checkpoint"] = {"merkle_root": cp.merkle_root, "to_seq": cp.to_seq}
    remote = publish_collect_run(
        settings,
        evidence_ids=[item["evidence_id"] for item in runs],
        checkpoint=cp,
    )
    if remote:
        out["remote"] = remote
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
    out: dict[str, Any] = {"ok": all(item["ok"] for item in runs) if runs else True, "runs": runs}
    cp = None
    if checkpoint and runs:
        cp = create_checkpoint(settings)
        out["checkpoint"] = {"merkle_root": cp.merkle_root, "to_seq": cp.to_seq}
    remote = publish_collect_run(
        settings,
        evidence_ids=[item["evidence_id"] for item in runs],
        checkpoint=cp,
    )
    if remote:
        out["remote"] = remote
    return out
