"""Unified framework engine: SCF target -> overlapping fetchers -> seal."""

from __future__ import annotations

from typing import Any

from beacon.config import Settings
from beacon.crypto.witness import create_checkpoint, seal_payload
from beacon.plugins.loader import get_plugin, load_plugins, plugins_for_target
from beacon.plugins.spec import CollectContext, CollectResult, Plugin
from beacon.scf.client import fetch_control
from beacon.scope.bind import bind_observation_payload, collect_scope
from beacon.scope.document import ScopeDocument
from beacon.storage import publish_collect_run
from beacon.scope.enforce import validate_plugin_scope, boundary_reasons
from beacon.errors import fail
from beacon.locking import locked


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
    *,
    scope: ScopeDocument | None = None,
) -> dict[str, Any]:
    if result.scf_targets is None:
        targets = list(plugin.spec.scf_targets)
    else:
        targets = list(result.scf_targets)
    payload = result.payload
    if scope is not None:
        validate_plugin_scope(scope, plugin.spec.name)
        if result.ok and result.mode == "live":
            reasons = boundary_reasons(scope, payload)
            if reasons:
                fail("E_SCOPE", ",".join(reasons))
        payload = bind_observation_payload(payload, scope)
    record = seal_payload(
        settings,
        plugin=plugin.spec.name,
        mode=result.mode,
        scf_targets=targets,
        payload=payload,
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


@locked
def collect_named(
    settings: Settings,
    name: str,
    ctx: CollectContext,
    *,
    checkpoint: bool = True,
    scope_id: str | None = None,
) -> dict[str, Any]:
    scope = collect_scope(settings, scope_id)
    plugin = get_plugin(settings, name)
    if scope is not None:
        validate_plugin_scope(scope, plugin.spec.name)
        ctx = CollectContext(target=ctx.target, live=ctx.live, extra={**ctx.extra, "scope": scope.canonical_body()})
    result = collect_plugin(settings, plugin, ctx)
    sealed = seal_result(settings, plugin, result, scope=scope)
    cp = None
    if checkpoint:
        cp = create_checkpoint(settings)
        sealed["checkpoint"] = {"merkle_root": cp.merkle_root, "to_seq": cp.to_seq}
    remote = publish_collect_run(settings, evidence_ids=[sealed["evidence_id"]], checkpoint=cp)
    if remote:
        sealed["remote"] = remote
    return sealed


@locked
def collect_target(
    settings: Settings,
    target: str,
    ctx: CollectContext | None = None,
    *,
    checkpoint: bool = True,
    scope_id: str | None = None,
) -> dict[str, Any]:
    scope = collect_scope(settings, scope_id)
    control = fetch_control(settings, target)
    bound = CollectContext(target=target, live=(ctx.live if ctx else None), extra=dict(ctx.extra) if ctx else {})
    selected = plugins_for_target(settings, target)
    if scope is not None:
        for plugin in selected:
            validate_plugin_scope(scope, plugin.spec.name)
        bound.extra["scope"] = scope.canonical_body()
    runs = []
    for plugin in selected:
        result = collect_plugin(settings, plugin, bound)
        runs.append(seal_result(settings, plugin, result, scope=scope))
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


@locked
def collect_all(
    settings: Settings,
    ctx: CollectContext | None = None,
    *,
    checkpoint: bool = True,
    scope_id: str | None = None,
) -> dict[str, Any]:
    scope = collect_scope(settings, scope_id)
    ctx = ctx or CollectContext()
    if scope is not None:
        ctx = CollectContext(target=ctx.target, live=ctx.live, extra={**ctx.extra, "scope": scope.canonical_body()})
    plugins = list(load_plugins(settings).values())
    for plugin in plugins:
        if scope is not None:
            validate_plugin_scope(scope, plugin.spec.name)
    runs = []
    for plugin in plugins:
        result = collect_plugin(settings, plugin, ctx)
        runs.append(seal_result(settings, plugin, result, scope=scope))
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
