"""Beacon CLI: init, seed, collect, check, scope, sync, pull, serve, tui, mcp."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from beacon import __version__
from beacon.config import load_settings
from beacon.crypto.witness import check_chain, create_checkpoint, load_checkpoints, load_records
from beacon.errors import BeaconError
from beacon.plugins.loader import load_plugins
from beacon.plugins.spec import CollectContext
from beacon.scf.engine import collect_all, collect_named, collect_target
from beacon.scope.store import init_scope, load_scope, scope_content_sha256
from beacon.storage import pull_workspace, sync_workspace
from beacon.workspace import freshness, init_workspace, seed_workspace, system_status, validation


def _settings():
    return load_settings()


def _emit(obj) -> None:
    click.echo(json.dumps(obj, indent=2, default=str))


def _die(exc: BaseException) -> None:
    code = getattr(exc, "code", "E_ERROR")
    click.echo(f"{code}: {exc}", err=True)
    raise SystemExit(2)


@click.group()
@click.version_option(__version__, prog_name="beacon")
def main() -> None:
    """Beacon GRC evidence engine."""


@main.command("init")
def cmd_init() -> None:
    """Create `.beacon/`, recorder vs witness keys, and a local RFC 3161 TSA."""
    try:
        meta = init_workspace(_settings())
    except BeaconError as exc:
        _die(exc)
    _emit({"ok": True, **meta})


@main.command("seed")
def cmd_seed() -> None:
    """Collect builtin fixtures and seal them through the witness chain."""
    try:
        result = seed_workspace(_settings())
    except BeaconError as exc:
        _die(exc)
    _emit({"ok": True, **result})


@main.command("collect")
@click.option("--target", "target", default=None, help="SCF control id, for example IAC-02 or CRY-07.")
@click.option("--plugin", "plugin_name", default=None, help="Plugin name, for example aws.inspector.")
@click.option(
    "--live/--fixture",
    "live",
    default=None,
    help="Force live collection or fixtures. Default: auto (fixture without credentials).",
)
def cmd_collect(target: str | None, plugin_name: str | None, live: bool | None) -> None:
    """Collect evidence, seal it, and write a Merkle/TSA checkpoint."""
    settings = _settings()
    ctx = CollectContext(target=target, live=live)
    try:
        if plugin_name:
            result = collect_named(settings, plugin_name, ctx, checkpoint=True)
        elif target:
            result = collect_target(settings, target, ctx, checkpoint=True)
        else:
            result = collect_all(settings, ctx, checkpoint=True)
    except BeaconError as exc:
        _die(exc)
    _emit(result)


@main.group("scope")
def cmd_scope() -> None:
    """Write and read the local assessment scope document."""


@cmd_scope.command("init")
@click.option("--id", "scope_id", required=True, help="Assessment scope id.")
def cmd_scope_init(scope_id: str) -> None:
    """Create ``.beacon/scopes/{scope_id}.json``. An unsafe id fails closed."""
    try:
        document = init_scope(_settings(), scope_id)
    except BeaconError as exc:
        _die(exc)
    _emit(document.canonical_body())


@cmd_scope.command("show")
@click.option("--id", "scope_id", required=True, help="Assessment scope id.")
def cmd_scope_show(scope_id: str) -> None:
    """Print one scope document. A missing file fails closed."""
    try:
        document = load_scope(_settings(), scope_id)
    except BeaconError as exc:
        _die(exc)
    _emit(document.canonical_body())


@cmd_scope.command("hash")
@click.option("--id", "scope_id", required=True, help="Assessment scope id.")
def cmd_scope_hash(scope_id: str) -> None:
    """Print ``ScopeDocument.content_sha256()``. A missing file fails closed."""
    try:
        digest = scope_content_sha256(_settings(), scope_id)
    except BeaconError as exc:
        _die(exc)
    click.echo(digest)


@main.command("check")
def cmd_check() -> None:
    """Verify signatures, the hash chain, Merkle roots, and TSA tokens. Fail closed."""
    try:
        result = check_chain(_settings())
    except BeaconError as exc:
        _die(exc)
    _emit(result)


@main.command("status")
def cmd_status() -> None:
    """Show workspace, keys, plugins, and chain coverage."""
    _emit(system_status(_settings()))


@main.command("plugins")
def cmd_plugins() -> None:
    """List builtin and drop-in plugins."""
    settings = _settings()
    items = []
    for plugin in load_plugins(settings).values():
        items.append(
            {
                "name": plugin.spec.name,
                "version": plugin.spec.version,
                "category": plugin.spec.category,
                "scf_targets": list(plugin.spec.scf_targets),
                "tools": list(plugin.spec.tools),
            }
        )
    _emit({"plugins": items})


@main.command("push")
@click.option("--out", "out_path", type=click.Path(path_type=Path), default=None)
def cmd_push(out_path: Path | None) -> None:
    """Export a sealed evidence pack (public keys only)."""
    from beacon.push import write_pack

    settings = _settings()
    try:
        result = write_pack(settings, out_path)
    except BeaconError as exc:
        _die(exc)
    payload = {"ok": True, "path": str(result.path)}
    if result.remote:
        payload["remote"] = result.remote
    _emit(payload)


@main.command("freshness")
def cmd_freshness() -> None:
    """Show the latest sealed evidence per plugin."""
    _emit({"items": freshness(_settings())})


@main.command("serve")
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8080, type=int)
def cmd_serve(host: str, port: int) -> None:
    """Start the Beacon GUI."""
    import uvicorn

    from beacon.gui.app import create_app

    uvicorn.run(create_app(), host=host, port=port, log_level="info")


@main.command("tui")
@click.option(
    "--no-tour",
    is_flag=True,
    help="Do not auto-start the walkthrough. BEACON_NO_TOUR=1 does the same.",
)
def cmd_tui(no_tour: bool) -> None:
    """Start the Paramify-style terminal UI."""
    from beacon.tui.app import run_tui

    run_tui(skip_tour=no_tour)


@main.command("mcp")
def cmd_mcp() -> None:
    """Run the MCP server on stdio (tools named beacon_*)."""
    from beacon.mcp.server import run_stdio

    run_stdio()


@main.command("checkpoint")
def cmd_checkpoint() -> None:
    """Write a Merkle checkpoint and RFC 3161 timestamp over the current chain."""
    try:
        cp = create_checkpoint(_settings())
    except BeaconError as exc:
        _die(exc)
    _emit(cp.to_dict())


@main.command("records")
def cmd_records() -> None:
    """Dump sealed records (no private keys)."""
    settings = _settings()
    _emit(
        {
            "records": [row.to_dict() for row in load_records(settings)],
            "checkpoints": [row.to_dict() for row in load_checkpoints(settings)],
        }
    )


@main.command("sync")
def cmd_sync() -> None:
    """Upload local sealed artifacts to the S3 evidence lake. Skips private keys."""
    try:
        result = sync_workspace(_settings())
    except BeaconError as exc:
        _die(exc)
    _emit({"ok": True, **result})


@main.command("pull")
def cmd_pull() -> None:
    """Download sealed artifacts from the DynamoDB index and verify SHA-256."""
    try:
        result = pull_workspace(_settings())
    except BeaconError as exc:
        _die(exc)
    _emit({"ok": True, **result})


if __name__ == "__main__":
    sys.exit(main())
