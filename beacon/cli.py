"""Beacon CLI: init, seed, collect, check, serve, tui, mcp."""

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
@click.option("--target", "target", default=None, help="SCF control id, for example IAC-01 or CRY-05.")
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
        path = write_pack(settings, out_path)
    except BeaconError as exc:
        _die(exc)
    _emit({"ok": True, "path": str(path)})


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
def cmd_tui() -> None:
    """Start the Paramify-style terminal UI."""
    from beacon.tui.app import run_tui

    run_tui()


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


if __name__ == "__main__":
    sys.exit(main())
