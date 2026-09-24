"""Beacon CLI: init, seed, collect, check, scope, sync, pull, serve, tui, mcp."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from beacon import __version__
from beacon.config import load_settings
from beacon.assurance.compile import compile_20x_drafts, write_compiled_packs
from beacon.assurance.index import ledger_method_report, load_evidence_ledger
from beacon.assurance.mapper_ingest import ingest_mapper_file
from beacon.assurance.policy import address_policy
from beacon.assurance.packs import PACK_KINDS
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
@click.option("--scope", "scope_id", default=None, help="Assessment scope id to bind into each payload.")
def cmd_collect(target: str | None, plugin_name: str | None, live: bool | None, scope_id: str | None) -> None:
    """Collect evidence, seal it, and write a Merkle/TSA checkpoint."""
    settings = _settings()
    ctx = CollectContext(target=target, live=live)
    try:
        if plugin_name:
            result = collect_named(settings, plugin_name, ctx, checkpoint=True, scope_id=scope_id)
        elif target:
            result = collect_target(settings, target, ctx, checkpoint=True, scope_id=scope_id)
        else:
            result = collect_all(settings, ctx, checkpoint=True, scope_id=scope_id)
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


@main.group("ledger")
def cmd_ledger() -> None:
    """Index sealed observations and count evidence methods. A count is not a claim."""


@cmd_ledger.command("show")
@click.option("--scope", "scope_id", default=None, help="Assessment scope id. Reuses the sealed scope pair.")
@click.option("--pack", "pack_path", type=click.Path(path_type=Path, exists=True, dir_okay=False), default=None)
@click.option("--scf", "scf_id", default=None, help="Keep entries that name this SCF id.")
def cmd_ledger_show(scope_id: str | None, pack_path: Path | None, scf_id: str | None) -> None:
    """Print custody rows for the local chain or one pack. No observation body."""
    try:
        ledger = load_evidence_ledger(
            _settings(),
            scope_id=scope_id,
            pack_path=pack_path,
            scf_id=scf_id,
        )
    except BeaconError as exc:
        _die(exc)
    _emit(ledger.model_dump(mode="json"))


@cmd_ledger.command("summary")
@click.option("--scope", "scope_id", default=None, help="Assessment scope id. Reuses the sealed scope pair.")
@click.option("--pack", "pack_path", type=click.Path(path_type=Path, exists=True, dir_okay=False), default=None)
@click.option("--scf", "scf_id", default=None, help="Count methods whose control ref is this SCF id.")
@click.option("--class", "package_class", type=click.Choice(["c", "d"]), default="c", show_default=True)
@click.option("--ksi", "ksi_ids", multiple=True, help="KSI label to include. Repeat for more than one.")
@click.option("--not-before", "not_before", default=None, help="Drop seals older than this ISO-8601 instant.")
def cmd_ledger_summary(
    scope_id: str | None,
    pack_path: Path | None,
    scf_id: str | None,
    package_class: str,
    ksi_ids: tuple[str, ...],
    not_before: str | None,
) -> None:
    """Print method counts and shortfalls. This report does not authorize a package."""
    match package_class:
        case "c" | "d":
            chosen_class = package_class
        case _:
            _die(BeaconError("E_LEDGER", "package class must be c or d"))
    try:
        report = ledger_method_report(
            _settings(),
            package_class=chosen_class,
            scope_id=scope_id,
            pack_path=pack_path,
            scf_id=scf_id,
            required_ksi_ids=ksi_ids or None,
            not_before=not_before,
        )
    except BeaconError as exc:
        _die(exc)
    _emit(report.model_dump(mode="json"))


@main.group("pack")
def cmd_pack() -> None:
    """Compile 20x draft packs from sealed observations. A shortfall is a package gap."""


@cmd_pack.command("compile")
@click.option(
    "--kind",
    "kind",
    type=click.Choice(["cpo", "sdr", "ocr", "scg", "all"]),
    default="all",
    show_default=True,
    help="Draft kind. all writes CPO, SDR, OCR, and SCG.",
)
@click.option("--scope", "scope_id", default=None, help="Assessment scope id. Reuses the sealed scope pair.")
@click.option("--pack", "pack_path", type=click.Path(path_type=Path, exists=True, dir_okay=False), default=None)
@click.option("--scf", "scf_id", default=None, help="Keep seals that name this SCF id.")
@click.option("--class", "package_class", type=click.Choice(["c", "d"]), default="c", show_default=True)
@click.option("--ksi", "ksi_ids", multiple=True, help="KSI label to include. Repeat for more than one.")
@click.option("--not-before", "not_before", default=None, help="Drop seals older than this ISO-8601 instant.")
@click.option("--fedramp-id", "fedramp_id", default=None, help="Copy this token onto each draft. Omit to leave it unset.")
@click.option("--out", "out_dir", type=click.Path(path_type=Path, file_okay=False), default=None)
def cmd_pack_compile(
    kind: str,
    scope_id: str | None,
    pack_path: Path | None,
    scf_id: str | None,
    package_class: str,
    ksi_ids: tuple[str, ...],
    not_before: str | None,
    fedramp_id: str | None,
    out_dir: Path | None,
) -> None:
    """Write JSON drafts and Markdown rendered from those drafts."""
    match package_class:
        case "c" | "d":
            chosen_class = package_class
        case _:
            _die(BeaconError("E_LEDGER", "package class must be c or d"))
    match kind:
        case "all":
            kinds = PACK_KINDS
        case "cpo" | "sdr" | "ocr" | "scg":
            kinds = (kind,)
        case _:
            _die(BeaconError("E_LEDGER", "pack kind must be cpo, sdr, ocr, scg, or all"))
    settings = _settings()
    target = out_dir if out_dir is not None else settings.export_dir / "20x"
    try:
        packs = compile_20x_drafts(
            settings,
            package_class=chosen_class,
            kinds=kinds,
            scope_id=scope_id,
            pack_path=pack_path,
            scf_id=scf_id,
            required_ksi_ids=ksi_ids or None,
            not_before=not_before,
            fedramp_id=fedramp_id,
        )
        paths = write_compiled_packs(packs, target)
    except BeaconError as exc:
        _die(exc)
    first = packs[0]
    _emit(
        {
            "ok": True,
            "draft": True,
            "format": first.format,
            "package_class": first.package_class,
            "scope_id": first.scope_id,
            "scope_sha256": first.scope_sha256,
            "kinds": [pack.pack_kind for pack in packs],
            "paths": paths,
            "package_gaps": [gap.model_dump(mode="json") for gap in first.package_gaps],
            "official_schema": first.official_schema,
        }
    )


@main.group("policy")
def cmd_policy() -> None:
    """Address a git policy file by path and content hash. The hash is custody metadata."""


@cmd_policy.command("show")
@click.option("--path", "policy_path", required=True, help="Relative path of the JSON policy file.")
@click.option("--root", "root", type=click.Path(path_type=Path, file_okay=False), default=None)
@click.option("--expect-sha256", "expect_sha256", default=None, help="Require this canonical content hash.")
def cmd_policy_show(policy_path: str, root: Path | None, expect_sha256: str | None) -> None:
    """Print path, content hash, and file hash. Word and PDF files fail closed."""
    base = root if root is not None else Path.cwd()
    try:
        _document, custody = address_policy(base, policy_path, expect_sha256=expect_sha256)
    except BeaconError as exc:
        _die(exc)
    _emit(custody.model_dump(mode="json"))


@cmd_policy.command("hash")
@click.option("--path", "policy_path", required=True, help="Relative path of the JSON policy file.")
@click.option("--root", "root", type=click.Path(path_type=Path, file_okay=False), default=None)
def cmd_policy_hash(policy_path: str, root: Path | None) -> None:
    """Print the canonical content hash of one policy file."""
    base = root if root is not None else Path.cwd()
    try:
        _document, custody = address_policy(base, policy_path)
    except BeaconError as exc:
        _die(exc)
    click.echo(custody.content_sha256)


@main.group("ingest")
def cmd_ingest() -> None:
    """Register an external file as a candidate. A candidate is not a witness seal."""


@cmd_ingest.command("mapper")
@click.option(
    "--file",
    "mapper_file",
    required=True,
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Mapper JSON file. PDF and Word files fail closed.",
)
@click.option("--out", "out_dir", type=click.Path(path_type=Path, file_okay=False), default=None)
def cmd_ingest_mapper(mapper_file: Path, out_dir: Path | None) -> None:
    """Write a candidate registration for a mapper report, KSI catalog, or link file."""
    settings = _settings()
    target = out_dir if out_dir is not None else settings.home / "ingest" / "mapper"
    try:
        candidate, written = ingest_mapper_file(mapper_file, target)
    except BeaconError as exc:
        _die(exc)
    _emit(
        {
            "ok": True,
            "role": candidate.role,
            "shape": candidate.shape,
            "path": str(written),
            "input_sha256": candidate.input_sha256,
            "policy_draft_sha256": candidate.policy_draft_sha256,
            "record_v": candidate.record_v,
        }
    )


@main.command("check")
@click.option("--scope", "scope_id", default=None, help="Assessment scope id to verify against sealed payloads.")
def cmd_check(scope_id: str | None) -> None:
    """Verify signatures, the hash chain, Merkle roots, and TSA tokens. Fail closed."""
    try:
        result = check_chain(_settings(), scope_id=scope_id)
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
