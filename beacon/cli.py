"""Beacon CLI: init, seed, collect, check, scope, ledger, pack, trust, scn, inbox."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from beacon import __version__
from beacon.config import load_settings
from beacon.assurance.compile import compile_20x_drafts, write_compiled_packs
from beacon.assurance.index import ledger_method_report, load_evidence_ledger
from beacon.assurance.inbox import intake_inbox_file
from beacon.assurance.packs import PACK_KINDS
from beacon.assurance.scn import draft_scn, write_scn
from beacon.assurance.trust_center import publish_bytes, publish_ledger_summary
from beacon.assurance.mapper_ingest import ingest_mapper_file
from beacon.assurance.policy import address_policy
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


@cmd_scope.command("import")
@click.option("--file", "source", required=True, type=click.Path(path_type=Path, exists=True, dir_okay=False))
def cmd_scope_import(source: Path) -> None:
    """Enroll an operator-reviewed scope. Existing ids are never overwritten."""
    from beacon.scope.store import import_scope
    try:
        scope = import_scope(_settings(), source.read_text(encoding="utf-8"))
    except BeaconError as exc:
        _die(exc)
    _emit({"scope_id": scope.scope_id, "scope_sha256": scope.content_sha256()})


@cmd_scope.command("list")
def cmd_scope_list() -> None:
    from beacon.scope.store import list_scopes
    try:
        _emit({"scopes": list_scopes(_settings())})
    except BeaconError as exc:
        _die(exc)


@main.command("objectives")
@click.option("--control", required=True)
def cmd_objectives(control: str) -> None:
    """Show unchanged assessment objective rows from the pinned SCF workbook."""
    from beacon.scf.objective_catalog import objectives
    try:
        _emit({"objectives": objectives(control.upper())})
    except BeaconError as exc:
        _die(exc)


@main.command("rules")
@click.option("--control", required=True)
def cmd_rules(control: str) -> None:
    """Show supporting rules and their hashes for operator scope approval."""
    from beacon.assurance.evaluation import rules_for
    try:
        _emit({"rules": rules_for(control.upper())})
    except BeaconError as exc:
        _die(exc)


@main.command("evaluate")
@click.option("--scope", "scope_id", required=True)
@click.option("--control", required=True)
@click.option("--judge", type=click.Choice(["none", "jev", "bedrock"]), default="none", show_default=True)
def cmd_evaluate(scope_id: str, control: str, judge: str) -> None:
    """Evaluate scoped supporting assertions and seal a historical receipt."""
    from beacon.assurance.evaluation import evaluate_control
    from beacon.assurance.bedrock import make_judge
    settings = _settings()
    try:
        evaluator = make_judge(judge, load_scope(settings, scope_id))
        _emit(evaluate_control(settings, scope_id=scope_id, control_ref=control.upper(), judge=evaluator))
    except BeaconError as exc:
        _die(exc)


@main.command("receipts")
@click.option("--scope", "scope_id", default=None)
def cmd_receipts(scope_id: str | None) -> None:
    """Read verified historical evaluations; re-evaluate for a current result."""
    from beacon.assurance.evaluation import list_receipts
    try:
        _emit({"receipts": list_receipts(_settings(), scope_id=scope_id)})
    except BeaconError as exc:
        _die(exc)


@main.command("assessment-specs")
@click.option("--scope", "scope_id", default=None)
def cmd_assessment_specs(scope_id: str | None) -> None:
    """List immutable assessment specifications and scope approval state."""
    from beacon.assurance.specs import list_specs
    try:
        _emit({"specs": list_specs(_settings(), scope_id=scope_id)})
    except BeaconError as exc:
        _die(exc)


@main.command("assessment-spec-draft")
@click.option("--policy-path", default="policies/encryption.json", show_default=True)
@click.option("--time-basis", type=click.Choice(["point_in_time", "period"]), default="point_in_time",
              show_default=True)
def cmd_assessment_spec_draft(policy_path: str, time_basis: str) -> None:
    """Print a reviewable EBS specification draft. This does not import or approve it."""
    from beacon.assurance.specs import draft_ebs_spec
    try:
        _emit(draft_ebs_spec(policy_path=policy_path, time_basis=time_basis))
    except (BeaconError, ValueError) as exc:
        _die(exc)


@main.command("assessment-spec-import")
@click.option("--file", "source", required=True, type=click.Path(path_type=Path, exists=True, dir_okay=False))
def cmd_assessment_spec_import(source: Path) -> None:
    """Store a reviewed specification by digest. The scope must still approve that digest."""
    from beacon.assurance.specs import import_spec
    try:
        if source.stat().st_size > 65536:
            raise BeaconError("E_SPEC", "assessment specification exceeds 64 KiB")
        _emit(import_spec(_settings(), source.read_text(encoding="utf-8")))
    except (BeaconError, OSError, UnicodeError) as exc:
        _die(exc)


@main.command("assess")
@click.option("--scope", "scope_id", required=True)
@click.option("--spec", "spec_sha256", required=True)
def cmd_assess(scope_id: str, spec_sha256: str) -> None:
    """Evaluate one approved evidence-set specification and seal a receipt."""
    from beacon.assurance.assessments import evaluate_assessment
    try:
        _emit(evaluate_assessment(_settings(), scope_id=scope_id, spec_sha256=spec_sha256))
    except BeaconError as exc:
        _die(exc)


@main.command("assessments")
@click.option("--scope", "scope_id", default=None)
def cmd_assessments(scope_id: str | None) -> None:
    """List current assessment receipts, gaps, invalidation, and review state."""
    from beacon.assurance.assessments import list_assessments
    try:
        _emit({"assessments": list_assessments(_settings(), scope_id=scope_id)})
    except BeaconError as exc:
        _die(exc)


@main.command("assessment-refresh")
@click.option("--scope", "scope_id", required=True)
@click.option("--collect-missing", is_flag=True, help="Run only scope-authorized, bounded live collectors.")
def cmd_assessment_refresh(scope_id: str, collect_missing: bool) -> None:
    """Reevaluate changed evidence; live collection is explicit and scope-gated."""
    from beacon.assurance.assessments import refresh_assessments
    try:
        _emit(refresh_assessments(_settings(), scope_id=scope_id, collect_missing=collect_missing))
    except BeaconError as exc:
        _die(exc)


@main.command("review-queue")
@click.option("--scope", "scope_id", default=None)
def cmd_review_queue(scope_id: str | None) -> None:
    """Show assessments requiring evidence, reevaluation, or review."""
    from beacon.assurance.assessments import review_queue
    try:
        _emit({"assessments": review_queue(_settings(), scope_id=scope_id)})
    except BeaconError as exc:
        _die(exc)


def _interactive_terminal() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


@main.command("review-assessment")
@click.option("--receipt", "receipt_evidence_id", required=True)
@click.option("--decision", type=click.Choice(["accept", "reject"]), required=True)
@click.option("--rationale", required=True)
def cmd_review_assessment(receipt_evidence_id: str, decision: str, rationale: str) -> None:
    """Record a local OS-attributed supporting review; never sets compliance claims.

    The record names an OS account, not a person. The terminal check and typed
    confirmation stop plain scripts and agent tool calls; they do not stop a
    process that fakes a terminal. Approve a reviewer account that no agent,
    MCP server, or automation runs as.
    """
    from beacon.assurance.assessments import record_review
    if not _interactive_terminal():
        _die(BeaconError("E_REVIEW", "operator review needs an interactive terminal; scripts cannot record reviews"))
    typed = click.prompt("Type the receipt evidence id to confirm this review", default="", show_default=False)
    if typed.strip() != receipt_evidence_id:
        _die(BeaconError("E_REVIEW", "confirmation did not match the receipt evidence id; no review recorded"))
    try:
        _emit(record_review(_settings(), receipt_evidence_id=receipt_evidence_id,
                            decision=decision, rationale=rationale))
    except BeaconError as exc:
        _die(exc)


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


@main.group("trust")
def cmd_trust() -> None:
    """Write allowlisted pack and report copies. This command does not host a site."""


@cmd_trust.command("publish")
@click.option("--relative", "relative", default=None, help="Allowlisted key under public/trust-center/.")
@click.option("--file", "source", type=click.Path(path_type=Path, exists=True, dir_okay=False), default=None)
@click.option("--ledger", "ledger", is_flag=True, help="Publish the local ledger summary.")
@click.option("--stamp", "artifact_id", default="summary", show_default=True)
@click.option("--scope", "scope_id", default=None)
@click.option("--pack", "pack_path", type=click.Path(path_type=Path, exists=True, dir_okay=False), default=None)
@click.option("--scf", "scf_id", default=None)
@click.option("--class", "package_class", type=click.Choice(["c", "d"]), default="c", show_default=True)
@click.option("--out", "out_dir", type=click.Path(path_type=Path, file_okay=False), default=None)
def cmd_trust_publish(
    relative: str | None,
    source: Path | None,
    ledger: bool,
    artifact_id: str,
    scope_id: str | None,
    pack_path: Path | None,
    scf_id: str | None,
    package_class: str,
    out_dir: Path | None,
) -> None:
    """Copy one allowlisted artifact into the local trust-center tree."""
    settings = _settings()
    target = out_dir if out_dir is not None else settings.export_dir / "trust-center"
    match package_class:
        case "c" | "d":
            chosen_class = package_class
        case _:
            _die(BeaconError("E_TRUST", "package class must be c or d"))
    try:
        if ledger:
            record = publish_ledger_summary(
                settings,
                artifact_id=artifact_id,
                out_dir=target,
                package_class=chosen_class,
                scope_id=scope_id,
                pack_path=pack_path,
                scf_id=scf_id,
            )
        else:
            if source is None or relative is None:
                _die(BeaconError("E_TRUST", "pass --file and --relative, or pass --ledger"))
            record = publish_bytes(settings, relative=relative, body=source.read_bytes(), out_dir=target)
    except BeaconError as exc:
        _die(exc)
    _emit(record.model_dump(mode="json"))


@main.group("scn")
def cmd_scn() -> None:
    """Draft a significant-change notice. This command does not send mail."""


@cmd_scn.command("draft")
@click.option("--scope", "scope_id", default=None)
@click.option("--pack", "pack_path", type=click.Path(path_type=Path, exists=True, dir_okay=False), default=None)
@click.option("--scf", "scf_id", default=None)
@click.option("--class", "package_class", type=click.Choice(["c", "d"]), default="c", show_default=True)
@click.option("--changes", "changes_path", type=click.Path(path_type=Path, exists=True, dir_okay=False), default=None)
@click.option("--dry-run", is_flag=True, help="Print the draft and do not write a file.")
@click.option("--out", "out_dir", type=click.Path(path_type=Path, file_okay=False), default=None)
def cmd_scn_draft(
    scope_id: str | None,
    pack_path: Path | None,
    scf_id: str | None,
    package_class: str,
    changes_path: Path | None,
    dry_run: bool,
    out_dir: Path | None,
) -> None:
    """Build one SCN draft from seals and package gaps."""
    match package_class:
        case "c" | "d":
            chosen_class = package_class
        case _:
            _die(BeaconError("E_SCN", "package class must be c or d"))
    settings = _settings()
    try:
        draft = draft_scn(
            settings,
            package_class=chosen_class,
            scope_id=scope_id,
            pack_path=pack_path,
            scf_id=scf_id,
            changes_path=changes_path,
        )
    except BeaconError as exc:
        _die(exc)
    payload = draft.canonical_body()
    payload["dry_run"] = dry_run
    if not dry_run:
        target = out_dir if out_dir is not None else settings.export_dir / "scn"
        try:
            written = write_scn(draft, target)
        except BeaconError as exc:
            _die(exc)
        payload["path"] = str(written)
    _emit(payload)


@main.group("inbox")
def cmd_inbox() -> None:
    """Digest a local security-inbox file. This command does not open a mailbox."""


@cmd_inbox.command("intake")
@click.option(
    "--file",
    "inbox_file",
    required=True,
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
)
@click.option("--out", "out_dir", type=click.Path(path_type=Path, file_okay=False), default=None)
def cmd_inbox_intake(inbox_file: Path, out_dir: Path | None) -> None:
    """Write a candidate for each known message. An unknown shape fails closed."""
    settings = _settings()
    target = out_dir if out_dir is not None else settings.home / "ingest" / "inbox"
    try:
        candidates, paths = intake_inbox_file(inbox_file, target)
    except BeaconError as exc:
        _die(exc)
    _emit(
        {
            "ok": True,
            "count": len(candidates),
            "paths": [str(path) for path in paths],
            "credential_used": False,
            "mailed": False,
            "record_v": 1,
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


@cmd_policy.command("seal")
@click.option("--scope", "scope_id", required=True)
@click.option("--root", required=True, type=click.Path(path_type=Path, exists=True, file_okay=False))
@click.option("--path", required=True)
@click.option("--commit", required=True)
def cmd_policy_seal(scope_id: str, root: Path, path: str, commit: str) -> None:
    """Seal the approved Git commit's policy bytes, ignoring working-tree edits."""
    from beacon.assurance.policy_capture import capture_policy
    try:
        _emit(capture_policy(_settings(), scope_id=scope_id, root=root, path=path, commit=commit))
    except BeaconError as exc:
        _die(exc)


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


@main.group("custody")
def cmd_custody() -> None:
    """Explicit trust enrollment and continuity setup."""


@cmd_custody.command("enroll")
@click.option("--recorder", required=True)
@click.option("--witness", required=True)
@click.option("--tsa-sha256", required=True)
@click.option("--workspace-id", required=True)
@click.option("--expected-seq", required=True, type=click.IntRange(min=0))
@click.option("--expected-head", required=True)
def cmd_enroll(**kwargs) -> None:
    """Migrate legacy history using public pins and a previously retained head."""
    from beacon.crypto.enrollment import enroll
    try:
        _emit(enroll(_settings(), **kwargs))
    except BeaconError as exc:
        _die(exc)


@cmd_custody.command("anchor")
def cmd_anchor() -> None:
    """Enroll BEACON_ANCHOR_DIR at the currently verified head; never reset it."""
    from beacon.crypto.enrollment import enroll_anchor
    try:
        _emit(enroll_anchor(_settings()))
    except BeaconError as exc:
        _die(exc)


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

    import os
    if host not in {"127.0.0.1", "localhost", "::1"} and not os.environ.get("BEACON_API_TOKEN"):
        _die(BeaconError("E_AUTH", "non-loopback serving requires BEACON_API_TOKEN and a TLS reverse proxy"))

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
