"""Ingest an ai-gate-ledger export as advisory evidence.

A model verdict never sets a control result. ``claim_status`` stays
``unverified``. ``control_satisfied`` and ``assurance_claim`` stay false.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any

from beacon.canonical import dumps, sha256_bytes
from beacon.config import Settings
from beacon.crypto.trust import atomic_write
from beacon.crypto.witness import create_checkpoint, seal_payload
from beacon.errors import BeaconError, E_ADVISORY, E_NOT_INITIALIZED, E_SCOPE, fail
from beacon.locking import locked
from beacon.scf.objective_catalog import objectives

SCHEMA_BEACON = "ai-gate-ledger/beacon-advisory@2"
SCHEMA_CICD = "ai-gate-ledger/cicd-receipt-row@2"
SCHEMA_VERSION = 1
KIND = "model_advisory"
CLAIM_STATUS = "unverified"
EVIDENCE_CLASS = "advisory"
PLUGIN = "beacon.advisory-ingest"
MODE = "advisory"
SCF_PIN = "2026.3"
SCF_KEYS = ("scf_version", "scf_id", "legacy_scf")
# Status tokens this command must not emit. Key names such as control_satisfied
# do not match: "_" is a word character, so the token is not a separate word.
CLAIM_WORDS = frozenset({"met", "pass", "satisfied", "compliant", "evidenced", "proven"})
_CLAIM_WORD = re.compile(r"\b(?:" + "|".join(sorted(CLAIM_WORDS)) + r")\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
_NIST_FAMILIES = "AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR"
_NIST_800_53_RE = re.compile(rf"^(?:{_NIST_FAMILIES})-\d{{1,2}}(?:\(\d{{1,2}}\))?$")
_INTEGRITY = frozenset({"verified", "unverified"})


def assert_no_claim_words(body: object) -> None:
    """Reject MET, pass, satisfied, compliant, evidenced, or proven as words."""
    text = json.dumps(body, ensure_ascii=False)
    if _CLAIM_WORD.search(text):
        fail(E_ADVISORY, "advisory output uses the status word unverified")


@lru_cache(maxsize=1)
def pinned_control_ids() -> frozenset[str]:
    """SCF 2026.3 control ids from the pinned objective rows. No invented ids."""
    return frozenset(str(row["control_ref"]) for row in objectives())


def ingest_advisory(
    settings: Settings,
    *,
    export_file: Path,
    ledger_root: Path,
    cicd_file: Path | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Check one export and, unless ``dry_run``, store receipts and one witness record."""
    if settings.require_scope:
        fail(E_SCOPE, "BEACON_REQUIRE_SCOPE=1 rejects unbound advisory evidence")
    plan = plan_advisory_ingest(export_file, ledger_root, cicd_file)
    if dry_run:
        result = _public(plan, dry_run=True)
        assert_no_claim_words(result)
        return result
    stored = _commit(settings, plan)
    result = _public(plan, dry_run=False, stored=stored)
    assert_no_claim_words(result)
    return result


def plan_advisory_ingest(
    export_file: Path,
    ledger_root: Path,
    cicd_file: Path | None = None,
) -> dict[str, Any]:
    """Run every check. Return the documents that a later commit would write."""
    export_path = _file(export_file, "export file")
    root = _dir(ledger_root)
    raw = _read_bytes(export_path, "export file")
    export_sha = sha256_bytes(raw)
    document = _json_object(raw, "export file")
    _require_beacon_document(document)
    verify_ledger(root)
    export_ledger_root = _absolute_root(document.get("ledger_root"))
    heads = _verify_heads(root, document.get("ledger_heads"))
    run_meta = _verify_run_receipts(root, export_ledger_root, document.get("receipts"))
    verdicts_by_run, mapped_ids = _map_subjects(
        document.get("subjects"), run_meta, root, export_ledger_root
    )
    export_date = _export_date(document.get("generated"))
    files: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    pointers: list[dict[str, str]] = []
    for run_id in sorted(run_meta):
        meta = run_meta[run_id]
        _safe_run_id(run_id)
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "kind": KIND,
            "claim_status": CLAIM_STATUS,
            "control_satisfied": False,
            "assurance_claim": False,
            "evidence_class": EVIDENCE_CLASS,
            "run_id": run_id,
            "source": meta["source"],
            "started": meta["started"],
            "ended": meta["ended"],
            "receipt_sha256": meta["sha256"],
            "export_sha256": export_sha,
            "ledger_heads": heads,
            "ledger_integrity": meta["ledger_integrity"],
            "verdicts": verdicts_by_run[run_id],
        }
        _validate_receipt(receipt)
        body = dumps(receipt)
        digest = sha256_bytes(body)
        relpath = f"advisory/{export_date}/{run_id}.json"
        files.append({"relpath": relpath, "body": body, "sha256": digest})
        pointers.append({"run_id": run_id, "relpath": relpath, "sha256": digest})
        receipts.append(receipt)
    cicd_doc: dict[str, Any] | None = None
    cicd_pointer: dict[str, Any] | None = None
    if cicd_file is not None:
        cicd_doc, cicd_bytes, cicd_ids = _plan_cicd(cicd_file, root, export_ledger_root)
        mapped_ids.update(cicd_ids)
        relpath = f"advisory/{export_date}/cicd.json"
        digest = sha256_bytes(cicd_bytes)
        files.append({"relpath": relpath, "body": cicd_bytes, "sha256": digest})
        cicd_pointer = {"relpath": relpath, "sha256": digest, "row_count": len(cicd_doc["rows"])}
    counts = _counts(receipts, cicd_doc)
    witness = {
        "format": "beacon.advisory-ingest/v1",
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "claim_status": CLAIM_STATUS,
        "control_satisfied": False,
        "assurance_claim": False,
        "evidence_class": EVIDENCE_CLASS,
        "export_date": export_date,
        "export_sha256": export_sha,
        "counts": counts,
        "mapped_scf_ids": sorted(mapped_ids),
        "receipts": pointers,
    }
    if cicd_pointer is not None:
        witness["cicd"] = cicd_pointer
    assert_no_claim_words(witness)
    for receipt in receipts:
        assert_no_claim_words(receipt)
    if cicd_doc is not None:
        assert_no_claim_words(cicd_doc)
    relpaths = [item["relpath"] for item in files]
    if len(relpaths) != len(set(relpaths)):
        fail(E_ADVISORY, "advisory output paths collide")
    return {
        "export_date": export_date,
        "export_sha256": export_sha,
        "receipts": receipts,
        "witness": witness,
        "cicd": cicd_doc,
        "files": files,
        "mapped_scf_ids": sorted(mapped_ids),
        "counts": counts,
    }


def verify_ledger(ledger_root: Path) -> dict[str, Any]:
    """Run ``python3 verify.py --json`` in the ledger root. Ignore export ledger_verify."""
    base = ledger_root.resolve()
    script = (base / "verify.py").resolve()
    if not script.is_file() or not script.is_relative_to(base):
        fail(E_ADVISORY, "ledger verify.py must stay inside the ledger root")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "AI_GATE_LEDGER_ROOT": str(base),
    }
    try:
        proc = subprocess.run(
            ["python3", "verify.py", "--json"],
            cwd=base,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired:
        fail(E_ADVISORY, "ledger verify timed out")
    except OSError as exc:
        fail(E_ADVISORY, f"ledger verify could not start: {exc}")
    if proc.returncode != 0:
        fail(E_ADVISORY, "ledger verify is not OK")
    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError:
        fail(E_ADVISORY, "ledger verify did not return JSON")
    failures = body.get("failures") if isinstance(body, dict) else None
    if not isinstance(body, dict) or body.get("ok") is not True or not isinstance(failures, list) or failures:
        fail(E_ADVISORY, "ledger verify is not OK")
    return body


def _commit(settings: Settings, plan: dict[str, Any]) -> dict[str, str]:
    if not settings.keys_dir.is_dir():
        fail(E_NOT_INITIALIZED, "run `beacon init` first")
    return _commit_locked(settings, plan)


@locked
def _commit_locked(settings: Settings, plan: dict[str, Any]) -> dict[str, str]:
    if not (settings.keys_dir / "recorder.pem").is_file():
        fail(E_NOT_INITIALIZED, "run `beacon init` first")
    evidence_root = settings.evidence_dir.resolve()
    planned: list[tuple[Path, dict[str, Any]]] = []
    for item in plan["files"]:
        planned.append((_evidence_dest(evidence_root, item["relpath"]), item))
    for dest, item in planned:
        if dest.is_file() and sha256_bytes(dest.read_bytes()) != item["sha256"]:
            fail(E_ADVISORY, "advisory file already exists with a different digest")
    created: list[Path] = []
    try:
        for dest, item in planned:
            if dest.is_file():
                continue
            atomic_write(dest, item["body"])
            created.append(dest)
            if sha256_bytes(dest.read_bytes()) != item["sha256"]:
                fail(E_ADVISORY, "written advisory file sha256 mismatch")
        record = seal_payload(
            settings,
            plugin=PLUGIN,
            mode=MODE,
            scf_targets=list(plan["mapped_scf_ids"]),
            payload=plan["witness"],
        )
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    create_checkpoint(settings)
    return {"witness_evidence_id": record.evidence_id, "witness_sha256": record.payload_sha256}


def _public(plan: dict[str, Any], *, dry_run: bool, stored: dict[str, str] | None = None) -> dict[str, Any]:
    counts = plan["counts"]
    result: dict[str, Any] = {
        "ok": True,
        "dry_run": dry_run,
        "claim_status": CLAIM_STATUS,
        "control_satisfied": False,
        "assurance_claim": False,
        "evidence_class": EVIDENCE_CLASS,
        "export_date": plan["export_date"],
        "export_sha256": plan["export_sha256"],
        "runs": counts["runs"],
        "verdicts": counts["verdicts"],
        "needs_review": counts["needs_review"],
        "advisory_observed": counts["advisory_observed"],
        "unmapped": counts["unmapped"],
        "mapped": counts["mapped"],
        "paths": [item["relpath"] for item in plan["files"]],
        "receipts": plan["receipts"],
        "witness": plan["witness"],
        "cicd_rows": counts["cicd_rows"],
        "cicd_verified": counts["cicd_verified"],
    }
    if plan["cicd"] is not None:
        result["cicd"] = plan["cicd"]
    if stored is not None:
        result.update(stored)
    return result


def _counts(receipts: list[dict[str, Any]], cicd: dict[str, Any] | None) -> dict[str, Any]:
    verdicts = [row for receipt in receipts for row in receipt["verdicts"]]
    cicd_rows = None if cicd is None else cicd["rows"]
    return {
        "runs": len(receipts),
        "verdicts": len(verdicts),
        "needs_review": sum(row["disposition"] == "needs_review" for row in verdicts),
        "advisory_observed": sum(row["disposition"] == "advisory_observed" for row in verdicts),
        "unmapped": sum(row["mapping"] == "unmapped" for row in verdicts),
        "mapped": sum(row["mapping"] == "mapped" for row in verdicts),
        "cicd_rows": None if cicd_rows is None else len(cicd_rows),
        "cicd_verified": 0 if cicd_rows is None else sum(row["ledger_integrity"] == "verified" for row in cicd_rows),
    }


def _require_beacon_document(document: dict[str, Any]) -> None:
    if document.get("schema") != SCHEMA_BEACON:
        fail(E_ADVISORY, "export schema is not ai-gate-ledger/beacon-advisory@2")
    if document.get("advisory") is not True:
        fail(E_ADVISORY, "export advisory flag is not true")
    if document.get("evidence_class") != EVIDENCE_CLASS:
        fail(E_ADVISORY, "export evidence_class is not advisory")


def _verify_heads(ledger_root: Path, raw: object) -> dict[str, str]:
    if not isinstance(raw, dict) or not raw:
        fail(E_ADVISORY, "ledger_heads must be a non-empty object")
    checked: dict[str, str] = {}
    for rel, expected in raw.items():
        if not isinstance(rel, str) or not _SHA256_RE.fullmatch(expected if isinstance(expected, str) else ""):
            fail(E_ADVISORY, "ledger_heads entries must be relative paths and sha256 digests")
        path = _relative_file(ledger_root, rel, "ledger head")
        actual = _last_line_sha(path)
        if actual != expected:
            fail(E_ADVISORY, f"ledger head sha256 mismatch for {rel}")
        checked[rel] = expected
    return checked


def _verify_run_receipts(ledger_root: Path, export_root: str, raw: object) -> dict[str, dict[str, str]]:
    if not isinstance(raw, dict) or not raw:
        fail(E_ADVISORY, "receipts must be a non-empty object")
    runs: dict[str, dict[str, str]] = {}
    for run_id, meta in raw.items():
        if not isinstance(run_id, str) or not isinstance(meta, dict):
            fail(E_ADVISORY, "each receipt entry needs a run_id and an object")
        _safe_run_id(run_id)
        path_text = _text(meta.get("path"), "receipt path")
        expected = _digest(meta.get("sha256"), "receipt sha256")
        status = _integrity(meta.get("status"))
        dest = _rebase(export_root, ledger_root, path_text, required=True)
        if dest is None or not dest.is_file():
            fail(E_ADVISORY, "receipt file is missing")
        actual = sha256_bytes(_read_bytes(dest, "receipt file"))
        if actual != expected:
            fail(E_ADVISORY, "receipt sha256 mismatch")
        runs[run_id] = {
            "source": _text(meta.get("source"), "receipt source"),
            "started": _text(meta.get("started"), "receipt started"),
            "ended": _text(meta.get("ended"), "receipt ended"),
            "sha256": actual,
            "ledger_integrity": status,
        }
    return runs


def _map_subjects(
    raw: object,
    runs: dict[str, dict[str, str]],
    ledger_root: Path,
    export_root: str,
) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    if not isinstance(raw, list):
        fail(E_ADVISORY, "subjects must be a list")
    grouped = {run_id: [] for run_id in runs}
    mapped: set[str] = set()
    for subject in raw:
        if not isinstance(subject, dict):
            fail(E_ADVISORY, "each subject must be an object")
        source = _text(subject.get("source"), "subject source")
        name = _text(subject.get("subject"), "subject")
        verdicts = subject.get("verdicts")
        if not isinstance(verdicts, list):
            fail(E_ADVISORY, "subject verdicts must be a list")
        for verdict in verdicts:
            if not isinstance(verdict, dict):
                fail(E_ADVISORY, "each verdict must be an object")
            run_id = _safe_run_id(_text(verdict.get("run_id"), "verdict run_id"))
            if run_id not in grouped:
                fail(E_ADVISORY, "verdict run_id is not in receipts")
            if source != runs[run_id]["source"]:
                fail(E_ADVISORY, "subject source does not match the run receipt")
            if "source_receipt" in verdict:
                _check_source_receipt(verdict.get("source_receipt"), ledger_root, export_root)
            row, scf_id = _map_verdict(subject, verdict, source, name, runs[run_id]["ledger_integrity"])
            grouped[run_id].append(row)
            if scf_id is not None:
                mapped.add(scf_id)
    return grouped, mapped


def _check_source_receipt(raw: object, ledger_root: Path, export_root: str) -> None:
    """When a verdict names a source receipt, Beacon recomputes that file sha256."""
    if not isinstance(raw, dict):
        fail(E_ADVISORY, "source_receipt must be an object")
    path_text = _text(raw.get("path"), "source_receipt path")
    expected = _digest(raw.get("sha256"), "source_receipt sha256")
    dest = _rebase(export_root, ledger_root, path_text, required=True)
    if dest is None or not dest.is_file():
        fail(E_ADVISORY, "source receipt file is missing")
    actual = sha256_bytes(_read_bytes(dest, "source receipt file"))
    if actual != expected:
        fail(E_ADVISORY, "source receipt sha256 mismatch")


def _map_verdict(
    subject: dict[str, Any],
    verdict: dict[str, Any],
    source: str,
    name: str,
    run_integrity: str,
) -> tuple[dict[str, Any], str | None]:
    flag = verdict.get("flag")
    if flag not in (True, False, None):
        fail(E_ADVISORY, "flag must be true, false, or null")
    held = _held(verdict.get("held"))
    disposition = "needs_review" if flag is True or held is not None else "advisory_observed"
    stated = _integrity(verdict.get("receipt_status"))
    has_source = "source_receipt" in verdict and verdict.get("source_receipt") is not None
    if not has_source and stated != run_integrity:
        fail(E_ADVISORY, "verdict receipt status does not match the run receipt")
    ledger_integrity = stated if has_source else run_integrity
    kept, reason, mapping = _scf_fields(_scf_view(subject, verdict))
    row: dict[str, Any] = {
        "source": source,
        "subject": name,
        "unit": _text(verdict.get("unit"), "verdict unit"),
        "check": _text(verdict.get("check"), "verdict check"),
        "engine": _text(verdict.get("engine"), "verdict engine"),
        "model_id": _text(verdict.get("model_id"), "verdict model_id"),
        "content_hash": _digest(verdict.get("content_hash"), "verdict content_hash"),
        "flag": flag,
        "held": held,
        "ts": _text(verdict.get("ts"), "verdict ts"),
        "disposition": disposition,
        "ledger_integrity": ledger_integrity,
        "mapping": mapping,
    }
    row.update(kept)
    if reason is not None:
        row["scf_drop_reason"] = reason
    return row, kept.get("scf_id")


def _scf_view(subject: dict[str, Any], verdict: dict[str, Any]) -> dict[str, Any]:
    """Copy SCF fields only from the export. Verdict fields win. Never infer an id."""
    view: dict[str, Any] = {}
    for key in SCF_KEYS:
        if key in verdict and verdict[key] is not None:
            view[key] = verdict[key]
    if view:
        return view
    for key in SCF_KEYS:
        if key in subject and subject[key] is not None:
            view[key] = subject[key]
    return view


def _scf_fields(view: dict[str, Any]) -> tuple[dict[str, str], str | None, str]:
    if not view:
        return {}, None, "unmapped"
    version, has_version = _optional_text(view, "scf_version")
    scf_id, has_id = _optional_text(view, "scf_id")
    legacy, has_legacy = _optional_text(view, "legacy_scf")
    if has_version and version != SCF_PIN:
        return {}, "scf_version is not 2026.3", "unmapped"
    if not has_id:
        return {}, "scf_id absent", "unmapped"
    if scf_id not in pinned_control_ids():
        return {}, "scf_id not in pinned SCF 2026.3 catalog", "unmapped"
    kept: dict[str, str] = {"scf_id": scf_id}
    if has_version:
        kept["scf_version"] = SCF_PIN
    if has_legacy:
        kept["legacy_scf"] = legacy
    return kept, None, "mapped"


def _optional_text(view: dict[str, Any], key: str) -> tuple[str, bool]:
    if key not in view:
        return "", False
    value = view[key]
    if not isinstance(value, str) or not value or value != value.strip():
        fail(E_ADVISORY, f"{key} must be a non-blank string when present")
    return value, True


def _plan_cicd(
    cicd_file: Path,
    ledger_root: Path,
    export_root: str,
) -> tuple[dict[str, Any], bytes, set[str]]:
    path = _file(cicd_file, "cicd file")
    raw = _read_bytes(path, "cicd file")
    rows_in = _cicd_rows(raw)
    mapped: set[str] = set()
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(rows_in):
        mapped_row, scf_id = _map_cicd_row(row, ledger_root, export_root, index)
        rows.append(mapped_row)
        if scf_id is not None:
            mapped.add(scf_id)
    document = {
        "schema_version": SCHEMA_VERSION,
        "kind": "model_advisory_cicd",
        "claim_status": CLAIM_STATUS,
        "control_satisfied": False,
        "assurance_claim": False,
        "evidence_class": EVIDENCE_CLASS,
        "export_sha256": sha256_bytes(raw),
        "rows": rows,
    }
    assert_no_claim_words(document)
    return document, dumps(document), mapped


def _cicd_rows(raw: bytes) -> list[dict[str, Any]]:
    if not raw.strip():
        return []
    rows: list[dict[str, Any]] = []
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        fail(E_ADVISORY, f"cicd file is not UTF-8: {exc}")
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(E_ADVISORY, f"cicd line {line_no} is not JSON: {exc}")
        if not isinstance(row, dict):
            fail(E_ADVISORY, f"cicd line {line_no} must be an object")
        rows.append(row)
    return rows


def _map_cicd_row(
    row: dict[str, Any],
    ledger_root: Path,
    export_root: str,
    index: int,
) -> tuple[dict[str, Any], str | None]:
    if row.get("schema") != SCHEMA_CICD:
        fail(E_ADVISORY, "cicd row schema is not ai-gate-ledger/cicd-receipt-row@2")
    if row.get("evidence_class") != EVIDENCE_CLASS:
        fail(E_ADVISORY, "cicd evidence_class is not advisory")
    if "advisory" in row and row.get("advisory") is not True:
        fail(E_ADVISORY, "cicd advisory flag is not true")
    derived = row.get("derived")
    derived_ok = isinstance(derived, list) and all(
        isinstance(item, str) and _NIST_800_53_RE.fullmatch(item) for item in derived
    )
    if not derived_ok:
        fail(E_ADVISORY, f"cicd row {index} derived must contain NIST SP 800-53 ids only")
    view: dict[str, Any] = {}
    if row.get("scf_version") is not None:
        view["scf_version"] = row.get("scf_version")
    if row.get("scf") is not None:
        view["scf_id"] = row.get("scf")
    if row.get("legacy_scf") is not None:
        view["legacy_scf"] = row.get("legacy_scf")
    kept, reason, mapping = _scf_fields(view)
    receipt = row.get("receipt")
    if not isinstance(receipt, dict):
        fail(E_ADVISORY, "cicd receipt must be an object")
    integrity = _cicd_integrity(receipt, ledger_root, export_root)
    mapped: dict[str, Any] = {
        "gate": _text(row.get("gate"), "cicd gate"),
        "derived": list(derived),
        "ledger_integrity": integrity,
        "mapping": mapping,
    }
    if isinstance(row.get("ksi"), str) and row["ksi"]:
        mapped["ksi"] = row["ksi"]
    mapped.update(kept)
    if reason is not None:
        mapped["scf_drop_reason"] = reason
    return mapped, kept.get("scf_id")


def _cicd_integrity(receipt: dict[str, Any], ledger_root: Path, export_root: str) -> str:
    """Verified only when Beacon reads the CI receipt and the sha256 matches."""
    path_text = receipt.get("path")
    digest = receipt.get("sha256")
    if not isinstance(path_text, str) or not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        return "unverified"
    dest = _rebase(export_root, ledger_root, path_text, required=False)
    if dest is None or not dest.is_file():
        return "unverified"
    actual = sha256_bytes(_read_bytes(dest, "cicd receipt"))
    if actual != digest:
        return "unverified"
    return "verified"


def _validate_receipt(receipt: dict[str, Any]) -> None:
    if receipt["schema_version"] != SCHEMA_VERSION or receipt["kind"] != KIND:
        fail(E_ADVISORY, "advisory receipt kind must be model_advisory schema 1")
    if receipt["claim_status"] != CLAIM_STATUS:
        fail(E_ADVISORY, "advisory receipt status is unverified")
    if receipt["control_satisfied"] is not False or receipt["assurance_claim"] is not False:
        fail(E_ADVISORY, "advisory receipt must not set a control result")
    if receipt["evidence_class"] != EVIDENCE_CLASS:
        fail(E_ADVISORY, "advisory receipt evidence_class must be advisory")
    if receipt["ledger_integrity"] not in _INTEGRITY:
        fail(E_ADVISORY, "ledger_integrity must be verified or unverified")
    if not isinstance(receipt["verdicts"], list):
        fail(E_ADVISORY, "verdicts must be a list")
    for row in receipt["verdicts"]:
        if row.get("disposition") not in {"needs_review", "advisory_observed"}:
            fail(E_ADVISORY, "verdict disposition must be needs_review or advisory_observed")
        if row.get("mapping") not in {"mapped", "unmapped"}:
            fail(E_ADVISORY, "verdict mapping must be mapped or unmapped")
        if row.get("ledger_integrity") not in _INTEGRITY:
            fail(E_ADVISORY, "ledger_integrity must be verified or unverified")
    assert_no_claim_words(receipt)


def _held(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and value.strip() and value == value.strip():
        return value
    fail(E_ADVISORY, "held must be a reason string or null")


def _safe_run_id(run_id: str) -> str:
    if not _RUN_ID_RE.fullmatch(run_id) or run_id == "cicd":
        fail(E_ADVISORY, "run_id is not a safe file name")
    return run_id


def _integrity(value: object) -> str:
    if value not in _INTEGRITY:
        fail(E_ADVISORY, "receipt status must be verified or unverified")
    return str(value)


def _export_date(value: object) -> str:
    if not isinstance(value, str):
        fail(E_ADVISORY, "generated must be a timestamp string")
    match = _DATE_RE.match(value)
    if match is None:
        fail(E_ADVISORY, "generated must start with YYYY-MM-DD")
    return match.group(1)


def _absolute_root(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("/") or ".." in Path(value).parts:
        fail(E_ADVISORY, "export ledger_root must be an absolute path")
    return value.rstrip("/")


def _rebase(export_root: str, ledger_root: Path, recorded: str, *, required: bool) -> Path | None:
    root = export_root.rstrip("/")
    prefix = root + "/"
    if not isinstance(recorded, str) or not recorded.startswith(prefix):
        if required:
            fail(E_ADVISORY, "receipt path is outside the export ledger_root")
        return None
    rel = recorded[len(prefix):]
    try:
        return _relative_file(ledger_root, rel, "receipt path")
    except BeaconError:
        if required:
            raise
        return None


def _relative_file(ledger_root: Path, rel: str, label: str) -> Path:
    if not isinstance(rel, str) or not rel or rel.startswith("/") or "\\" in rel:
        fail(E_ADVISORY, f"{label} must be a relative path")
    parts = Path(rel).parts
    if any(part in {"", ".", ".."} for part in parts):
        fail(E_ADVISORY, f"{label} must stay inside the ledger root")
    base = ledger_root.resolve()
    dest = (base / rel).resolve()
    if not dest.is_relative_to(base):
        fail(E_ADVISORY, f"{label} escapes the ledger root")
    return dest


def _evidence_dest(evidence_root: Path, relpath: str) -> Path:
    if not isinstance(relpath, str) or relpath.startswith("/") or ".." in Path(relpath).parts:
        fail(E_ADVISORY, "advisory output path escapes the evidence directory")
    dest = (evidence_root / relpath).resolve()
    if not dest.is_relative_to(evidence_root):
        fail(E_ADVISORY, "advisory output path escapes the evidence directory")
    return dest


def _last_line_sha(path: Path) -> str:
    data = _read_bytes(path, "ledger head file")
    if not data:
        fail(E_ADVISORY, "ledger head file is empty")
    last = data.rstrip(b"\n").split(b"\n")[-1]
    if not last:
        fail(E_ADVISORY, "ledger head file has no last line")
    return sha256_bytes(last)


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        fail(E_ADVISORY, f"{label} is not JSON: {exc}")
    if not isinstance(data, dict):
        fail(E_ADVISORY, f"{label} must be a JSON object")
    return data


def _read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        fail(E_ADVISORY, f"{label} is not readable: {exc}")


def _file(path: Path, label: str) -> Path:
    if not path.is_file():
        fail(E_ADVISORY, f"{label} is missing")
    return path


def _dir(path: Path) -> Path:
    if not path.is_dir():
        fail(E_ADVISORY, "ledger root is missing")
    return path.resolve()


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        fail(E_ADVISORY, f"{label} must be a non-blank string")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        fail(E_ADVISORY, f"{label} must be 64 lowercase hex characters")
    return value
