"""Build a Perch Gate receipt. This module does not seal and does not call Perch."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from beacon.errors import E_PERCH, fail
from beacon.scf.objective_catalog import objectives

SCHEMA_VERSION = 0
CLAIM_STATUS = "unverified"
KIND = "perch_gate"
MAP_PATH = Path("perch-gate/maps/terraform-v0.json")
RULES_DIR = Path(".perch/rules")
PERCH_YAML = Path("perch.yaml")
COMMENT_FIELDS = ("scf_id", "ao_id", "legacy_control_ref", "ppt", "origins")
# Keys perch src/ask.js accepts. A rule file that adds scf_id as a key fails to parse.
ALLOWED_RULE_KEYS = frozenset(
    {
        "name",
        "disabled",
        "min",
        "gate",
        "type",
        "each",
        "where",
        "except",
        "sees",
        "ask",
        "true",
        "false",
        "options",
        "levels",
        "when",
        "issue",
        "ensure",
        "ensure_present",
        "ensure_absent",
    }
)
CLAIM_WORDS = frozenset({"compliant", "evidenced", "proven"})
_RULE_KEY = re.compile(r"^  ([A-Za-z0-9_]+):")
_NAME = re.compile(r"^- name:\s*(\S+)\s*$")
_BEACON = re.compile(r"^# beacon\.([A-Za-z0-9_]+):\s*(.*)$")
_ROOT_RULE = re.compile(r"^\s*- name:\s*\S+")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _sha256_files(root: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        rel = path.relative_to(root).as_posix().encode()
        digest.update(rel)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def rule_paths(root: Path) -> list[Path]:
    """Rule files in the order Perch reads them: perch.yaml, then .perch/rules in path order."""
    perch = root / PERCH_YAML
    if not perch.is_file():
        fail(E_PERCH, "perch.yaml is missing")
    rules_root = root / RULES_DIR
    found: list[Path] = []
    if rules_root.is_dir():
        for path in rules_root.rglob("*"):
            if path.is_file() and path.suffix in {".yaml", ".yml"}:
                found.append(path)
    found.sort(key=lambda path: path.relative_to(root).as_posix())
    return [perch, *found]


def ruleset_files(root: Path) -> list[Path]:
    files = [*rule_paths(root), root / MAP_PATH]
    missing = [str(path.relative_to(root)) for path in files if not path.is_file()]
    if missing:
        fail(E_PERCH, "ruleset file missing: " + ", ".join(missing))
    return files


def ruleset_sha256(root: Path) -> str:
    return _sha256_files(root, ruleset_files(root))


def load_ao_map(root: Path) -> dict[str, Any]:
    path = root / MAP_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(E_PERCH, f"AO map is not JSON: {exc}")
    if data.get("schema_version") != 0 or not isinstance(data.get("rules"), list):
        fail(E_PERCH, "AO map schema_version must be 0 and rules must be a list")
    return data


def parse_rule_file(text: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Return Perch keys and Beacon comment maps for each rule, in file order."""
    rules: list[dict[str, str]] = []
    maps: list[dict[str, str]] = []
    pending: dict[str, str] = {}
    current_keys: dict[str, str] | None = None
    for line in text.splitlines():
        comment = _BEACON.match(line)
        if comment:
            # A comment after a finished rule belongs to the next rule.
            current_keys = None
            field = comment.group(1)
            if field in pending:
                fail(E_PERCH, f"beacon.{field} is set twice on one rule")
            pending[field] = comment.group(2).strip()
            continue
        name = _NAME.match(line)
        if name:
            current_keys = {"name": name.group(1)}
            rules.append(current_keys)
            maps.append(pending)
            pending = {}
            continue
        key = _RULE_KEY.match(line)
        if key:
            if current_keys is None:
                fail(E_PERCH, f"rule key {key.group(1)} has no rule name")
            field = key.group(1)
            if field not in ALLOWED_RULE_KEYS:
                fail(E_PERCH, f"{field} is not a Perch rule key")
            current_keys[field] = line.split(":", 1)[1].strip()
    if pending:
        fail(E_PERCH, "beacon comment is not attached to a rule")
    return rules, maps


def _row_for(ao_id: str) -> dict[str, Any]:
    control_ref = ao_id.split("_", 1)[0]
    for row in objectives(control_ref):
        if row["ao_id"] == ao_id:
            return row
    fail(E_PERCH, f"{ao_id} is not in the pinned objective rows")


def _offline_control_path(root: Path, scf_id: str, control_json: str) -> Path:
    expected = f"beacon/scf/offline/{scf_id}.json"
    if control_json != expected or control_json.startswith("/") or ".." in control_json.split("/"):
        fail(E_PERCH, f"control JSON must be {expected}")
    path = (root / expected).resolve()
    if not path.is_relative_to(root.resolve()):
        fail(E_PERCH, f"control JSON must stay inside the repository: {expected}")
    if not path.is_file():
        fail(E_PERCH, f"offline control JSON is missing: {expected}")
    return path


def _check_hops(root: Path, rule: dict[str, Any]) -> None:
    hops = rule.get("framework_hops")
    control_json = rule.get("control_json")
    if hops is None:
        return
    if not isinstance(control_json, str) or not control_json:
        fail(E_PERCH, f"{rule['name']} has framework hops and no offline control JSON")
    path = _offline_control_path(root, str(rule["scf_id"]), control_json)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(E_PERCH, f"offline control JSON is not readable: {exc}")
    if payload.get("control_id") != rule["scf_id"]:
        fail(E_PERCH, f"{control_json} control_id does not match {rule['scf_id']}")
    crosswalks = payload.get("crosswalks")
    if not isinstance(crosswalks, dict) or not isinstance(hops, dict):
        fail(E_PERCH, f"{rule['name']} framework hops are not a map")
    for framework_id, values in hops.items():
        known = crosswalks.get(framework_id)
        if not isinstance(known, list) or not isinstance(values, list):
            fail(E_PERCH, f"{framework_id} is not a crosswalk on {rule['scf_id']}")
        for value in values:
            if value not in known:
                fail(E_PERCH, f"{value} is not listed under {framework_id} for {rule['scf_id']}")


def verify_pack(root: Path | None = None) -> dict[str, Any]:
    """Fail closed when a rule id is not in the pinned rows or the files disagree."""
    base = root if root is not None else repo_root()
    ao_map = load_ao_map(base)
    if ao_map.get("scf_pin") != "2026.3":
        fail(E_PERCH, "AO map scf_pin must be 2026.3")
    by_name: dict[str, dict[str, Any]] = {}
    for rule in ao_map["rules"]:
        name = rule.get("name")
        if not isinstance(name, str) or name in by_name:
            fail(E_PERCH, "each AO map rule needs one unique name")
        scf_id = rule.get("scf_id")
        if not isinstance(scf_id, str) or not scf_id:
            fail(E_PERCH, f"{name} needs a real scf_id")
        ao_id = rule.get("ao_id")
        if ao_id is not None:
            if not isinstance(ao_id, str) or not ao_id.startswith(scf_id + "_"):
                fail(E_PERCH, f"{name} ao_id does not belong to {scf_id}")
            row = _row_for(ao_id)
            if row["control_ref"] != scf_id or row["ppt"] != rule.get("ppt"):
                fail(E_PERCH, f"{name} ppt or control_ref does not match the objective row")
            if row["origins"] != rule.get("origins"):
                fail(E_PERCH, f"{name} origins does not match the objective row")
            legacy = row.get("legacy_control_ref")
            if legacy in (None, "", "NONE"):
                if "legacy_control_ref" in rule:
                    fail(E_PERCH, f"{name} has no legacy id in the objective row")
            elif rule.get("legacy_control_ref") != legacy:
                fail(E_PERCH, f"{name} legacy_control_ref does not match the objective row")
        elif "ao_id" in rule:
            fail(E_PERCH, f"{name} ao_id is empty")
        control_json = rule.get("control_json")
        if control_json is not None:
            if not isinstance(control_json, str):
                fail(E_PERCH, f"{name} control_json must be a path")
            offline = _offline_control_path(base, scf_id, control_json)
            try:
                payload = json.loads(offline.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                fail(E_PERCH, f"offline control JSON is not readable: {exc}")
            if payload.get("control_id") != scf_id:
                fail(E_PERCH, f"{name} control_json is a different control")
        _check_hops(base, rule)
        by_name[name] = rule

    in_force = merge_rule_texts(_rule_texts(base))
    if [keys["name"] for keys, _comment in in_force] != [rule["name"] for rule in ao_map["rules"]]:
        fail(E_PERCH, "rule file order and AO map order differ")
    for keys, comment in in_force:
        name = keys["name"]
        mapped = by_name.get(name)
        if mapped is None:
            fail(E_PERCH, f"{name} has no AO map entry")
        _check_rule_shape(name, keys)
        for field in COMMENT_FIELDS:
            left = comment.get(field)
            right = mapped.get(field)
            if right is None:
                if left is not None:
                    fail(E_PERCH, f"{name} comment {field} is not in the AO map")
                continue
            if left != right:
                fail(E_PERCH, f"{name} comment {field} does not match the AO map")
    return ao_map


def _rule_texts(root: Path) -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = []
    for path in rule_paths(root):
        text = path.read_text(encoding="utf-8")
        if path.name == PERCH_YAML.name and path.parent == root:
            for line in text.splitlines():
                if _ROOT_RULE.match(line):
                    fail(E_PERCH, "put rules in .perch/rules so the AO map covers every rule")
            continue
        texts.append((path.relative_to(root).as_posix(), text))
    return texts


def merge_rule_texts(files: list[tuple[str, str]]) -> list[tuple[dict[str, str], dict[str, str]]]:
    """Last file in Perch's path order wins when two rules share a name."""
    by_name: dict[str, tuple[dict[str, str], dict[str, str]]] = {}
    order: list[str] = []
    for _path, text in files:
        parsed, comments = parse_rule_file(text)
        for keys, comment in zip(parsed, comments, strict=True):
            name = keys["name"]
            if name not in by_name:
                order.append(name)
            by_name[name] = (keys, comment)
    return [by_name[name] for name in order]


def _check_rule_shape(name: str, keys: dict[str, str]) -> None:
    if "disabled" in keys:
        fail(E_PERCH, f"{name} is disabled")
    if "except" in keys:
        fail(E_PERCH, f"{name} has except")
    if keys.get("each") != "file":
        fail(E_PERCH, f"{name} each must be file")
    if keys.get("min") != "70":
        fail(E_PERCH, f"{name} min must be 70")
    if keys.get("gate") != "true":
        fail(E_PERCH, f"{name} gate must be true")
    where = keys.get("where", "").strip().strip("'").strip('"')
    if where != "**/*.tf":
        fail(E_PERCH, f"{name} where must be **/*.tf")
    if "ensure" not in keys and "ensure_present" not in keys and "ensure_absent" not in keys:
        fail(E_PERCH, f"{name} needs an ensure sentence")


def _scope_pair(scope_id: str | None, scope_sha256: str | None) -> tuple[str | None, str | None]:
    if scope_id is None and scope_sha256 is None:
        return None, None
    if not scope_id or not scope_sha256 or not re.fullmatch(r"[0-9a-f]{64}", scope_sha256):
        fail(E_PERCH, "scope_id and scope_sha256 must both be present")
    return scope_id, scope_sha256


def _rule_name(issue: dict[str, Any]) -> str | None:
    rule = issue.get("rule")
    if isinstance(rule, str) and rule:
        return rule
    lint = issue.get("lint")
    if isinstance(lint, dict) and isinstance(lint.get("rule"), str) and lint["rule"]:
        return lint["rule"]
    source = issue.get("from")
    if isinstance(source, str) and source:
        return source
    return None


def _issues_from_scan(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        fail(E_PERCH, "scan JSON needs a run object and an issues list")
    run = payload.get("run")
    if not isinstance(run, dict) or run.get("status") != "complete":
        fail(E_PERCH, "scan run status must be complete")
    incomplete = run.get("incomplete") or []
    if incomplete:
        fail(E_PERCH, "scan run has incomplete checks")
    raw = payload.get("issues", payload.get("findings"))
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        fail(E_PERCH, "scan JSON needs an issues list")
    return raw


def _ao_hits(ao_map: dict[str, Any], issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name = {rule["name"]: rule for rule in ao_map["rules"]}
    grouped: dict[tuple[str, str | None], list[str]] = {}
    order: list[tuple[str, str | None]] = []
    for issue in issues:
        name = _rule_name(issue)
        if name is None:
            fail(E_PERCH, "scan issue has no rule name")
        mapped = by_name.get(name)
        if mapped is None:
            fail(E_PERCH, f"scan issue names unknown rule {name}")
        issue_id = issue.get("id")
        if not isinstance(issue_id, str) or not issue_id:
            fail(E_PERCH, f"scan issue for {name} has no id")
        key = (mapped["scf_id"], mapped.get("ao_id"))
        if key not in grouped:
            order.append(key)
            grouped[key] = []
        grouped[key].append(issue_id)
    hits: list[dict[str, Any]] = []
    for scf_id, ao_id in order:
        hit: dict[str, Any] = {"scf_id": scf_id, "issue_ids": grouped[(scf_id, ao_id)]}
        if ao_id:
            hit["ao_id"] = ao_id
        hits.append(hit)
    return hits


def build_receipt(
    *,
    root: Path | None = None,
    repo: str,
    commit_sha: str,
    perch_version: str,
    exit_code: int,
    issues: list[dict[str, Any]] | None = None,
    live_api: bool = False,
    scope_id: str | None = None,
    scope_sha256: str | None = None,
) -> dict[str, Any]:
    """Return a receipt. claim_status stays unverified. sealed stays false."""
    if not repo or not commit_sha or not perch_version:
        fail(E_PERCH, "repo, commit_sha, and perch_version are required")
    if live_api and perch_version in {"not-run", "unknown"}:
        fail(E_PERCH, "a live scan needs the Perch version string")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code < 0:
        fail(E_PERCH, "exit_code must be an integer from 0")
    base = root if root is not None else repo_root()
    ao_map = verify_pack(base)
    found = issues or []
    if found and exit_code == 0:
        fail(E_PERCH, "scan JSON lists problems and exit code is 0")
    scope = _scope_pair(scope_id, scope_sha256)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "repo": repo,
        "commit_sha": commit_sha,
        "ruleset_sha256": ruleset_sha256(base),
        "perch_version": perch_version,
        "exit_code": exit_code,
        "problem_count": len(found),
        "failing": exit_code != 0,
        "ao_hits": _ao_hits(ao_map, found),
        "scope_id": scope[0],
        "scope_sha256": scope[1],
        "claim_status": CLAIM_STATUS,
        "sealed": False,
        "live_api": live_api,
    }
    validate_receipt(receipt)
    return receipt


def build_mock_receipt(root: Path | None = None) -> dict[str, Any]:
    """A local receipt. live_api is false. The status word is unverified."""
    return build_receipt(
        root=root,
        repo="mock/beacon",
        commit_sha="mock",
        perch_version="not-run",
        exit_code=0,
        issues=[],
        live_api=False,
    )


def build_scan_receipt(
    scan_path: Path,
    *,
    root: Path | None = None,
    repo: str,
    commit_sha: str,
    perch_version: str,
    exit_code: int,
    live_api: bool,
    scope_id: str | None = None,
    scope_sha256: str | None = None,
) -> dict[str, Any]:
    try:
        payload = json.loads(scan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(E_PERCH, f"scan JSON is not readable: {exc}")
    return build_receipt(
        root=root,
        repo=repo,
        commit_sha=commit_sha,
        perch_version=perch_version,
        exit_code=exit_code,
        issues=_issues_from_scan(payload),
        live_api=live_api,
        scope_id=scope_id,
        scope_sha256=scope_sha256,
    )


def validate_receipt(receipt: dict[str, Any]) -> None:
    """Reject a claim word. A v0 receipt stays unverified and unsealed."""
    required = {
        "schema_version",
        "kind",
        "repo",
        "commit_sha",
        "ruleset_sha256",
        "perch_version",
        "exit_code",
        "problem_count",
        "failing",
        "ao_hits",
        "scope_id",
        "scope_sha256",
        "claim_status",
        "sealed",
        "live_api",
    }
    extra = set(receipt) - required
    missing = required - set(receipt)
    if extra or missing:
        fail(E_PERCH, "receipt fields do not match the v0 schema")
    if receipt["schema_version"] != 0 or receipt["kind"] != KIND:
        fail(E_PERCH, "receipt kind must be perch_gate schema 0")
    if receipt["claim_status"] != CLAIM_STATUS or receipt["sealed"] is not False:
        fail(E_PERCH, "v0 receipt status is unverified and sealed is false")
    if any(word in CLAIM_WORDS for word in receipt.values() if isinstance(word, str)):
        fail(E_PERCH, "v0 receipt uses the status word unverified")
    if not re.fullmatch(r"[0-9a-f]{64}", str(receipt["ruleset_sha256"])):
        fail(E_PERCH, "ruleset_sha256 must be 64 hex characters")
    if not isinstance(receipt["problem_count"], int) or receipt["problem_count"] < 0:
        fail(E_PERCH, "problem_count must be an integer from 0")
    if receipt["problem_count"] > 0 and receipt["failing"] is not True:
        fail(E_PERCH, "a receipt with problems has failing true")
    if receipt["exit_code"] != 0 and receipt["failing"] is not True:
        fail(E_PERCH, "a non-zero exit has failing true")
    if not isinstance(receipt["live_api"], bool):
        fail(E_PERCH, "live_api must be true or false")
    if not isinstance(receipt["ao_hits"], list):
        fail(E_PERCH, "ao_hits must be a list")
    for hit in receipt["ao_hits"]:
        if not isinstance(hit, dict):
            fail(E_PERCH, "each ao hit must be an object")
        allowed = {"scf_id", "ao_id", "issue_ids"}
        if set(hit) - allowed or "scf_id" not in hit or "issue_ids" not in hit:
            fail(E_PERCH, "an ao hit needs scf_id and issue_ids")
        if not isinstance(hit["issue_ids"], list) or any(not isinstance(item, str) or not item for item in hit["issue_ids"]):
            fail(E_PERCH, "issue_ids must be non-empty strings")
    scope_id = receipt["scope_id"]
    scope_sha = receipt["scope_sha256"]
    if scope_id is None or scope_sha is None:
        if scope_id is not None or scope_sha is not None:
            fail(E_PERCH, "scope_id and scope_sha256 must both be present")
    elif not isinstance(scope_id, str) or not re.fullmatch(r"[0-9a-f]{64}", str(scope_sha)):
        fail(E_PERCH, "scope_sha256 must be 64 hex characters")


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a Perch Gate receipt. This command does not seal.")
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--scan", type=Path, default=None)
    parser.add_argument("--exit-code", type=int, default=None)
    parser.add_argument("--repo", default=None)
    parser.add_argument("--commit", default=None)
    parser.add_argument("--perch-version", default=None)
    parser.add_argument("--scope", dest="scope_id", default=None)
    parser.add_argument("--scope-sha256", default=None)
    parser.add_argument("--live-api", action="store_true")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        if args.mock and args.scan is not None:
            fail(E_PERCH, "use --mock or --scan")
        if args.mock:
            if args.live_api:
                fail(E_PERCH, "a mock receipt has live_api false")
            receipt = build_mock_receipt(args.root)
        else:
            if args.exit_code is None or not args.repo or not args.commit or not args.perch_version:
                fail(E_PERCH, "a scan receipt needs --repo, --commit, --perch-version, and --exit-code")
            if args.scan is None:
                receipt = build_receipt(
                    root=args.root,
                    repo=args.repo,
                    commit_sha=args.commit,
                    perch_version=args.perch_version,
                    exit_code=args.exit_code,
                    issues=[],
                    live_api=args.live_api,
                    scope_id=args.scope_id,
                    scope_sha256=args.scope_sha256,
                )
            else:
                receipt = build_scan_receipt(
                    args.scan,
                    root=args.root,
                    repo=args.repo,
                    commit_sha=args.commit,
                    perch_version=args.perch_version,
                    exit_code=args.exit_code,
                    live_api=args.live_api,
                    scope_id=args.scope_id,
                    scope_sha256=args.scope_sha256,
                )
    except Exception as exc:
        code = getattr(exc, "code", "E_PERCH")
        print(f"{code}: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(receipt, indent=2) + "\n"
    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
