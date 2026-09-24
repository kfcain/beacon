"""Offline SCF 2026.3 catalog pin. Live HackIDLE is not the source of truth."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, NoReturn

from beacon.canonical import sha256_bytes
from beacon.config import env
from beacon.errors import E_SCF, fail

PINNED_SCF_VERSION = "2026.3"
PINNED_WORKBOOK_SHA256 = "5a89bf2d3c106a9a87d4b6e3d62dd3e147d0e960d4c07473045a10aa8a7df697"
PINNED_XLSX_NAME = "secure-controls-framework-scf-2026-3.xlsx"
PINNED_COUNTS: dict[str, int] = {
    "total_controls": 1591,
    "total_families": 34,
    "total_crosswalk_frameworks": 270,
    "total_evidence_requests": 422,
    "total_assessment_objectives": 6446,
}
PINNED_QTS_FAMILY = "QTS"
PINNED_QTS_CONTROL_COUNT = 31
# Already declared in PIN.json. Do not invent framework ids.
PINNED_PILLAR_FRAMEWORK_IDS: tuple[str, ...] = (
    "usa-federal-gsa-fedramp-5-high",
    "general-nist-800-53-r5-2",
    "usa-federal-dow-cmmc-2-level-2",
    "general-aicpa-tsc-2017",
)
PINNED_NOT_A_FRAMEWORK_IDS: tuple[str, ...] = ("usa-federal-gsa-fedramp-20x-ksi",)
PINNED_FILE_SHA256: dict[str, str] = {
    "summary.json": "584d0d830913a17c58812dde3a1b6771802fd8c29fdc3f47c9d7297bcf2d00ee",
    "families.json": "ef1291c85660b679006749e12d95d16ac0891f2e2c9c5c2c9934161b5115f0a2",
    "index-meta.json": "1a45e3f70768b7d185b432e595e76901cc1a8f4be8de7e6b46b942454e30adc4",
}
CATALOG_PROVENANCE = "scf-catalog"
# Documented drop-in target already used by examples/echo_platform.py. Not invented.
# 2026.3 GOV-02 is legacy GOV-01 (SCRP). 2026.3 GOV-01 is a new policy control.
CATALOG_SCF_TARGET = "GOV-02"
CATALOG_SCF_FAMILY = "GOV"
REQUIRED_PIN_FILES: tuple[str, ...] = ("PIN.json", "summary.json", "families.json", "index-meta.json")
HASHED_JSON_FILES: tuple[str, ...] = ("summary.json", "families.json", "index-meta.json")
VENDORED_CATALOG_DIR = Path(__file__).resolve().parent / "catalog"

CatalogRootKind = Literal["vendored", "env"]


def _never(value: object) -> NoReturn:
    raise AssertionError(f"unhandled value: {value}")


@dataclass
class CatalogPinResult:
    ok: bool
    catalog_root: Path
    catalog_root_kind: CatalogRootKind
    scf_version: str
    workbook_sha256: str
    workbook_present: bool
    file_sha256: dict[str, str]
    expected_file_sha256: dict[str, str]
    counts: dict[str, int]
    family_codes: list[str]
    qts_control_count: int
    errors: list[str] = field(default_factory=list)
    provenance: str = CATALOG_PROVENANCE

    def scf_binding(self) -> dict[str, Any]:
        """Align with PR #5 seal fields. Catalog evidence is not a control hop map."""
        pinned = self.ok and self.scf_version == PINNED_SCF_VERSION
        return {
            "scf_version": self.scf_version if pinned else "unpinned",
            "scf_id": CATALOG_SCF_TARGET if pinned else "",
            "scf_ids": [CATALOG_SCF_TARGET] if pinned else [],
            "scf_family": CATALOG_SCF_FAMILY if pinned else "",
            "erl_ids": [],
            "framework_hops": [],
            "pinned": pinned,
            "provenance": CATALOG_PROVENANCE,
        }


def vendored_catalog_dir() -> Path:
    return VENDORED_CATALOG_DIR.resolve()


def resolve_catalog_root(explicit: str | Path | None = None) -> tuple[Path, CatalogRootKind]:
    raw = explicit if explicit is not None else env("SCF_CATALOG_PATH")
    if raw:
        path = Path(str(raw)).expanduser()
        if path.is_file():
            path = path.parent
        return path.resolve(), "env"
    return vendored_catalog_dir(), "vendored"


def _read_json_object(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _as_str(value: object) -> str:
    return str(value).strip() if value is not None else ""


def _is_sha256_hex(value: str) -> bool:
    if len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value.lower())


def _family_rows(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _framework_ids(value: object) -> list[str] | None:
    """Return catalog framework ids, or None when the list is absent."""
    if not isinstance(value, list):
        return None
    ids: list[str] = []
    for item in value:
        if isinstance(item, str):
            ids.append(item.strip())
            continue
        if isinstance(item, dict):
            raw = item.get("framework_id")
            ids.append(raw.strip() if isinstance(raw, str) else "")
            continue
        ids.append("")
    return ids


def _count_from(data: dict[str, Any], key: str, *, list_key: str | None = None) -> int | None:
    listed = data.get(list_key) if list_key else None
    if isinstance(listed, list):
        return len(listed)
    return _as_int(data.get(key))


def _find_file(root: Path, name: str, extra: tuple[Path, ...] = ()) -> Path | None:
    candidates = (root / name, *extra)
    for path in candidates:
        if path.is_file():
            return path
    return None


def _summary_path(root: Path) -> Path | None:
    return _find_file(
        root,
        "summary.json",
        extra=(root / "api" / "summary.json", root / "raw" / "api" / "summary.json"),
    )


def inspect_catalog_pin(explicit: str | Path | None = None) -> CatalogPinResult:
    """Verify the offline 2026.3 pin. Does not call live HackIDLE."""
    root, kind = resolve_catalog_root(explicit)
    errors: list[str] = []
    if kind not in ("vendored", "env"):
        _never(kind)

    if not root.is_dir():
        errors.append(f"catalog root is missing: {root}")
        return CatalogPinResult(
            ok=False,
            catalog_root=root,
            catalog_root_kind=kind,
            scf_version="",
            workbook_sha256="",
            workbook_present=False,
            file_sha256={},
            expected_file_sha256={},
            counts={},
            family_codes=[],
            qts_control_count=0,
            errors=errors,
        )

    pin_path = _find_file(root, "PIN.json")
    summary_path = _summary_path(root)
    pin_dir = summary_path.parent if summary_path is not None else root
    families_path = _find_file(pin_dir, "families.json", extra=(root / "families.json",))
    meta_path = _find_file(pin_dir, "index-meta.json", extra=(root / "index-meta.json",))

    for required in REQUIRED_PIN_FILES:
        present = {
            "PIN.json": pin_path,
            "summary.json": summary_path,
            "families.json": families_path,
            "index-meta.json": meta_path,
        }[required]
        if present is None:
            errors.append(f"required file missing: {required}")

    pin = _read_json_object(pin_path) if pin_path is not None else None
    summary = _read_json_object(summary_path) if summary_path is not None else None
    families_doc = _read_json_object(families_path) if families_path is not None else None
    meta = _read_json_object(meta_path) if meta_path is not None else None
    if pin_path is not None and pin is None:
        errors.append("PIN.json is not a JSON object")
    if summary_path is not None and summary is None:
        errors.append("summary.json is not a JSON object")
    if families_path is not None and families_doc is None:
        errors.append("families.json is not a JSON object")
    if meta_path is not None and meta is None:
        errors.append("index-meta.json is not a JSON object")

    pin = pin or {}
    summary = summary or {}
    families_doc = families_doc or {}
    meta = meta or {}

    scf_version = _as_str(summary.get("scf_version") or pin.get("scf_version") or meta.get("scf_version"))
    if scf_version != PINNED_SCF_VERSION:
        errors.append(f"scf_version {scf_version!r} is not pinned {PINNED_SCF_VERSION}")

    pin_version = _as_str(pin.get("scf_version"))
    if pin and pin_version != PINNED_SCF_VERSION:
        errors.append(f"PIN.json scf_version {pin_version!r} is not pinned {PINNED_SCF_VERSION}")

    workbook_sha = _as_str(pin.get("xlsx_sha256")).lower()
    meta_workbook = meta.get("workbook") if isinstance(meta.get("workbook"), dict) else {}
    meta_sha = _as_str(meta_workbook.get("sha256")).lower()
    if not _is_sha256_hex(workbook_sha):
        errors.append("PIN.json xlsx_sha256 is missing")
        declared_sha = workbook_sha
    elif workbook_sha != PINNED_WORKBOOK_SHA256:
        errors.append("PIN.json workbook SHA-256 does not match the 2026.3 pin")
        declared_sha = workbook_sha
    else:
        declared_sha = workbook_sha
    if meta_sha:
        if meta_sha != PINNED_WORKBOOK_SHA256:
            errors.append("index-meta.json workbook SHA-256 does not match the 2026.3 pin")

    if families_path is not None:
        family_rows = _family_rows(families_doc.get("families"))
        if not family_rows:
            errors.append("families.json families list is missing")
    else:
        family_rows = []
    family_codes = [_as_str(row.get("family_code")).upper() for row in family_rows if _as_str(row.get("family_code"))]
    meta_codes = meta.get("family_codes")
    if isinstance(meta_codes, list) and meta_codes:
        meta_set = {_as_str(item).upper() for item in meta_codes if _as_str(item)}
        if family_codes and meta_set != set(family_codes):
            errors.append("index-meta.json family_codes does not match families.json")

    qts_count: int | None = None
    for row in family_rows:
        if _as_str(row.get("family_code")).upper() == PINNED_QTS_FAMILY:
            qts_count = _as_int(row.get("control_count"))
            break
    if PINNED_QTS_FAMILY not in family_codes:
        errors.append("family QTS is missing from the catalog pin")
    if qts_count is None:
        errors.append("QTS control_count is missing from families.json")
        qts_count = 0
    elif qts_count != PINNED_QTS_CONTROL_COUNT:
        errors.append(f"QTS control_count {qts_count} is not {PINNED_QTS_CONTROL_COUNT}")
    if len(set(family_codes)) != PINNED_COUNTS["total_families"]:
        errors.append(
            f"family count {len(set(family_codes))} is not {PINNED_COUNTS['total_families']}"
        )

    counts: dict[str, int] = {}
    count_sources: tuple[tuple[str, dict[str, Any], str | None], ...] = (
        ("total_controls", summary, None),
        ("total_families", summary, "families"),
        ("total_crosswalk_frameworks", summary, "crosswalk_frameworks"),
        ("total_evidence_requests", summary, None),
        ("total_assessment_objectives", summary, None),
    )
    for key, source, list_key in count_sources:
        listed = source.get(list_key) if list_key else None
        declared = _as_int(source.get(key))
        if isinstance(listed, list) and declared is not None and declared != len(listed):
            errors.append(f"{key} {declared} does not match list length {len(listed)}")
        got = _count_from(source, key, list_key=list_key)
        if got is None:
            errors.append(f"count {key} is missing from summary.json")
            continue
        counts[key] = got
        expected = PINNED_COUNTS[key]
        if got != expected:
            errors.append(f"count {key}={got} is not pinned {expected}")
        pin_count = _as_int(pin.get(key))
        if pin_count is not None and pin_count != expected:
            errors.append(f"PIN.json {key}={pin_count} is not pinned {expected}")

    framework_ids = _framework_ids(summary.get("crosswalk_frameworks"))
    if framework_ids is None:
        errors.append("summary.json crosswalk_frameworks list is missing")
        framework_ids = []
    elif not framework_ids:
        errors.append("summary.json crosswalk_frameworks list is missing")
    else:
        if any(not item for item in framework_ids):
            errors.append("summary.json crosswalk_frameworks has an empty framework_id")
        if len(framework_ids) != len(set(framework_ids)):
            errors.append("summary.json crosswalk_frameworks has duplicate framework_id values")
        have = {item.lower() for item in framework_ids if item}
        blocked = {item.lower() for item in PINNED_NOT_A_FRAMEWORK_IDS}
        extra_blocked = pin.get("not_a_framework_id")
        if isinstance(extra_blocked, list):
            blocked.update(_as_str(item).lower() for item in extra_blocked if _as_str(item))
        if blocked.intersection(have):
            errors.append(
                "summary.json crosswalk_frameworks includes a documented non-framework id"
            )
        for pillar in PINNED_PILLAR_FRAMEWORK_IDS:
            if pillar.lower() not in have:
                errors.append(f"summary.json crosswalk_frameworks is missing pillar {pillar}")

    if family_rows:
        family_sum = 0
        for row in family_rows:
            count = _as_int(row.get("control_count"))
            if count is None:
                code = _as_str(row.get("family_code")) or "?"
                errors.append(f"family {code} control_count is missing")
                continue
            family_sum += count
        if family_sum != PINNED_COUNTS["total_controls"]:
            errors.append(
                f"sum of family control_count {family_sum} is not {PINNED_COUNTS['total_controls']}"
            )

    expected_hashes: dict[str, str] = {}
    raw_hashes = pin.get("file_sha256")
    if not isinstance(raw_hashes, dict) or not raw_hashes:
        errors.append("PIN.json file_sha256 is missing")
    else:
        for name in HASHED_JSON_FILES:
            digest = _as_str(raw_hashes.get(name)).lower()
            if not _is_sha256_hex(digest):
                errors.append(f"PIN.json file_sha256 is missing {name}")
                continue
            expected_hashes[name] = digest

    measured: dict[str, str] = {}
    named_files: dict[str, Path | None] = {
        "summary.json": summary_path,
        "families.json": families_path,
        "index-meta.json": meta_path,
    }
    for name in HASHED_JSON_FILES:
        path = named_files[name]
        if path is None or not path.is_file():
            if name in expected_hashes:
                errors.append(f"PIN.json hashes {name} but the file is missing")
            continue
        digest = sha256_bytes(path.read_bytes())
        measured[name] = digest
        expected = expected_hashes.get(name, "")
        if expected and expected != digest:
            errors.append(f"SHA-256 mismatch for {name}")
        if kind == "vendored":
            pinned_digest = PINNED_FILE_SHA256[name]
            if digest != pinned_digest:
                errors.append(f"vendored SHA-256 mismatch for {name}")
            if expected and expected != pinned_digest:
                errors.append(f"PIN.json file_sha256 for {name} is not the vendored pin")
        elif kind == "env":
            pass
        else:
            _never(kind)

    workbook_path = _find_file(
        pin_dir,
        PINNED_XLSX_NAME,
        extra=(
            root / PINNED_XLSX_NAME,
            root / "official" / PINNED_XLSX_NAME,
            root / "raw" / "official" / PINNED_XLSX_NAME,
        ),
    )
    workbook_present = workbook_path is not None
    if workbook_present:
        xlsx_digest = sha256_bytes(workbook_path.read_bytes())
        if xlsx_digest != PINNED_WORKBOOK_SHA256:
            errors.append("workbook SHA-256 does not match the 2026.3 pin")

    return CatalogPinResult(
        ok=not errors,
        catalog_root=root,
        catalog_root_kind=kind,
        scf_version=scf_version,
        workbook_sha256=declared_sha,
        workbook_present=workbook_present,
        file_sha256=measured,
        expected_file_sha256=expected_hashes,
        counts=counts,
        family_codes=family_codes,
        qts_control_count=qts_count,
        errors=errors,
    )


def verify_catalog_pin(explicit: str | Path | None = None) -> CatalogPinResult:
    result = inspect_catalog_pin(explicit)
    if not result.ok:
        fail(E_SCF, "; ".join(result.errors) or "SCF catalog pin failed")
    return result
