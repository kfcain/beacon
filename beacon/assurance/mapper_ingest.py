"""Register grc-pdf-mapper JSON as a candidate. This module does not read a PDF.

Known shapes are a mapping report, a KSI catalog, and policy-code links.
An unknown or ambiguous shape fails closed. The candidate has no claim word.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, NoReturn

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from beacon.canonical import dumps, sha256_bytes, sha256_obj
from beacon.crypto.witness import CHAIN_VERSION
from beacon.errors import E_MAPPER, fail
from beacon.scope.document import SCOPE_ID_RE, SHA256_RE

SCHEMA_VERSION = 1
MapperShape = Literal["mapping_report", "ksi_catalog", "policy_code_links"]
CLAIM_MARKERS = ("compliant", "evidenced", "proven", "Implemented", " met", '"met"')


def _mapper_fail(message: str) -> NoReturn:
    fail(E_MAPPER, message)


def assert_no_claim_words(body: object) -> None:
    """Refuse a candidate whose JSON contains a claim word."""
    text = json.dumps(body)
    for word in CLAIM_MARKERS:
        if word in text:
            _mapper_fail("candidate must not contain a claim word")


class PolicyDraft(BaseModel):
    """Empty people, process, and technology draft. A human commit fills the git file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = SCHEMA_VERSION
    policy_id: str
    title: str
    people: tuple[dict[str, str], ...] = ()
    process: tuple[dict[str, str], ...] = ()
    technology: tuple[dict[str, str], ...] = ()
    control_refs: tuple[str, ...] = ()
    statement_ids: tuple[str, ...] = ()
    role: Literal["candidate"] = "candidate"

    @field_validator("policy_id")
    @classmethod
    def policy_id_is_safe(cls, value: str) -> str:
        if not SCOPE_ID_RE.fullmatch(value):
            raise ValueError("policy_id must match the safe id pattern")
        return value


class MapperCandidate(BaseModel):
    """Custody pointer for one mapper file. role stays candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = SCHEMA_VERSION
    role: Literal["candidate"] = "candidate"
    shape: MapperShape
    input_path: str
    input_sha256: str
    tag: Literal["evidence:policy"] = "evidence:policy"
    legacy_bytes_are_source_of_truth: Literal[False] = False
    awaiting_human_commit: Literal[True] = True
    doc_id: str | None = None
    snapshot_id: str | None = None
    ingest_source_hash: str | None = None
    statement_ids: tuple[str, ...] = ()
    mapper_control_labels: tuple[str, ...] = ()
    mapper_indicator_ids: tuple[str, ...] = ()
    link_ids: tuple[str, ...] = ()
    policy_draft: PolicyDraft | None = None
    policy_draft_sha256: str | None = None
    claim: None = None
    record_v: Literal[1] = CHAIN_VERSION

    @field_validator("input_sha256")
    @classmethod
    def input_hash_is_sha256(cls, value: str) -> str:
        if not SHA256_RE.fullmatch(value):
            raise ValueError("input_sha256 must be 64 lowercase hex characters")
        return value


def _nonblank(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        _mapper_fail(f"{label} must be a non-blank string")
    return value


def _sha256(value: object, label: str) -> str:
    text = _nonblank(value, label)
    if not SHA256_RE.fullmatch(text):
        _mapper_fail(f"{label} must be 64 lowercase hex characters")
    return text


def _optional_sha256(value: object, label: str) -> str | None:
    if value is None or value == "":
        return None
    return _sha256(value, label)


def _safe_id(value: object, label: str) -> str:
    text = _nonblank(value, label)
    if not SCOPE_ID_RE.fullmatch(text):
        _mapper_fail(f"{label} must match the safe id pattern")
    return text


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _mapper_fail(f"{label} must be an object")
    return value


def _never_shape(shape: MapperShape) -> NoReturn:
    raise AssertionError(f"unhandled mapper shape: {shape!r}")


def _classify(data: dict[str, Any]) -> MapperShape:
    report = "ingest" in data or ("doc_id" in data and "snapshot_id" in data)
    ksi = "domains" in data or "classes" in data
    links = "links" in data
    matches: list[MapperShape] = []
    if report:
        matches.append("mapping_report")
    if ksi:
        matches.append("ksi_catalog")
    if links:
        matches.append("policy_code_links")
    if len(matches) != 1:
        _mapper_fail("mapper shape is unknown or ambiguous")
    return matches[0]


def _labels(values: list[str]) -> tuple[str, ...]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in values:
        if item in seen:
            continue
        seen.add(item)
        cleaned.append(item)
    return tuple(cleaned)


def _parse_report(data: dict[str, Any], input_path: str, input_sha256: str) -> MapperCandidate:
    doc_id = _safe_id(data.get("doc_id"), "doc_id")
    snapshot_id = _safe_id(data.get("snapshot_id"), "snapshot_id")
    ingest = _object(data.get("ingest"), "ingest")
    _nonblank(ingest.get("source_path"), "ingest.source_path")
    _nonblank(ingest.get("markdown"), "ingest.markdown")
    source_hash = _sha256(ingest.get("source_hash"), "ingest.source_hash")
    raw_statements = data.get("statements", [])
    if not isinstance(raw_statements, list):
        _mapper_fail("statements must be a list")
    statement_ids: list[str] = []
    labels: list[str] = []
    for index, row in enumerate(raw_statements):
        statement_row = _object(row, f"statements[{index}]")
        statement = _object(statement_row.get("statement"), f"statements[{index}].statement")
        statement_ids.append(_safe_id(statement.get("statement_id"), "statement_id"))
        _nonblank(statement.get("text"), "statement.text")
        _optional_sha256(statement.get("content_hash"), "statement.content_hash")
        mappings = statement_row.get("mappings", [])
        if not isinstance(mappings, list):
            _mapper_fail("mappings must be a list")
        for map_index, hit in enumerate(mappings):
            mapping = _object(hit, f"mappings[{map_index}]")
            _nonblank(mapping.get("source"), "mapping.source")
            _nonblank(mapping.get("framework"), "mapping.framework")
            labels.append(_nonblank(mapping.get("control_id"), "mapping.control_id"))
    draft = PolicyDraft(
        policy_id=doc_id,
        title=doc_id,
        statement_ids=tuple(statement_ids),
    )
    draft_body = draft.model_dump(mode="json")
    return MapperCandidate(
        shape="mapping_report",
        input_path=input_path,
        input_sha256=input_sha256,
        doc_id=doc_id,
        snapshot_id=snapshot_id,
        ingest_source_hash=source_hash,
        statement_ids=tuple(statement_ids),
        mapper_control_labels=_labels(labels),
        policy_draft=draft,
        policy_draft_sha256=sha256_obj(draft_body),
    )


def _parse_ksi(data: dict[str, Any], input_path: str, input_sha256: str) -> MapperCandidate:
    _object(data.get("source"), "source")
    _object(data.get("classes"), "classes")
    domains = _object(data.get("domains"), "domains")
    indicator_ids: list[str] = []
    for name, domain in domains.items():
        _nonblank(name, "domain name")
        body = _object(domain, "domain")
        indicators = body.get("indicators", [])
        if not isinstance(indicators, list):
            _mapper_fail("indicators must be a list")
        for index, indicator in enumerate(indicators):
            row = _object(indicator, f"indicators[{index}]")
            indicator_ids.append(_safe_id(row.get("id"), "indicator id"))
    return MapperCandidate(
        shape="ksi_catalog",
        input_path=input_path,
        input_sha256=input_sha256,
        mapper_indicator_ids=_labels(indicator_ids),
    )


def _parse_links(data: dict[str, Any], input_path: str, input_sha256: str) -> MapperCandidate:
    raw_links = data.get("links")
    if not isinstance(raw_links, list):
        _mapper_fail("links must be a list")
    link_ids: list[str] = []
    labels: list[str] = []
    for index, item in enumerate(raw_links):
        link = _object(item, f"links[{index}]")
        link_ids.append(_safe_id(link.get("link_id"), "link_id"))
        _safe_id(link.get("doc_id"), "doc_id")
        _nonblank(link.get("statement_anchor"), "statement_anchor")
        control_ids = link.get("control_ids", [])
        if not isinstance(control_ids, list):
            _mapper_fail("control_ids must be a list")
        for control_id in control_ids:
            labels.append(_nonblank(control_id, "control_id"))
    return MapperCandidate(
        shape="policy_code_links",
        input_path=input_path,
        input_sha256=input_sha256,
        link_ids=tuple(link_ids),
        mapper_control_labels=_labels(labels),
    )


def parse_mapper_document(data: object, *, input_path: str, input_sha256: str) -> MapperCandidate:
    """Parse one mapper object. The candidate omits statement prose."""
    body = _object(data, "mapper document")
    shape = _classify(body)
    match shape:
        case "mapping_report":
            candidate = _parse_report(body, input_path, input_sha256)
        case "ksi_catalog":
            candidate = _parse_ksi(body, input_path, input_sha256)
        case "policy_code_links":
            candidate = _parse_links(body, input_path, input_sha256)
        case _:
            _never_shape(shape)
    if candidate.record_v != 1 or candidate.claim is not None:
        _mapper_fail("candidate record is not a draft registration")
    if candidate.role != "candidate":
        _mapper_fail("candidate record is not a draft registration")
    assert_no_claim_words(candidate.model_dump(mode="json"))
    return candidate


def load_mapper_file(path: Path) -> MapperCandidate:
    """Read one mapper JSON file and hash its bytes."""
    if not path.is_file():
        _mapper_fail("mapper file is missing")
    suffix = path.suffix.lower()
    if suffix in {".pdf", ".doc", ".docx", ".docm", ".rtf", ".odt"}:
        _mapper_fail("mapper ingest reads JSON only")
    raw = path.read_bytes()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        _mapper_fail("mapper file is not JSON")
    return parse_mapper_document(data, input_path=str(path), input_sha256=sha256_bytes(raw))


def write_mapper_candidate(candidate: MapperCandidate, out_dir: Path) -> Path:
    """Write the candidate JSON. An existing different file fails closed."""
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"{candidate.shape}-{candidate.input_sha256[:16]}.json"
    path = out_dir / name
    payload = dumps(candidate.model_dump(mode="json")) + b"\n"
    assert_no_claim_words(json.loads(payload))
    if path.exists() and path.read_bytes() != payload:
        _mapper_fail("candidate file already exists with different bytes")
    path.write_bytes(payload)
    return path


def ingest_mapper_file(path: Path, out_dir: Path) -> tuple[MapperCandidate, Path]:
    """Register one mapper file as a candidate under out_dir."""
    try:
        candidate = load_mapper_file(path)
    except ValidationError as exc:
        _mapper_fail(f"mapper file failed validation: {exc.errors()[0]['msg']}")
    written = write_mapper_candidate(candidate, out_dir)
    return candidate, written
