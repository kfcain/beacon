"""Compile Beacon-shaped CPO, SDR, OCR, and SCG drafts from sealed observations.

The draft is JSON. Markdown is rendered from that same object.
This module does not fetch a FedRAMP schema and does not set a schema status word.
A method shortfall stays a package gap.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from beacon.assurance.index import (
    SourceKind,
    assert_no_claim_words,
    ledger_method_report,
    load_evidence_ledger,
)
from beacon.assurance.ledger import CLASS_AUTOMATED_METHOD_MIN, KsiMethodCount, PackageClass
from beacon.assurance.packs import (
    BEACON_PACK_TYPE_BY_KIND,
    GUIDE_NOTES,
    PACK_KINDS,
    UNSET_FIELDS,
    EvidencePointer,
    PackKind,
)
from beacon.canonical import dumps
from beacon.config import Settings
from beacon.errors import E_LEDGER, BeaconError, fail
from beacon.scope.document import SCOPE_ID_RE, SHA256_RE
from beacon.locking import locked

DRAFT_FORMAT = "beacon-20x-draft/v1"
OfficialSchema = Literal["not-fetched"]

GUIDE_NAMES: dict[PackKind, str] = {
    "cpo": "Certification Package Overview",
    "sdr": "Security Decision Record",
    "ocr": "Ongoing Certification Report",
    "scg": "Secure Configuration Guide",
}

# Beacon field, guide field, whether this compiler fills it, and a short note.
# Unset guide fields are appended from UNSET_FIELDS so the map stays aligned.
_SHARED_FIELD_MAP: tuple[tuple[str, str, bool, str], ...] = (
    (
        "evidence.sha256",
        "evidence pointer",
        True,
        "Seal digest. The observation body stays out of this file.",
    ),
    (
        "scope_id",
        "Beacon scope stamp",
        True,
        "Copied when every selected seal shares one scope pair, or when --scope is set.",
    ),
    (
        "scope_sha256",
        "Beacon scope stamp",
        True,
        "ScopeDocument content hash. Copied with scope_id. Not a guide schema field.",
    ),
    (
        "fedramp_id",
        "FedRAMP identifier",
        True,
        "Copied only when the operator passes it. Guide citation CDS-CSO-FID.",
    ),
    (
        "package_gaps",
        "keySecurityIndicators automated-count minimum",
        True,
        "A shortfall is a package gap. Class C cites FRC-CSX-VVK. No schema status word is written.",
    ),
    (
        "method_counts",
        "automated-count",
        True,
        "Distinct automated evidence-method ids. A manual evidence-method is listed and does not add to the count.",
    ),
)

_UNSET_NOTES: dict[str, str] = {
    "serviceIdentification": "Operator service identity. This compiler does not invent it.",
    "contactInformation": "Operator contact. This compiler does not invent it.",
    "serviceProperties.trustCenter.url": "Trust-center URL. Publish stays a later phase.",
    "serviceProperties.secureConfigurationGuidance": "Pointer to the SCG. The guide text stays unset.",
    "serviceProperties.assessor": "Assessor identity. This compiler does not invent it.",
    "nextOngoingCertificationReportDate": "Next OCR date. This compiler does not choose a calendar date.",
    "certificationPackageOverviewUri": "CPO URI. This compiler does not invent a trust-center URL.",
    "fedRampRequirements": "Requirement rows. This compiler does not invent requirement text.",
    "keySecurityIndicators": "Guide indicator object. Beacon writes package_gaps instead of a schema status word.",
    "metadata": "Guide-metadata object. Left unset. Beacon stamps scope and fedramp_id on this draft.",
    "reportPeriod": "OCR window. This compiler does not choose from and to.",
    "certificationDataChanges": "Change list. This compiler does not invent change rows.",
    "plannedCertificationDataChanges": "Planned change list. This compiler does not invent change rows.",
    "acceptedVulnerabilities": "Accepted vulnerability list. This compiler does not invent vulnerability rows.",
    "transformativeChanges": "Transformative change list. This compiler does not invent change rows.",
    "updatedRecommendations": "Recommendation list. This compiler does not invent recommendation text.",
    "activeAgencies": "Agency list. This compiler does not invent agency names.",
    "reportableIncidents": "Left unset. An empty array would say that no reportable incident occurred.",
    "instructions_to_get_and_use": "SCG-CSO-AUP asks for these instructions. This compiler does not invent them.",
}


def _never(value: object) -> NoReturn:
    raise AssertionError(f"unhandled value: {value!r}")


class FieldMapRow(BaseModel):
    """One Beacon field and the guide field it relates to."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    beacon_field: str
    guide_field: str
    filled: bool
    note: str


class PackageGap(BaseModel):
    """One KSI whose automated method count is under the class minimum."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ksi_id: str
    automated_method_ids: tuple[str, ...]
    manual_method_ids: tuple[str, ...]
    automated_method_count: int = Field(ge=0)
    minimum: int = Field(ge=1)
    shortfall: int = Field(ge=1)


class CompiledPack(BaseModel):
    """One machine-readable 20x draft. Human guide fields stay in ``unset_fields``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format: Literal["beacon-20x-draft/v1"] = DRAFT_FORMAT
    draft: Literal[True] = True
    pack_kind: PackKind
    beacon_pack_type: str | None
    guide_name: str
    guide_note: str
    scope_id: str | None = None
    scope_sha256: str | None = None
    fedramp_id: str | None = None
    package_class: PackageClass
    minimum_automated_methods: int = Field(ge=1)
    required_list_supplied: bool
    source: SourceKind
    evidence: tuple[EvidencePointer, ...] = ()
    control_refs: tuple[str, ...] = ()
    method_counts: tuple[KsiMethodCount, ...] = ()
    package_gaps: tuple[PackageGap, ...] = ()
    below_minimum: tuple[str, ...] = ()
    excluded_stale: tuple[str, ...] = ()
    excluded_undated: tuple[str, ...] = ()
    excluded_ineligible: tuple[str, ...] = ()
    unset_fields: tuple[str, ...] = Field(min_length=1)
    field_map: tuple[FieldMapRow, ...] = Field(min_length=1)
    official_schema: OfficialSchema = "not-fetched"
    emits_schema_status_words: Literal[False] = False

    @field_validator("scope_id")
    @classmethod
    def scope_id_is_safe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not SCOPE_ID_RE.fullmatch(value):
            raise ValueError("scope_id must match the safe id pattern")
        return value

    @field_validator("scope_sha256")
    @classmethod
    def scope_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not SHA256_RE.fullmatch(value):
            raise ValueError("scope_sha256 must be 64 lowercase hex characters")
        return value

    @field_validator("fedramp_id")
    @classmethod
    def fedramp_id_is_token(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            not value
            or value != value.strip()
            or any(char.isspace() for char in value)
            or "/" in value
            or "\\" in value
            or ".." in value
        ):
            raise ValueError("fedramp_id must be a non-blank token")
        return value

    @field_validator("control_refs")
    @classmethod
    def control_refs_are_safe(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            if not SCOPE_ID_RE.fullmatch(item):
                raise ValueError("control ref must match the safe id pattern")
        if list(value) != sorted(set(value)):
            raise ValueError("control refs must be unique and sorted")
        return value

    @model_validator(mode="after")
    def shape_matches_kind(self) -> CompiledPack:
        if (self.scope_id is None) != (self.scope_sha256 is None):
            raise ValueError("scope_id and scope_sha256 must be set together")
        if self.beacon_pack_type != BEACON_PACK_TYPE_BY_KIND[self.pack_kind]:
            raise ValueError("beacon pack type does not match the pack kind")
        if self.guide_name != GUIDE_NAMES[self.pack_kind]:
            raise ValueError("guide name does not match the pack kind")
        if self.guide_note != GUIDE_NOTES[self.pack_kind]:
            raise ValueError("guide note does not match the pack kind")
        if self.unset_fields != UNSET_FIELDS[self.pack_kind]:
            raise ValueError("unset fields do not match the pack kind")
        if self.field_map != field_map_for(self.pack_kind):
            raise ValueError("field map does not match the pack kind")
        if self.minimum_automated_methods != CLASS_AUTOMATED_METHOD_MIN[self.package_class]:
            raise ValueError("minimum does not match the package class")
        gap_ids = tuple(row.ksi_id for row in self.package_gaps)
        if gap_ids != self.below_minimum:
            raise ValueError("package gaps do not match below_minimum")
        for gap in self.package_gaps:
            if gap.minimum != self.minimum_automated_methods:
                raise ValueError("package gap minimum does not match the package class")
        return self

    def canonical_body(self) -> dict:
        return self.model_dump(mode="json")


def field_map_for(kind: PackKind) -> tuple[FieldMapRow, ...]:
    """Return the Beacon-to-guide map for one pack kind."""
    rows = [
        FieldMapRow(beacon_field=beacon, guide_field=guide, filled=filled, note=note)
        for beacon, guide, filled, note in _SHARED_FIELD_MAP
    ]
    for guide_field in UNSET_FIELDS[kind]:
        rows.append(
            FieldMapRow(
                beacon_field="unset_fields",
                guide_field=guide_field,
                filled=False,
                note=_UNSET_NOTES[guide_field],
            )
        )
    return tuple(rows)


def render_pack_markdown(pack: CompiledPack) -> str:
    """Render Markdown from one compiled draft. The JSON file stays the source."""
    lines = [
        f"# {pack.guide_name}",
        "",
        f"- format: {pack.format}",
        "- draft: true",
        f"- pack_kind: {pack.pack_kind}",
        f"- beacon_pack_type: {pack.beacon_pack_type}",
        f"- package_class: {pack.package_class}",
        f"- minimum_automated_methods: {pack.minimum_automated_methods}",
        f"- scope_id: {pack.scope_id}",
        f"- scope_sha256: {pack.scope_sha256}",
        f"- fedramp_id: {pack.fedramp_id}",
        f"- official_schema: {pack.official_schema}",
        f"- source: {pack.source}",
        "",
        pack.guide_note,
        "",
        "## Evidence pointers",
        "",
    ]
    if not pack.evidence:
        lines.append("- none")
    for pointer in pack.evidence:
        lines.append(f"- sha256: {pointer.sha256}")
    lines.extend(["", "## Control refs", ""])
    if not pack.control_refs:
        lines.append("- none")
    for ref in pack.control_refs:
        lines.append(f"- {ref}")
    lines.extend(["", "## Method-counts", ""])
    if not pack.method_counts:
        lines.append("- none")
    for row in pack.method_counts:
        lines.append(
            f"- {row.ksi_id}: automated {row.automated_method_count}, "
            f"minimum {row.minimum}, shortfall {row.shortfall}"
        )
    lines.extend(["", "## Package gaps", ""])
    if not pack.package_gaps:
        lines.append("- none")
    for gap in pack.package_gaps:
        lines.append(
            f"- {gap.ksi_id}: shortfall {gap.shortfall} "
            f"(automated {gap.automated_method_count}, minimum {gap.minimum})"
        )
    lines.extend(["", "## Unset fields", ""])
    # Prefix keeps a space off names such as metadata. The ledger claim check
    # treats the letters " met" as a claim word.
    for name in pack.unset_fields:
        lines.append(f"- unset:{name}")
    lines.extend(
        [
            "",
            "A shortfall is a package gap. This draft writes no schema status word.",
            "",
        ]
    )
    return "\n".join(lines)


def _compile_fail(message: str) -> NoReturn:
    fail(E_LEDGER, message)


def _scope_stamp(
    entries: tuple,
    *,
    bound_scope_id: str | None,
    bound_scope_sha256: str | None,
) -> tuple[str | None, str | None]:
    if bound_scope_id is not None:
        return bound_scope_id, bound_scope_sha256
    stamps: list[tuple[str | None, str | None]] = []
    for entry in entries:
        if (entry.scope_id is None) != (entry.scope_sha256 is None):
            _compile_fail(f"seq {entry.seq} scope pair is incomplete")
        stamps.append((entry.scope_id, entry.scope_sha256))
    unique = set(stamps)
    if len(unique) > 1:
        _compile_fail("sealed observations do not share one scope pair")
    if not unique:
        return None, None
    return unique.pop()


def _pointers(entries: tuple) -> tuple[EvidencePointer, ...]:
    pointers: list[EvidencePointer] = []
    for entry in entries:
        try:
            pointers.append(EvidencePointer(sha256=entry.seal_sha256))
        except ValidationError as exc:
            _compile_fail(f"seq {entry.seq} evidence pointer is not valid: {exc}")
    return tuple(pointers)


def _control_refs(entries: tuple) -> tuple[str, ...]:
    found: list[str] = []
    for entry in entries:
        for scf_id in entry.scf_ids:
            if scf_id not in found:
                found.append(scf_id)
    return tuple(sorted(found))


def _gaps(counts: tuple[KsiMethodCount, ...]) -> tuple[PackageGap, ...]:
    rows: list[PackageGap] = []
    for count in counts:
        if count.shortfall == 0:
            continue
        rows.append(
            PackageGap(
                ksi_id=count.ksi_id,
                automated_method_ids=count.automated_method_ids,
                manual_method_ids=count.manual_method_ids,
                automated_method_count=count.automated_method_count,
                minimum=count.minimum,
                shortfall=count.shortfall,
            )
        )
    return tuple(rows)


@locked
def compile_20x_drafts(
    settings: Settings,
    *,
    package_class: PackageClass,
    kinds: tuple[PackKind, ...] = PACK_KINDS,
    scope_id: str | None = None,
    pack_path: Path | None = None,
    scf_id: str | None = None,
    required_ksi_ids: list[str] | tuple[str, ...] | None = None,
    not_before: str | None = None,
    fedramp_id: str | None = None,
) -> tuple[CompiledPack, ...]:
    """Compile one draft per kind from the ledger and the Class C/D method report."""
    if not kinds:
        _compile_fail("pack kind list must not be empty")
    seen: set[str] = set()
    for kind in kinds:
        match kind:
            case "cpo" | "sdr" | "ocr" | "scg":
                if kind in seen:
                    _compile_fail("pack kinds must not repeat")
                seen.add(kind)
            case _ as unknown:
                _never(unknown)
    try:
        ledger = load_evidence_ledger(
            settings,
            scope_id=scope_id,
            pack_path=pack_path,
            scf_id=scf_id,
        )
        report = ledger_method_report(
            settings,
            package_class=package_class,
            scope_id=scope_id,
            pack_path=pack_path,
            scf_id=scf_id,
            required_ksi_ids=required_ksi_ids,
            not_before=not_before,
        )
    except BeaconError:
        raise
    scope_stamp_id, scope_stamp_hash = _scope_stamp(
        ledger.entries,
        bound_scope_id=ledger.scope_id,
        bound_scope_sha256=ledger.scope_sha256,
    )
    pointers = _pointers(tuple(entry for entry in ledger.entries if entry.eligible))
    refs = _control_refs(ledger.entries)
    gaps = _gaps(report.counts)
    packs: list[CompiledPack] = []
    for kind in kinds:
        try:
            pack = CompiledPack(
                pack_kind=kind,
                beacon_pack_type=BEACON_PACK_TYPE_BY_KIND[kind],
                guide_name=GUIDE_NAMES[kind],
                guide_note=GUIDE_NOTES[kind],
                scope_id=scope_stamp_id,
                scope_sha256=scope_stamp_hash,
                fedramp_id=fedramp_id,
                package_class=report.package_class,
                minimum_automated_methods=report.minimum,
                required_list_supplied=report.required_list_supplied,
                source=ledger.source,
                evidence=pointers,
                control_refs=refs,
                method_counts=report.counts,
                package_gaps=gaps,
                below_minimum=report.below_minimum,
                excluded_stale=report.excluded_stale,
                excluded_undated=report.excluded_undated,
                excluded_ineligible=report.excluded_ineligible,
                unset_fields=UNSET_FIELDS[kind],
                field_map=field_map_for(kind),
            )
        except (ValidationError, ValueError) as exc:
            _compile_fail(str(exc))
        assert_no_claim_words(pack.canonical_body())
        packs.append(pack)
    return tuple(packs)


def write_compiled_packs(packs: tuple[CompiledPack, ...] | list[CompiledPack], out_dir: Path) -> dict[str, dict[str, str]]:
    """Write one JSON file and one Markdown file per draft. JSON is the source."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, dict[str, str]] = {}
    for pack in packs:
        json_path = out_dir / f"{pack.pack_kind}.json"
        md_path = out_dir / f"{pack.pack_kind}.md"
        json_path.write_bytes(dumps(pack.canonical_body()) + b"\n")
        md_path.write_text(render_pack_markdown(pack), encoding="utf-8")
        text = md_path.read_text(encoding="utf-8")
        assert_no_claim_words({"markdown": text})
        paths[pack.pack_kind] = {"json": str(json_path), "markdown": str(md_path)}
    return paths
