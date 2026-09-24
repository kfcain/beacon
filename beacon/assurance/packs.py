"""Draft pack shapes for CR26 CPO, SDR, OCR, and SCG.

The draft stores evidence pointers. It does not store observation bodies.
It does not emit claim words or SDR status words.
"""

from __future__ import annotations

import urllib.parse
from typing import Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from beacon.config import PACK_TYPES
from beacon.scope.document import SHA256_RE

PackKind = Literal["cpo", "sdr", "ocr", "scg"]
PACK_KINDS: tuple[PackKind, ...] = ("cpo", "sdr", "ocr", "scg")

# Existing beacon push types. CPO has no pack_type yet.
BEACON_PACK_TYPE_BY_KIND: dict[PackKind, str | None] = {
    "cpo": None,
    "sdr": "security-decision-record",
    "ocr": "ongoing-certification-report",
    "scg": "secure-configuration-guide",
}

GUIDE_NOTES: dict[PackKind, str] = {
    "cpo": "CPO draft. Field names follow the CR26 Class C guide. Values for human fields are unset.",
    "sdr": "SDR draft. Evidence is a pointer list. Status words are unset.",
    "ocr": "OCR draft. reportableIncidents is unset so an empty array is not an attestation.",
    "scg": "SCG draft. The guide asks for instructions to get and use the guide (SCG-CSO-AUP). That text is unset.",
}

# Field names copied from the CR26 Class C guide (schema pages). Not a fetched schema.
UNSET_FIELDS: dict[PackKind, tuple[str, ...]] = {
    "cpo": (
        "serviceIdentification",
        "contactInformation",
        "serviceProperties.trustCenter.url",
        "serviceProperties.secureConfigurationGuidance",
        "serviceProperties.assessor",
        "nextOngoingCertificationReportDate",
    ),
    "sdr": (
        "certificationPackageOverviewUri",
        "fedRampRequirements",
        "keySecurityIndicators",
        "metadata",
    ),
    "ocr": (
        "certificationPackageOverviewUri",
        "reportPeriod",
        "certificationDataChanges",
        "plannedCertificationDataChanges",
        "acceptedVulnerabilities",
        "transformativeChanges",
        "updatedRecommendations",
        "activeAgencies",
        "reportableIncidents",
    ),
    "scg": (
        "instructions_to_get_and_use",
    ),
}


def _never(value: object) -> NoReturn:
    raise AssertionError(f"unhandled value: {value!r}")


def _kind(value: str) -> PackKind:
    match value:
        case "cpo" | "sdr" | "ocr" | "scg":
            return value
        case _:
            raise ValueError("unknown pack kind")


class EvidencePointer(BaseModel):
    """A hash and optional location. The pointer does not include observation bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sha256: str
    s3_uri: str | None = None
    git_sha: str | None = None

    @field_validator("sha256")
    @classmethod
    def hash_is_sha256(cls, value: str) -> str:
        if not SHA256_RE.fullmatch(value):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        return value

    @field_validator("s3_uri")
    @classmethod
    def s3_uri_is_not_an_observation(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(char.isspace() for char in value) or not value.startswith("s3://"):
            raise ValueError("s3_uri must be an s3 URI")
        rest = value[len("s3://") :]
        bucket, separator, key = rest.partition("/")
        if not bucket or not separator or not key:
            raise ValueError("s3_uri must name a bucket and a key")
        decoded = urllib.parse.unquote(key).lower()
        segments = [part for part in decoded.split("/") if part]
        if "observations" in segments:
            raise ValueError("s3_uri must not point at an observations prefix")
        return value

    @field_validator("git_sha")
    @classmethod
    def git_sha_is_hex(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value) not in (40, 64) or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("git_sha must be 40 or 64 lowercase hex characters")
        return value


class PackDraft(BaseModel):
    """Schema-shaped draft. Human fields stay in ``unset_fields``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    draft: Literal[True] = True
    pack_kind: PackKind
    beacon_pack_type: str | None
    scope_sha256: str
    fedramp_id: str | None = None
    evidence: tuple[EvidencePointer, ...] = ()
    unset_fields: tuple[str, ...] = Field(min_length=1)
    guide_note: str

    @field_validator("scope_sha256")
    @classmethod
    def scope_hash(cls, value: str) -> str:
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

    @model_validator(mode="after")
    def shape_matches_kind(self) -> PackDraft:
        if self.beacon_pack_type != BEACON_PACK_TYPE_BY_KIND[self.pack_kind]:
            raise ValueError("beacon pack type does not match the pack kind")
        if self.unset_fields != UNSET_FIELDS[self.pack_kind]:
            raise ValueError("unset fields do not match the pack kind")
        if self.guide_note != GUIDE_NOTES[self.pack_kind]:
            raise ValueError("guide note does not match the pack kind")
        return self

    def canonical_body(self) -> dict:
        return self.model_dump(mode="json")


def compile_pack_draft(
    kind: str,
    *,
    pointers: list[EvidencePointer] | tuple[EvidencePointer, ...] = (),
    scope_sha256: str,
    fedramp_id: str | None = None,
) -> PackDraft:
    """Emit one draft pack. OCR does not include an empty incidents array.

    An empty incidents array would attest that no reportable incident occurred.
    This sketch leaves ``reportableIncidents`` unset.
    """
    pack_kind = _kind(kind)
    beacon_type = BEACON_PACK_TYPE_BY_KIND[pack_kind]
    if beacon_type is not None and beacon_type not in PACK_TYPES:
        raise ValueError("beacon pack type is not a current pack type")
    match pack_kind:
        case "cpo" | "sdr" | "ocr" | "scg":
            note = GUIDE_NOTES[pack_kind]
        case _ as unknown:
            _never(unknown)
    return PackDraft(
        pack_kind=pack_kind,
        beacon_pack_type=beacon_type,
        scope_sha256=scope_sha256,
        fedramp_id=fedramp_id,
        evidence=tuple(pointers),
        unset_fields=UNSET_FIELDS[pack_kind],
        guide_note=note,
    )
