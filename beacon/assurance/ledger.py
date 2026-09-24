"""KSI automated-method counts. A count is a package rule. It is not a seal and it is not a claim."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from beacon.config import parse_iso8601
from beacon.scope.document import SCOPE_ID_RE, SHA256_RE

PackageClass = Literal["c", "d"]

# Class C minimum is the CR26 Class C guide rule FRC-CSX-VVK (at least 2).
# Class D minimum is the assurance-stack brief. The attached guide is Class C only.
# This module does not invent a Class D rule id.
CLASS_AUTOMATED_METHOD_MIN: dict[PackageClass, int] = {"c": 2, "d": 4}


class MethodRecord(BaseModel):
    """One sealed validation method. The body of the observation stays out of this record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope_id: str
    ksi_id: str
    method_id: str
    automated: bool
    evidence_sha256: str
    s3_uri: str | None = None
    git_sha: str | None = None
    ao_id: str | None = None
    control_ref: str | None = None
    sealed_at: str | None = None

    @field_validator("scope_id", "ksi_id", "method_id")
    @classmethod
    def ids_are_safe(cls, value: str) -> str:
        if not SCOPE_ID_RE.fullmatch(value):
            raise ValueError("id must match the safe id pattern")
        return value

    @field_validator("evidence_sha256")
    @classmethod
    def hash_is_sha256(cls, value: str) -> str:
        if not SHA256_RE.fullmatch(value):
            raise ValueError("evidence_sha256 must be 64 lowercase hex characters")
        return value

    @field_validator("ao_id", "control_ref")
    @classmethod
    def optional_label(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not SCOPE_ID_RE.fullmatch(value):
            raise ValueError("label must match the safe id pattern")
        return value


class KsiMethodCount(BaseModel):
    """Automated-method count for one KSI label. ``shortfall`` is a package gap, not a met flag."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ksi_id: str
    automated_method_ids: tuple[str, ...]
    manual_method_ids: tuple[str, ...]
    automated_method_count: int = Field(ge=0)
    minimum: int = Field(ge=1)
    shortfall: int = Field(ge=0)


class LedgerGapReport(BaseModel):
    """Gap view for package readiness. This report has no claim field."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    package_class: PackageClass
    minimum: int = Field(ge=1)
    required_list_supplied: bool
    counts: tuple[KsiMethodCount, ...]
    below_minimum: tuple[str, ...]
    excluded_stale: tuple[str, ...] = ()
    excluded_undated: tuple[str, ...] = ()


def _instant(value: str, *, label: str):
    try:
        return parse_iso8601(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not an ISO-8601 instant") from exc


def _minimum(package_class: str) -> int:
    match package_class:
        case "c" | "d":
            return CLASS_AUTOMATED_METHOD_MIN[package_class]
        case _:
            raise ValueError("package class must be c or d")


def ksi_method_report(
    records: list[MethodRecord] | tuple[MethodRecord, ...],
    *,
    package_class: PackageClass,
    required_ksi_ids: list[str] | tuple[str, ...] | None = None,
    not_before: str | None = None,
) -> LedgerGapReport:
    """Count distinct automated methods per KSI.

    The same ``method_id`` counts once. A manual method does not count.
    When ``not_before`` is set, a record older than that instant is excluded.
    A record with no ``sealed_at`` is excluded too. This function does not
    choose the freshness window.
    When ``required_ksi_ids`` is omitted, only KSI labels present on counted
    records appear. ``required_list_supplied`` is then false. The guide names
    46 KSIs. This function does not ship that list.
    """
    minimum = _minimum(package_class)
    cutoff = _instant(not_before, label="not_before") if not_before is not None else None
    if records:
        scope_ids = {record.scope_id for record in records}
        if len(scope_ids) != 1:
            raise ValueError("method records must share one scope_id")
    counted: list[MethodRecord] = []
    stale: list[str] = []
    undated: list[str] = []
    for record in records:
        label = f"{record.ksi_id}/{record.method_id}"
        if cutoff is None:
            counted.append(record)
            continue
        if record.sealed_at is None:
            undated.append(label)
            continue
        sealed = _instant(record.sealed_at, label="sealed_at")
        if sealed < cutoff:
            stale.append(label)
            continue
        counted.append(record)

    grouped: dict[str, list[MethodRecord]] = {}
    for record in counted:
        grouped.setdefault(record.ksi_id, []).append(record)

    ordered_ids: list[str] = []
    supplied = required_ksi_ids is not None
    if required_ksi_ids is not None:
        if len(required_ksi_ids) == 0:
            raise ValueError("required ksi ids must not be empty")
        seen: set[str] = set()
        for ksi_id in required_ksi_ids:
            if not SCOPE_ID_RE.fullmatch(ksi_id):
                raise ValueError("required ksi id must match the safe id pattern")
            if ksi_id in seen:
                raise ValueError("required ksi ids must not repeat")
            seen.add(ksi_id)
            ordered_ids.append(ksi_id)
    else:
        ordered_ids = sorted(grouped)

    counts: list[KsiMethodCount] = []
    below: list[str] = []
    for ksi_id in ordered_ids:
        rows = grouped.get(ksi_id, [])
        automated: list[str] = []
        manual: list[str] = []
        seen_flag: dict[str, bool] = {}
        for row in rows:
            prior = seen_flag.get(row.method_id)
            if prior is not None and prior != row.automated:
                raise ValueError("one method id must not be both automated and manual")
            seen_flag[row.method_id] = row.automated
            target = automated if row.automated else manual
            if row.method_id not in target:
                target.append(row.method_id)
        shortfall = max(0, minimum - len(automated))
        if shortfall:
            below.append(ksi_id)
        counts.append(
            KsiMethodCount(
                ksi_id=ksi_id,
                automated_method_ids=tuple(automated),
                manual_method_ids=tuple(manual),
                automated_method_count=len(automated),
                minimum=minimum,
                shortfall=shortfall,
            )
        )
    return LedgerGapReport(
        package_class=package_class,
        minimum=minimum,
        required_list_supplied=supplied,
        counts=tuple(counts),
        below_minimum=tuple(below),
        excluded_stale=tuple(stale),
        excluded_undated=tuple(undated),
    )
