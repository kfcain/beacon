"""Immutable assessment specifications; importing a specification does not approve it."""
from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from beacon.canonical import dumps, sha256_obj
from beacon.errors import fail
from beacon.locking import locked
from beacon.scf.objective_catalog import CATALOG_SHA256, objectives
from beacon.scope.store import list_scopes, load_scope

HASH = r"^[0-9a-f]{64}$"


class Criterion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    criterion_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    assertion: str = Field(min_length=10, max_length=2000)
    validator_id: str = Field(min_length=1, max_length=100)
    validator_sha256: str = Field(pattern=HASH)
    max_age_seconds: int = Field(default=86400, ge=1, le=2592000)
    policy_path: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def valid_source(self):
        from beacon.assurance.validators import validator_definition
        definition = validator_definition(self.validator_id)
        if definition["plugin"] == "git.policy":
            path = self.policy_path
            if (not path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
                    or "\\" in path or not path.endswith(".json")):
                raise ValueError("policy criteria require an exact relative JSON policy_path")
        elif self.policy_path is not None:
            raise ValueError("policy_path only applies to policy validators")
        return self


class AssessmentSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    schema_version: Literal[1] = 1
    spec_id: str = Field(pattern=r"^[a-z][a-z0-9._/-]{0,99}$")
    title: str = Field(min_length=1, max_length=200)
    control_ref: str = Field(pattern=r"^[A-Z0-9]+-[0-9]+$")
    ao_id: str = Field(min_length=1, max_length=100)
    objective_sha256: str = Field(pattern=HASH)
    catalog_sha256: str = Field(pattern=HASH)
    coverage: Literal["supporting"] = "supporting"
    time_basis: Literal["point_in_time", "period"] = "point_in_time"
    criteria: list[Criterion] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def valid_objective(self):
        from beacon.assurance.validators import validator_definition
        if self.catalog_sha256 != CATALOG_SHA256:
            raise ValueError("specification catalog differs from the reviewed pin")
        objective = next((row for row in objectives(self.control_ref) if row["ao_id"] == self.ao_id), None)
        if objective is None or sha256_obj(objective) != self.objective_sha256:
            raise ValueError("objective text or identifier does not match the reviewed catalog")
        ids = [criterion.criterion_id for criterion in self.criteria]
        if len(ids) != len(set(ids)):
            raise ValueError("criterion ids must be unique")
        for criterion in self.criteria:
            controls = validator_definition(criterion.validator_id)["controls"]
            if controls and self.control_ref not in controls:
                raise ValueError("validator does not support this control")
        return self


def spec_digest(spec: AssessmentSpec) -> str:
    return sha256_obj(spec.model_dump(mode="json"))


def _spec_path(settings, digest: str):
    if not isinstance(digest, str) or re.fullmatch(HASH, digest) is None:
        fail("E_SPEC", "spec_sha256 must be a lowercase SHA-256 digest")
    return settings.home / "assessment-specs" / f"{digest}.json"


def _parse(raw: str) -> AssessmentSpec:
    if len(raw.encode("utf-8")) > 65536:
        fail("E_SPEC", "assessment specification exceeds 64 KiB")
    try:
        return AssessmentSpec.model_validate_json(raw)
    except ValueError as exc:
        fail("E_SPEC", f"invalid assessment specification: {exc}")


@locked
def import_spec(settings, raw: str) -> dict:
    spec = _parse(raw)
    digest = spec_digest(spec)
    path = _spec_path(settings, digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        load_spec(settings, digest)
    else:
        from beacon.crypto.trust import atomic_write
        atomic_write(path, dumps(spec.model_dump(mode="json")) + b"\n")
    return {"spec": spec.model_dump(mode="json"), "spec_sha256": digest, "approved": False}


def load_spec(settings, digest: str) -> AssessmentSpec:
    path = _spec_path(settings, digest)
    try:
        if path.stat().st_size > 65536:
            fail("E_SPEC", "assessment specification exceeds 64 KiB")
        spec = _parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        fail("E_SPEC", f"assessment specification unavailable: {exc}")
    if spec_digest(spec) != digest:
        fail("E_SPEC", "stored specification no longer matches its digest")
    return spec


def list_specs(settings, *, scope_id: str | None = None) -> list[dict]:
    approved = None if scope_id is None else set(getattr(load_scope(settings, scope_id), "parameters", {}).get(
        "approved_assessment_sha256", []))
    return [{"spec": (spec := load_spec(settings, path.stem)).model_dump(mode="json"),
             "spec_sha256": spec_digest(spec), "approved": None if approved is None else path.stem in approved}
            for path in sorted((settings.home / "assessment-specs").glob("*.json"))]


def draft_ebs_spec(*, policy_path: str = "policies/encryption.json", time_basis: str = "point_in_time") -> dict:
    """A reviewable example. No source, organizational parameter, or scope is approved here."""
    from beacon.assurance.validators import validator_digest
    objective = next(row for row in objectives("CRY-07") if row["ao_id"] == "CRY-07_A02")
    clauses = [
        ("encryption", "ebs-encryption/v1", "Every volume in the approved EBS inventory reports encryption enabled.", None),
        ("approved_keys", "ebs-approved-keys/v1", "Every observed EBS volume names a key ARN in the approved key list; this does not test key permissions or rotation.", None),
        ("policy", "policy-review/v1", "Review whether the approved policy documents the scoped encryption and approved-key obligations, citing the relevant sections.", policy_path),
    ]
    spec = AssessmentSpec(spec_id="ebs-encryption-policy/v1", title="EBS encryption and approved policy",
        control_ref="CRY-07", ao_id=objective["ao_id"], objective_sha256=sha256_obj(objective),
        catalog_sha256=CATALOG_SHA256, time_basis=time_basis,
        criteria=[Criterion(criterion_id=cid, assertion=assertion, validator_id=vid,
                  validator_sha256=validator_digest(vid), policy_path=path) for cid, vid, assertion, path in clauses])
    return spec.model_dump(mode="json")
