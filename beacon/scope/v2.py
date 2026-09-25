"""Opt-in scope parameters. Version-1 serialization and hashes remain stable."""
import json
import datetime as dt
import re
from typing import Literal

from pydantic import Field, JsonValue, field_validator, model_validator

from beacon.scope.document import ScopeDocument, Exclusion, SHA256_RE


class ExclusionV2(Exclusion):
    @model_validator(mode="after")
    def evidence_kind_is_known(self):
        if self.kind == "evidence_kind" and self.value not in {
            "cloud_inspector", "lake_log_extract", "catalog_pin", "drop_in", "policy", "attestation", "inbox"
        }:
            raise ValueError("unknown evidence kind")
        return self


class ScopeDocumentV2(ScopeDocument):
    schema_version: Literal[2] = 2
    allowed_evidence_kinds: tuple[Literal[
        "cloud_inspector", "lake_log_extract", "catalog_pin", "drop_in", "policy", "attestation", "inbox"
    ], ...] = Field(min_length=1)
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    exclusions: tuple[ExclusionV2, ...] = ()

    @field_validator("parameters")
    @classmethod
    def validate_parameters(cls, values):
        for key in ("approved_rule_sha256", "expected_ebs_volumes", "approved_assessment_sha256",
                    "approved_reviewers", "approved_kms_key_arns", "allowed_assessment_collectors"):
            if key in values:
                rows = values[key]
                if not isinstance(rows, list) or any(not isinstance(row, str) or not row for row in rows):
                    raise ValueError(f"{key} must be a list of nonblank strings")
                if len(rows) != len(set(rows)):
                    raise ValueError(f"{key} must not repeat")
                if key in {"approved_rule_sha256", "approved_assessment_sha256"} and any(not SHA256_RE.fullmatch(row) for row in rows):
                    raise ValueError("approved rules and specifications must be SHA-256 digests")
                if key == "approved_assessment_sha256" and len(rows) > 32:
                    raise ValueError("a scope supports at most 32 assessment specifications")
                if key == "approved_reviewers" and any(not re.fullmatch(r"uid:(0|[1-9][0-9]*)", row) for row in rows):
                    raise ValueError("approved reviewers must be canonical local uid identities")
                if key == "approved_kms_key_arns":
                    from beacon.assurance.validators import KMS_KEY_ARN
                    if any(KMS_KEY_ARN.fullmatch(row) is None for row in rows):
                        raise ValueError("approved KMS keys must be exact key ARNs, not aliases or patterns")
                if key == "allowed_assessment_collectors" and set(rows) - {"aws.ebs.encryption"}:
                    raise ValueError("only the read-only EBS collector supports automatic assessment refresh")
        if "assessment_recollection_seconds" in values:
            seconds = values["assessment_recollection_seconds"]
            if type(seconds) is not int or not 60 <= seconds <= 86400:
                raise ValueError("assessment recollection cooldown must be 60–86400 seconds")
        if "assessment_period" in values:
            period = values["assessment_period"]
            if not isinstance(period, dict) or set(period) != {"start", "end"}:
                raise ValueError("assessment period requires exactly start and end")
            try:
                start, end = [dt.datetime.fromisoformat(period[key].replace("Z", "+00:00")) for key in ("start", "end")]
                if start.tzinfo is None or end.tzinfo is None or start >= end:
                    raise ValueError("invalid time interval")
            except (AttributeError, TypeError, ValueError):
                raise ValueError("assessment period requires ordered timezone-aware timestamps")
        if "allow_external_judgment" in values and type(values["allow_external_judgment"]) is not bool:
            raise ValueError("allow_external_judgment must be a boolean")
        if "policy_sources" in values:
            sources = values["policy_sources"]
            if not isinstance(sources, list) or any(not isinstance(source, dict) for source in sources):
                raise ValueError("policy_sources must be an array of objects")
        return values


def parse_scope(raw: str):
    body = json.loads(raw)
    if not isinstance(body, dict):
        raise ValueError("scope is not an object")
    match body.get("schema_version", 1):
        case 1:
            return ScopeDocument.model_validate(body)
        case 2:
            return ScopeDocumentV2.model_validate(body)
        case _:
            raise ValueError("unsupported scope version")
