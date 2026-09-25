"""Versioned, installed validators. Specifications never contain executable code."""
from __future__ import annotations

import json
import re
from pathlib import Path

from beacon.assurance.policy import PolicyObject
from beacon.canonical import sha256_bytes, sha256_obj
from beacon.errors import fail

KMS_KEY_ARN = re.compile(r"^arn:(aws|aws-us-gov):kms:([a-z0-9-]+):([0-9]{12}):key/([A-Za-z0-9-]+)$")

DEFINITIONS = {
    "ebs-encryption/v1": {"plugin": "aws.ebs.encryption", "format": "beacon.aws-ebs/v1", "method": "test", "controls": ["CRY-07"]},
    "ebs-approved-keys/v1": {"plugin": "aws.ebs.encryption", "format": "beacon.aws-ebs/v1", "method": "test", "controls": ["CRY-07"]},
    "policy-review/v1": {"plugin": "git.policy", "format": "beacon.git-policy/v1", "method": "examine", "controls": []},
}


def validator_definition(validator_id: str) -> dict:
    if validator_id not in DEFINITIONS:
        fail("E_VALIDATOR", "unknown installed validator; specifications cannot load code")
    return dict(DEFINITIONS[validator_id])


def validator_digest(validator_id: str) -> str:
    definition = validator_definition(validator_id)
    root = Path(__file__).resolve().parents[1]
    # Pin the implementation and its collection, admission, and assessment
    # semantics, not just a label. What "complete" means lives in the collectors.
    files = ("assurance/validators.py", "assurance/specs.py", "assurance/assessments.py",
             "assurance/admission.py", "assurance/policy.py", "assurance/policy_capture.py",
             "plugins/aws_ebs.py", "scf/engine.py", "scope/enforce.py", "scope/bind.py",
             "scope/v2.py", "scope/store.py")
    return sha256_obj({"validator_id": validator_id, "definition": definition,
        "implementation": {name: sha256_bytes((root / name).read_bytes()) for name in files}})


def _finding(code: str, resource: str, message: str) -> dict:
    return {"code": code, "resource": resource, "message": message}


def _ebs(payload: dict, scope) -> dict:
    gaps, findings = [], []
    expected = scope.parameters.get("expected_ebs_volumes", [])
    if not expected:
        gaps.append("approved_population_missing")
    rows = payload.get("volumes")
    valid_rows, ids = [], []
    if not isinstance(rows, list):
        rows = []
        gaps.append("malformed_inventory")
    regions = set(scope.boundary.regions)
    if not regions or len(scope.boundary.accounts) != 1:
        gaps.append("single_account_and_regions_required")
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("VolumeId"), str)
                or not row["VolumeId"] or not isinstance(row.get("region"), str)
                or row["region"] not in regions or type(row.get("Encrypted")) is not bool):
            gaps.append("malformed_volume")
            continue
        resource = f"{row['region']}/{row['VolumeId']}"
        ids.append(resource)
        valid_rows.append(row)
        if row["Encrypted"] is False:
            findings.append(_finding("unencrypted_volume", resource, "Observed volume reports Encrypted=false."))
    if len(ids) != len(set(ids)):
        gaps.append("duplicate_volume")
    missing, extra = sorted(set(expected) - set(ids)), sorted(set(ids) - set(expected))
    if missing:
        gaps.append("population_missing")
    if extra:
        gaps.append("population_unexpected")
    if not rows:
        gaps.append("empty_population_requires_review")
    observed_regions = payload.get("regions")
    runs = payload.get("region_runs")
    if (not isinstance(observed_regions, list) or any(not isinstance(r, str) for r in observed_regions)
            or set(observed_regions) != regions or len(observed_regions) != len(regions)):
        gaps.append("region_inventory_mismatch")
    if (not isinstance(runs, list) or len(runs) != len(regions)
            or any(not isinstance(run, dict) or not isinstance(run.get("region"), str) for run in runs)):
        gaps.append("malformed_region_runs")
    else:
        if {run["region"] for run in runs} != regions:
            gaps.append("incomplete_region_inventory")
        for run in runs:
            if (run.get("complete") is not True or type(run.get("pages")) is not int or run["pages"] < 1
                    or type(run.get("volume_count")) is not int
                    or run["volume_count"] != sum(row["region"] == run["region"] for row in valid_rows)):
                gaps.append("incomplete_region_inventory")
    if payload.get("errors") != []:
        gaps.append("collection_errors")
    return {"gaps": sorted(set(gaps)), "findings": findings, "rows": valid_rows,
            "coverage": {"expected": len(expected), "observed": len(set(ids)), "missing": missing, "unexpected": extra}}


def _policy(payload: dict, scope, criterion, control_ref: str) -> dict:
    gaps = []
    content = payload.get("content")
    try:
        if not isinstance(content, str) or len(content.encode("utf-8")) > 16384:
            raise ValueError("invalid policy content")
        policy = PolicyObject.model_validate_json(content)
        if policy.canonical_body() != payload.get("policy"):
            raise ValueError("normalized policy differs from the approved bytes")
        if control_ref not in policy.control_refs or scope.scope_id not in policy.scope_refs:
            raise ValueError("policy does not cover this control and scope")
        digest = sha256_bytes(content.encode("utf-8"))
        sources = scope.parameters.get("policy_sources", [])
        if not any(isinstance(source, dict) and source.get("path") == criterion.policy_path == payload.get("path")
                   and source.get("commit") == payload.get("git_commit")
                   and source.get("file_sha256") == digest == payload.get("file_sha256")
                   and source.get("system_id") == payload.get("identity", {}).get("system_id")
                   for source in sources):
            raise ValueError("policy source not approved")
    except (ValueError, TypeError, AttributeError):
        gaps.append("policy_binding_mismatch")
    return {"status": "insufficient" if gaps else "needs_review", "gaps": gaps,
            "findings": [], "coverage": {"document": criterion.policy_path},
            "review_prompt": criterion.assertion}


def run_validator(validator_id: str, payload: dict, scope, criterion, control_ref: str) -> dict:
    validator_definition(validator_id)
    if validator_id == "policy-review/v1":
        return _policy(payload, scope, criterion, control_ref)
    result = _ebs(payload, scope)
    if validator_id == "ebs-approved-keys/v1":
        approved = scope.parameters.get("approved_kms_key_arns", [])
        if not approved:
            result["gaps"].append("approved_key_list_missing")
        for row in result["rows"]:
            resource = f"{row['region']}/{row['VolumeId']}"
            key = row.get("KmsKeyId")
            parsed = KMS_KEY_ARN.fullmatch(key) if isinstance(key, str) else None
            if parsed is None:
                result["gaps"].append(f"key_arn_missing_or_malformed:{resource}")
            elif (parsed[2] != row["region"] or parsed[1] != (payload.get("identity", {}).get("partition")
                                                               if isinstance(payload.get("identity"), dict) else None)):
                result["findings"].append(_finding("key_location_mismatch", resource, "Key ARN region or partition differs from the observed volume."))
            elif approved and key not in approved:
                result["findings"].append(_finding("unapproved_key", resource, f"Observed key ARN is not in the approved list: {key}"))
    result.pop("rows")
    result["gaps"] = sorted(set(result["gaps"]))
    result["status"] = "supporting_fail" if result["findings"] else "insufficient" if result["gaps"] else "supporting_pass"
    return result
