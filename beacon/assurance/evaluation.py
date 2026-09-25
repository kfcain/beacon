"""Objective-specific supporting assertions, independently of custody validity.

Every objective is accounted for. No bundled rule claims a complete objective,
control, framework authorization, or certification. No cached claim is reused.
"""
from __future__ import annotations

import datetime as dt
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from beacon.assurance.admission import eligibility, verified_snapshot
from beacon.assurance.jev import judgment_supports
from beacon.canonical import sha256_bytes, sha256_obj
from beacon.config import parse_iso8601
from beacon.crypto.witness import seal_payload, create_checkpoint
from beacon.errors import fail
from beacon.locking import locked
from beacon.scf.objective_catalog import objectives, CATALOG_SHA256, WORKBOOK_SHA256
from beacon.scope.bind import bind_observation_payload
from beacon.scope.store import load_scope


class ObjectiveRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    rule_id: str
    ao_id: str
    objective_sha256: str
    predicate: Literal["ebs_all_encrypted", "policy_content_review"]
    plugin: Literal["aws.ebs.encryption", "git.policy"]
    payload_format: Literal["beacon.aws-ebs/v1", "beacon.git-policy/v1"]
    coverage: Literal["supporting"] = "supporting"
    assertion: str
    max_age_seconds: int = Field(default=86400, ge=1, le=2592000)
    score_min: float = Field(default=1.0, ge=0, le=1, allow_inf_nan=False)
    noul_min: float = Field(default=1.0, ge=0, le=1, allow_inf_nan=False)
    confidence_min: float = Field(default=1.0, ge=0, le=1, allow_inf_nan=False)


def rule_for(objective: dict) -> ObjectiveRule | None:
    common = {"ao_id": objective["ao_id"], "objective_sha256": sha256_obj(objective)}
    if objective["ao_id"] == "CRY-07_A02":
        return ObjectiveRule(**common, rule_id="ebs-volume-encryption/v1", predicate="ebs_all_encrypted",
            plugin="aws.ebs.encryption", payload_format="beacon.aws-ebs/v1",
            assertion="Every EBS volume in the approved inventory and regions reports Encrypted=true. "
                      "This does not assess all storage, key authorization, algorithm strength, or data classification.")
    if objective["ao_id"] in {"GOV-02_A01", "GOV-02_A21", "IAC-02_A03", "IAC-02_A05"}:
        return ObjectiveRule(**common, rule_id=f"policy-content-{objective['ao_id']}/v1",
            predicate="policy_content_review", plugin="git.policy", payload_format="beacon.git-policy/v1",
            assertion="The approved policy text documents the activity or assigned roles named in the objective. "
                      "This does not demonstrate execution, skills, dissemination, or operating effectiveness.")
    return None


def rules_for(control_ref: str) -> list[dict]:
    return [{"rule": rule.model_dump(mode="json"), "rule_sha256": sha256_obj(rule.model_dump(mode="json"))}
            for objective in objectives(control_ref) if (rule := rule_for(objective)) is not None]


def _ebs_check(payload: dict, scope) -> tuple[str, list[str]]:
    rows, runs, regions = payload.get("volumes"), payload.get("region_runs"), payload.get("regions")
    expected_regions = set(scope.boundary.regions)
    # Sealed bytes are untrusted structure: reject wrong shapes before any set or count.
    if (not isinstance(rows, list) or not isinstance(runs, list) or not isinstance(regions, list)
            or any(not isinstance(region, str) for region in regions)
            or any(not isinstance(run, dict) or not isinstance(run.get("region"), str) for run in runs)):
        return "insufficient", ["malformed_inventory"]
    if (payload.get("errors") != [] or set(regions) != expected_regions
            or len(runs) != len(expected_regions)
            or {run["region"] for run in runs} != expected_regions
            or any(run.get("complete") is not True for run in runs)):
        return "insufficient", ["incomplete_region_inventory"]
    if not rows:
        return "insufficient", ["empty_population_requires_review"]
    ids = []
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("VolumeId"), str)
                or not isinstance(row.get("region"), str) or row["region"] not in expected_regions
                or type(row.get("Encrypted")) is not bool):
            return "insufficient", ["malformed_volume"]
        ids.append(f"{row['region']}/{row['VolumeId']}")
    if len(ids) != len(set(ids)):
        return "insufficient", ["duplicate_volume"]
    for run in runs:
        pages, count = run.get("pages"), run.get("volume_count")
        if (type(pages) is not int or pages < 1 or type(count) is not int
                or count != sum(row["region"] == run["region"] for row in rows)):
            return "insufficient", ["inventory_count_mismatch"]
    expected = getattr(scope, "parameters", {}).get("expected_ebs_volumes")
    if not isinstance(expected, list) or not expected or any(not isinstance(item, str) for item in expected):
        return "insufficient", ["approved_population_missing"]
    if len(expected) != len(set(expected)) or set(ids) != set(expected):
        return "insufficient", ["population_mismatch"]
    failed = [f"unencrypted:{row['region']}/{row['VolumeId']}" for row in rows if row["Encrypted"] is False]
    return ("supporting_fail", failed) if failed else ("supporting_pass", [])


def _policy_bound(payload: dict, parameters: dict, *, scope_id: str, control_ref: str) -> bool:
    policy = payload.get("policy")
    content = payload.get("content")
    if not isinstance(policy, dict) or not isinstance(content, str):
        return False
    control_refs, scope_refs = policy.get("control_refs"), policy.get("scope_refs")
    # Lists only: a string would turn membership into a substring test.
    if not isinstance(control_refs, list) or not isinstance(scope_refs, list):
        return False
    if sha256_bytes(content.encode("utf-8")) != payload.get("file_sha256"):
        return False
    sources = parameters.get("policy_sources", [])
    return (any(isinstance(source, dict) and source.get("commit") == payload.get("git_commit")
                and source.get("path") == payload.get("path")
                and source.get("file_sha256") == payload.get("file_sha256") for source in sources)
            and control_ref in control_refs and scope_id in scope_refs)


@locked
def evaluate_control(settings, *, scope_id: str, control_ref: str, judge=None) -> dict:
    scope = load_scope(settings, scope_id)
    parameters = getattr(scope, "parameters", {})
    if judge is not None and parameters.get("allow_external_judgment") is not True:
        fail("E_JEV", "scope does not authorize external judgment of its policy content")
    snapshot = verified_snapshot(settings)
    now = dt.datetime.now(dt.timezone.utc)
    rows = []
    for objective in objectives(control_ref):
        rule = rule_for(objective)
        row = {"ao_id": objective["ao_id"], "ppt": objective["ppt"], "statement": objective["statement"],
               "status": "no_rule", "objective_satisfied": False, "evidence": [], "reasons": [],
               "objective_sha256": sha256_obj(objective), "rule_sha256": None, "judgment": None}
        rows.append(row)
        if rule is None:
            row["reasons"] = ["reviewed_objective_rule_missing"]
            continue
        rule_body = rule.model_dump(mode="json")
        row["rule_sha256"] = sha256_obj(rule_body)
        row["assertion"] = rule.assertion
        if row["rule_sha256"] not in parameters.get("approved_rule_sha256", []):
            row.update(status="unapproved_rule", reasons=["rule_not_approved_in_scope"])
            continue
        # Only attempts for this control and scope compete. A record for another
        # control is not a newer attempt at this one.
        candidates = [record for record in snapshot.records if record.plugin == rule.plugin
                      and control_ref in record.scf_targets
                      and snapshot.payloads[record.evidence_id].get("scope_id") == scope_id]
        if not candidates:
            row.update(status="no_evidence", reasons=["matching_evidence_missing"])
            continue
        # A newer failure supersedes an older success; never cherry-pick a green run.
        record = candidates[-1]
        payload = snapshot.payloads[record.evidence_id]
        row["evidence"] = [{"evidence_id": record.evidence_id, "payload_sha256": record.payload_sha256,
                            "record_sha256": sha256_obj(record.to_dict())}]
        problems = list(eligibility(settings, record, payload, now=now, max_age_seconds=rule.max_age_seconds))
        if payload.get("format") != rule.payload_format:
            problems.append("payload_schema_mismatch")
        if problems:
            row.update(status="ineligible", reasons=problems)
            continue
        expires = parse_iso8601(payload["observed_at"]) + dt.timedelta(seconds=rule.max_age_seconds)
        row["expires_at"] = expires.isoformat()
        if rule.predicate == "ebs_all_encrypted":
            row["status"], row["reasons"] = _ebs_check(payload, scope)
        else:
            if not _policy_bound(payload, parameters, scope_id=scope_id, control_ref=control_ref):
                row.update(status="ineligible", reasons=["policy_binding_mismatch"])
                continue
            candidate = {"content": payload["content"], "evidence_sha256": record.payload_sha256,
                         "scope_sha256": scope.content_sha256(), "rule_sha256": row["rule_sha256"],
                         "ao_id": objective["ao_id"]}
            candidate["candidate_sha256"] = sha256_obj(candidate)
            row["candidate_sha256"] = candidate["candidate_sha256"]
            if judge is None:
                row.update(status="needs_review", reasons=["external_judgment_disabled", "human_review_required"])
            else:
                result = judge.judge(objective=objective, rule=rule_body, candidate=candidate)
                row["judgment"] = result
                # Jev and Bedrock are advisory. A judgment can order human review;
                # it never sets a supporting result.
                advisory = ("advisory_meets_thresholds"
                            if judgment_supports(result, candidate["candidate_sha256"], rule_body)
                            else "judgment_abstained_or_below_threshold")
                row.update(status="needs_review", reasons=[advisory, "human_review_required"])
    receipt = bind_observation_payload({"format": "beacon.evaluation/v2", "schema_version": 2,
        "receipt_id": uuid4().hex, "source": "beacon.evaluator", "mode": "evaluation",
        "evaluated_at": now.isoformat(), "catalog_sha256": CATALOG_SHA256,
        "workbook_sha256": WORKBOOK_SHA256, "control_ref": control_ref,
        "chain_head_sha256": sha256_obj(snapshot.records[-1].to_dict()) if snapshot.records else "0" * 64,
        "results": rows, "control_satisfied": False, "assurance_claim": False,
        "summary": {status: sum(row["status"] == status for row in rows) for status in sorted({row["status"] for row in rows})}}, scope)
    record = seal_payload(settings, plugin="beacon.evaluator", mode="evaluation", scf_targets=[control_ref], payload=receipt)
    create_checkpoint(settings)
    return {**receipt, "receipt_evidence_id": record.evidence_id, "receipt_sha256": record.payload_sha256}


@locked
def list_receipts(settings, *, scope_id: str | None = None) -> list[dict]:
    snapshot = verified_snapshot(settings)
    return [{"evidence_id": record.evidence_id, "payload_sha256": record.payload_sha256,
             "historical": True, "receipt": snapshot.payloads[record.evidence_id]}
            for record in snapshot.records if record.plugin == "beacon.evaluator" and record.mode == "evaluation"
            and snapshot.payloads[record.evidence_id].get("format") == "beacon.evaluation/v2"
            and (scope_id is None or snapshot.payloads[record.evidence_id].get("scope_id") == scope_id)]
