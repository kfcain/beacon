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
from beacon.canonical import sha256_obj
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
    rows, runs = payload.get("volumes"), payload.get("region_runs")
    expected_regions = set(scope.boundary.regions)
    if (not isinstance(rows, list) or not isinstance(runs, list) or payload.get("errors")
            or set(payload.get("regions", [])) != expected_regions
            or len(runs) != len(expected_regions)
            or {run.get("region") for run in runs} != expected_regions
            or any(run.get("complete") is not True for run in runs)):
        return "insufficient", ["incomplete_region_inventory"]
    if not rows:
        return "insufficient", ["empty_population_requires_review"]
    ids = []
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("VolumeId"), str)
                or row.get("region") not in expected_regions or type(row.get("Encrypted")) is not bool):
            return "insufficient", ["malformed_volume"]
        ids.append(f"{row['region']}/{row['VolumeId']}")
    if len(ids) != len(set(ids)):
        return "insufficient", ["duplicate_volume"]
    for run in runs:
        if run.get("volume_count") != sum(row["region"] == run["region"] for row in rows) or run.get("pages", 0) < 1:
            return "insufficient", ["inventory_count_mismatch"]
    expected = getattr(scope, "parameters", {}).get("expected_ebs_volumes")
    if not isinstance(expected, list) or not expected or any(not isinstance(item, str) for item in expected):
        return "insufficient", ["approved_population_missing"]
    if len(expected) != len(set(expected)) or set(ids) != set(expected):
        return "insufficient", ["population_mismatch"]
    failed = [f"unencrypted:{row['region']}/{row['VolumeId']}" for row in rows if row["Encrypted"] is False]
    return ("supporting_fail", failed) if failed else ("supporting_pass", [])


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
        candidates = [record for record in snapshot.records if record.plugin == rule.plugin
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
        if control_ref not in record.scf_targets:
            problems.append("control_binding_mismatch")
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
            policy = payload.get("policy", {})
            sources = parameters.get("policy_sources", [])
            if (not any(isinstance(source, dict) and source.get("commit") == payload.get("git_commit")
                        and source.get("path") == payload.get("path")
                        and source.get("file_sha256") == payload.get("file_sha256") for source in sources)
                    or control_ref not in policy.get("control_refs", []) or scope_id not in policy.get("scope_refs", [])):
                row.update(status="ineligible", reasons=["policy_binding_mismatch"])
                continue
            candidate = {"content": payload["content"], "evidence_sha256": record.payload_sha256,
                         "scope_sha256": scope.content_sha256(), "rule_sha256": row["rule_sha256"],
                         "ao_id": objective["ao_id"]}
            candidate["candidate_sha256"] = sha256_obj(candidate)
            row["candidate_sha256"] = candidate["candidate_sha256"]
            if judge is None:
                row.update(status="needs_review", reasons=["external_judgment_disabled"])
            else:
                result = judge.judge(objective=objective, rule=rule_body, candidate=candidate)
                row["judgment"] = result
                supported = judgment_supports(result, candidate["candidate_sha256"], rule_body)
                row.update(status="supporting_pass" if supported else "needs_review",
                           reasons=[] if supported else ["judgment_abstained_or_below_threshold"])
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
            for record in snapshot.records if record.plugin == "beacon.evaluator"
            and (scope_id is None or snapshot.payloads[record.evidence_id].get("scope_id") == scope_id)]
