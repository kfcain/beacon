"""Evidence-set assessment, current views, operator review, and bounded refresh.

The workspace remains the serialized trust boundary. No model calls, arbitrary
commands, cloud remediation, or complete objective/control claims live here.
"""
from __future__ import annotations

import datetime as dt
import os
from uuid import uuid4

from beacon.assurance.admission import eligibility, verified_snapshot
from beacon.assurance.specs import load_spec
from beacon.assurance.validators import run_validator, validator_definition, validator_digest
from beacon.canonical import sha256_obj
from beacon.config import parse_iso8601
from beacon.crypto.witness import seal_payload, create_checkpoint
from beacon.errors import BeaconError, fail
from beacon.locking import locked
from beacon.plugins.spec import CollectContext
from beacon.scf.engine import collect_named
from beacon.scope.bind import bind_observation_payload
from beacon.scope.enforce import validate_plugin_scope
from beacon.scope.store import list_scopes, load_scope

ASSESSOR = "beacon.assessor"
REVIEWER = "beacon.review"
RUNNER = "beacon.assessment-run"
RECOLLECTABLE = frozenset({"aws.ebs.encryption"})


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def operator_identity() -> dict:
    """Local OS-account attribution, not proof that a human operated the account."""
    if not hasattr(os, "geteuid"):
        fail("E_REVIEW", "local operator review requires a POSIX effective UID")
    import pwd
    uid = os.geteuid()
    return {"actor_id": f"uid:{uid}", "account_name": pwd.getpwuid(uid).pw_name,
            "authentication": "local_os_account"}


def _scope(settings, scope_id):
    scope = load_scope(settings, scope_id)
    if scope.schema_version != 2:
        fail("E_ASSESSMENT", "evidence-set assessment requires an enrolled version-2 scope")
    return scope


def _selected(snapshot, scope, spec, criterion):
    source = validator_definition(criterion.validator_id)["plugin"]
    candidates = [record for record in snapshot.records
        if record.plugin == source and spec.control_ref in record.scf_targets
        and snapshot.payloads[record.evidence_id].get("scope_id") == scope.scope_id
        and (criterion.policy_path is None
             or snapshot.payloads[record.evidence_id].get("path") == criterion.policy_path)]
    # Newest attempt, even when it failed. Never merge convenient subsets of scans.
    return candidates[-1] if candidates else None


def _input_state(settings, snapshot, scope, spec, now):
    rows = []
    for criterion in spec.criteria:
        record = _selected(snapshot, scope, spec, criterion)
        row = {"criterion_id": criterion.criterion_id,
               "runtime_sha256": validator_digest(criterion.validator_id), "evidence": None, "eligibility": []}
        if record is not None:
            payload = snapshot.payloads[record.evidence_id]
            row["evidence"] = {"evidence_id": record.evidence_id, "payload_sha256": record.payload_sha256}
            row["eligibility"] = list(eligibility(settings, record, payload, now=now,
                                                  max_age_seconds=criterion.max_age_seconds))
        rows.append(row)
    # No chain head, receipt timestamps, or review records: the worker cannot trigger itself.
    return {"scope_sha256": scope.content_sha256(), "spec": spec.model_dump(mode="json"), "inputs": rows}


def _calculate(settings, snapshot, scope, spec, now):
    state = _input_state(settings, snapshot, scope, spec, now)
    rows = []
    for criterion, input_row in zip(spec.criteria, state["inputs"]):
        definition = validator_definition(criterion.validator_id)
        row = {"criterion_id": criterion.criterion_id, "assertion": criterion.assertion,
               "validator_id": criterion.validator_id, "validator_sha256": criterion.validator_sha256,
               "runtime_sha256": input_row["runtime_sha256"], "source": definition["plugin"],
               "method": definition["method"], "status": "insufficient", "evidence": [],
               "eligibility": {"eligible": False, "reasons": []}, "gaps": [], "findings": [], "coverage": {}}
        rows.append(row)
        if input_row["runtime_sha256"] != criterion.validator_sha256:
            row.update(status="unapproved_validator", gaps=["validator_implementation_changed"])
            continue
        record = _selected(snapshot, scope, spec, criterion)
        if record is None:
            row["gaps"] = ["matching_evidence_missing"]
            continue
        payload = snapshot.payloads[record.evidence_id]
        row["evidence"] = [{"evidence_id": record.evidence_id, "payload_sha256": record.payload_sha256,
                            "observed_at": payload.get("observed_at"), "path": payload.get("path")}]
        problems = list(input_row["eligibility"])
        if payload.get("format") != definition["format"]:
            problems.append("payload_schema_mismatch")
        row["eligibility"] = {"eligible": not problems, "reasons": sorted(set(problems))}
        # Even an incomplete run can contain a useful negative observation.
        # Keep it qualified by eligibility; it can never create a passing result.
        result = run_validator(criterion.validator_id, payload, scope, criterion, spec.control_ref)
        row.update(result)
        row["findings"] = [{**finding, "criterion_id": criterion.criterion_id,
                            "evidence_id": record.evidence_id, "eligible": not problems}
                           for finding in result["findings"]]
        row["gaps"] = sorted(set(row["gaps"] + problems))
        if problems:
            row["status"] = "ineligible"
        else:
            row["expires_at"] = (parse_iso8601(payload["observed_at"])
                                     + dt.timedelta(seconds=criterion.max_age_seconds)).isoformat()
        if spec.time_basis == "period":
            row["gaps"].append("operating_period_not_demonstrated")
            if row["status"] in {"supporting_pass", "needs_review"}:
                row["status"] = "insufficient"
    statuses = {row["status"] for row in rows}
    status = ("supporting_fail" if "supporting_fail" in statuses else
              "insufficient" if statuses - {"supporting_pass", "needs_review"} else
              "needs_review" if "needs_review" in statuses else "supporting_pass")
    return {"status": status, "results": rows, "input_sha256": sha256_obj(state),
            "gaps": [f"{row['criterion_id']}: {gap}" for row in rows for gap in row["gaps"]],
            "findings": [finding for row in rows for finding in row["findings"]]}


def _seal(settings, scope, *, source, mode, payload, targets):
    body = bind_observation_payload({**payload, "source": source, "mode": mode}, scope)
    record = seal_payload(settings, plugin=source, mode=mode, scf_targets=targets, payload=body)
    create_checkpoint(settings)
    return {**body, "receipt_evidence_id": record.evidence_id, "receipt_sha256": record.payload_sha256}


@locked
def evaluate_assessment(settings, *, scope_id: str, spec_sha256: str) -> dict:
    scope = _scope(settings, scope_id)
    spec = load_spec(settings, spec_sha256)
    if spec_sha256 not in scope.parameters.get("approved_assessment_sha256", []):
        fail("E_SPEC", "assessment specification is not approved in this scope")
    now = utcnow()
    snapshot = verified_snapshot(settings)
    result = _calculate(settings, snapshot, scope, spec, now)
    return _seal(settings, scope, source=ASSESSOR, mode="assessment", targets=[spec.control_ref], payload={
        "format": "beacon.assessment/v1", "schema_version": 1, "receipt_id": uuid4().hex,
        "spec_id": spec.spec_id, "spec_sha256": spec_sha256, "title": spec.title,
        "control_ref": spec.control_ref, "ao_id": spec.ao_id, "objective_sha256": spec.objective_sha256,
        "catalog_sha256": spec.catalog_sha256, "coverage": spec.coverage, "time_basis": spec.time_basis,
        "assessment_period": scope.parameters.get("assessment_period"), "evaluated_at": now.isoformat(),
        "objective_satisfied": False, "control_satisfied": False, "assurance_claim": False, **result})


def _records(snapshot, *, source, mode, format):
    for record in snapshot.records:
        body = snapshot.payloads[record.evidence_id]
        if (record.plugin == source and record.mode == mode and body.get("source") == source
                and body.get("mode") == mode and body.get("format") == format and body.get("schema_version") == 1):
            yield record, body


def _latest_assessments(snapshot, scope_id=None):
    latest = {}
    for record, body in _records(snapshot, source=ASSESSOR, mode="assessment", format="beacon.assessment/v1"):
        if scope_id is None or body.get("scope_id") == scope_id:
            key = (body.get("scope_id"), body.get("spec_sha256"))
            latest[key] = (record, body)
    return latest


@locked
def list_assessments(settings, *, scope_id: str | None = None) -> list[dict]:
    if scope_id is not None:
        _scope(settings, scope_id)
    snapshot = verified_snapshot(settings)
    now, result = utcnow(), []
    for (_, digest), (record, body) in _latest_assessments(snapshot, scope_id).items():
        scope = _scope(settings, body["scope_id"])
        reasons = []
        try:
            spec = load_spec(settings, digest)
            if digest not in scope.parameters.get("approved_assessment_sha256", []):
                reasons.append("specification_not_approved")
            calculated = _calculate(settings, snapshot, scope, spec, now)
            if calculated["input_sha256"] != body.get("input_sha256"):
                reasons.append("evidence_or_validator_changed_or_expired")
            elif any(body.get(key) != calculated[key] for key in ("status", "results", "gaps", "findings")):
                reasons.append("receipt_results_do_not_match_evidence")
            expected = {"spec_id": spec.spec_id, "title": spec.title, "control_ref": spec.control_ref,
                        "ao_id": spec.ao_id, "objective_sha256": spec.objective_sha256,
                        "catalog_sha256": spec.catalog_sha256, "coverage": spec.coverage, "time_basis": spec.time_basis}
            if any(body.get(key) != value for key, value in expected.items()) or any(
                    body.get(key) is not False for key in ("objective_satisfied", "control_satisfied", "assurance_claim")):
                reasons.append("receipt_claim_or_specification_mismatch")
        except BeaconError as exc:
            reasons.append(exc.code + ": " + str(exc))
        review = None
        for review_record, review_body in _records(snapshot, source=REVIEWER, mode="review", format="beacon.review/v1"):
            if (review_body.get("target_evidence_id") == record.evidence_id
                    and review_body.get("target_sha256") == record.payload_sha256
                    and review_body.get("input_sha256") == body.get("input_sha256")
                    and review_body.get("scope_id") == scope.scope_id
                    and review_body.get("actor_id") in scope.parameters.get("approved_reviewers", [])
                    and review_body.get("authentication") == "local_os_account"
                    and review_body.get("review_type") == "supporting_operator_attestation"
                    and review_body.get("decision") in {"accept", "reject"}
                    and isinstance(review_body.get("rationale"), str)
                    and 10 <= len(review_body["rationale"].strip()) <= 4000
                    and all(review_body.get(key) is False for key in ("objective_satisfied", "control_satisfied", "assurance_claim"))):
                review = {**review_body, "evidence_id": review_record.evidence_id, "current": not reasons}
        result.append({"receipt": {**body, "receipt_evidence_id": record.evidence_id,
                                   "receipt_sha256": record.payload_sha256},
                       "evidence_id": record.evidence_id, "current": not reasons,
                       "invalidation_reasons": reasons, "review": review})
    return result


def review_queue(settings, *, scope_id: str | None = None) -> list[dict]:
    return [item for item in list_assessments(settings, scope_id=scope_id)
            if not item["current"] or item["receipt"].get("status") not in {"supporting_pass", "needs_review"}
            or not item["review"] or item["review"].get("decision") != "accept"]


@locked
def record_review(settings, *, receipt_evidence_id: str, decision: str, rationale: str) -> dict:
    if decision not in {"accept", "reject"}:
        fail("E_REVIEW", "decision must be accept or reject")
    if not isinstance(rationale, str) or not 10 <= len(rationale.strip()) <= 4000:
        fail("E_REVIEW", "review requires a rationale of 10–4000 characters, including source citations")
    snapshot = verified_snapshot(settings)
    target = next(((record, body) for record, body in _records(snapshot, source=ASSESSOR,
        mode="assessment", format="beacon.assessment/v1") if record.evidence_id == receipt_evidence_id), None)
    if target is None:
        fail("E_REVIEW", "target is not a verified assessment receipt")
    record, body = target
    scope = _scope(settings, body["scope_id"])
    identity = operator_identity()
    if identity["actor_id"] not in scope.parameters.get("approved_reviewers", []):
        fail("E_REVIEW", "this local OS account is not an approved reviewer for the scope")
    if decision == "accept":
        item = next((item for item in list_assessments(settings, scope_id=scope.scope_id)
                     if item["evidence_id"] == receipt_evidence_id), None)
        if (item is None or not item["current"] or body.get("status") not in {"supporting_pass", "needs_review"}
                or body.get("gaps") or body.get("findings")):
            fail("E_REVIEW", "cannot accept an outdated assessment, failed check, or incomplete evidence set")
    return _seal(settings, scope, source=REVIEWER, mode="review", targets=[body["control_ref"]], payload={
        "format": "beacon.review/v1", "schema_version": 1, "review_id": uuid4().hex,
        "target_evidence_id": record.evidence_id, "target_sha256": record.payload_sha256,
        "input_sha256": body["input_sha256"], "spec_sha256": body["spec_sha256"],
        "reviewed_at": utcnow().isoformat(), "decision": decision, "rationale": rationale.strip(),
        **identity, "review_type": "supporting_operator_attestation",
        "objective_satisfied": False, "control_satisfied": False, "assurance_claim": False})


def _collection_needed(result):
    actions = set()
    trigger_gaps = {"matching_evidence_missing", "evidence_stale", "collection_incomplete", "not_live",
                    "population_missing", "incomplete_region_inventory", "collection_errors"}
    negative_sources = {row["source"] for row in result["results"] if row["findings"]}
    for row in result["results"]:
        if (row["source"] in RECOLLECTABLE and row["source"] not in negative_sources
                and row["status"] in {"insufficient", "ineligible"} and trigger_gaps.intersection(row["gaps"])):
            actions.add(row["source"])
    return actions


@locked
def collection_plan(settings, *, scope_id: str) -> dict:
    scope = _scope(settings, scope_id)
    snapshot, now, wanted, negative = verified_snapshot(settings), utcnow(), set(), set()
    for digest in scope.parameters.get("approved_assessment_sha256", []):
        spec = load_spec(settings, digest)
        calculated = _calculate(settings, snapshot, scope, spec, now)
        wanted.update(_collection_needed(calculated))
        negative.update(row["source"] for row in calculated["results"] if row["findings"])
    wanted.difference_update(negative)
    allowed = set(scope.parameters.get("allowed_assessment_collectors", []))
    return {"scope_id": scope_id, "scope_sha256": scope.content_sha256(), "actions": [
        {"plugin": plugin, "control_ref": "CRY-07", "live": True, "authorized": plugin in allowed,
         "reason": "refresh_missing_stale_or_incomplete_evidence"} for plugin in sorted(wanted)]}


def _run_record(settings, scope, **fields):
    return _seal(settings, scope, source=RUNNER, mode="assessment_run", targets=[], payload={
        "format": "beacon.assessment-run/v1", "schema_version": 1, "run_id": uuid4().hex,
        "recorded_at": utcnow().isoformat(), **fields})


@locked
def refresh_assessments(settings, *, scope_id: str, collect_missing: bool = False) -> dict:
    """One reconciliation pass; at most one EBS recollection, with a durable cooldown.

    A CLI watch can repeat this pass. A clock/event change creates a new receipt;
    unchanged inputs never append another assessment. No automation is installed.
    """
    scope = _scope(settings, scope_id)
    allowed = set(scope.parameters.get("allowed_assessment_collectors", [])) & RECOLLECTABLE
    if collect_missing and not allowed:
        fail("E_SCOPE", "live refresh requires scope-approved assessment collectors")
    collections = []
    if collect_missing:
        # Recompute the plan inside the same serialized scope; never execute a supplied plan.
        plan = collection_plan(settings, scope_id=scope_id)
        for action in plan["actions"][:1]:
            plugin = action["plugin"]
            if plugin not in allowed:
                continue
            validate_plugin_scope(scope, plugin)
            snapshot = verified_snapshot(settings)
            attempts = [body for _, body in _records(snapshot, source=RUNNER, mode="assessment_run",
                format="beacon.assessment-run/v1") if body.get("scope_id") == scope_id
                and body.get("action") == "collection_started" and body.get("plugin") == plugin]
            cooldown = scope.parameters.get("assessment_recollection_seconds", 3600)
            if attempts and (utcnow() - parse_iso8601(attempts[-1]["recorded_at"])).total_seconds() < cooldown:
                collections.append({"plugin": plugin, "status": "cooldown", "cooldown_seconds": cooldown})
                continue
            # Persist before network access so crashes cannot cause a tight retry loop.
            started = _run_record(settings, scope, action="collection_started", plugin=plugin)
            try:
                output = collect_named(settings, plugin, CollectContext(target="CRY-07", live=True), scope_id=scope_id)
                collections.append({"plugin": plugin, "status": "completed" if output.get("ok") else "failed", "result": output})
            except Exception as exc:
                # A failed new attempt supersedes old success even when a connector raised before sealing.
                failure = bind_observation_payload({"source": plugin, "mode": "live_failed", "ok": False,
                    "format": "beacon.aws-ebs/v1", "cloud": "aws", "collection_complete": False,
                    "observed_at": utcnow().isoformat(), "identity": {}, "regions": list(scope.boundary.regions),
                    "errors": [{"code": type(exc).__name__}], "volumes": [], "region_runs": []}, scope)
                seal_payload(settings, plugin=plugin, mode="live_failed", scf_targets=["CRY-07"], payload=failure)
                create_checkpoint(settings)
                collections.append({"plugin": plugin, "status": "failed", "code": type(exc).__name__})
            _run_record(settings, scope, action="collection_finished", plugin=plugin,
                        started_evidence_id=started["receipt_evidence_id"], status=collections[-1]["status"])
    snapshot, now = verified_snapshot(settings), utcnow()
    latest = _latest_assessments(snapshot, scope_id)
    evaluations, unchanged = [], 0
    for digest in scope.parameters.get("approved_assessment_sha256", []):
        spec = load_spec(settings, digest)
        fingerprint = sha256_obj(_input_state(settings, snapshot, scope, spec, now))
        previous = latest.get((scope_id, digest))
        if previous is not None and previous[1].get("input_sha256") == fingerprint:
            unchanged += 1
        else:
            evaluations.append(evaluate_assessment(settings, scope_id=scope_id, spec_sha256=digest))
    return {"scope_id": scope_id, "evaluations": evaluations, "collections": collections, "unchanged": unchanged}
