"""Adversarial evidence-set, review, and refresh regressions; no cloud calls."""
from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path

import pytest

from beacon.assurance import assessments
from beacon.assurance.assessments import (
    bounded_live_collection, collection_plan, evaluate_assessment, list_assessments, record_review,
    refresh_assessments, review_queue,
)
from beacon.assurance.policy import PolicyObject
from beacon.assurance.specs import draft_ebs_spec, import_spec, load_spec
from beacon.assurance.validators import validator_digest
from beacon.canonical import dumps, sha256_bytes
from beacon.config import load_settings
from beacon.crypto.witness import create_checkpoint, load_records, seal_payload
from beacon.errors import BeaconError
from beacon.scope.bind import bind_observation_payload
from beacon.scope.store import import_scope, new_scope_document

KEY = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111"
OTHER_KEY = "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222"
ACTOR = {"actor_id": "uid:4242", "account_name": "reviewer", "authentication": "local_os_account"}


def enroll(settings, *, criteria=("encryption", "approved_keys"), approved=True,
           scope_id="assessment-test", sources=(), spec=None, **parameters):
    spec = copy.deepcopy(spec) if spec is not None else draft_ebs_spec()
    spec["criteria"] = [row for row in spec["criteria"] if row["criterion_id"] in criteria]
    imported = import_spec(settings, json.dumps(spec))
    body = new_scope_document(scope_id).canonical_body()
    body.update(schema_version=2, allowed_evidence_kinds=["cloud_inspector", "policy"],
                boundary={"accounts": ["123456789012"], "regions": ["us-east-1"],
                          "systems": ["policy-service"]},
                parameters={
                    "approved_assessment_sha256": [imported["spec_sha256"]] if approved else [],
                    "expected_ebs_volumes": ["us-east-1/vol-0123", "us-east-1/vol-0456"],
                    "approved_kms_key_arns": [KEY], "approved_reviewers": [ACTOR["actor_id"]],
                    "policy_sources": list(sources), **parameters})
    return import_scope(settings, json.dumps(body)), imported["spec_sha256"]


def ebs_payload():
    return {"format": "beacon.aws-ebs/v1", "source": "aws.ebs.encryption", "cloud": "aws",
            "mode": "live", "ok": True, "collection_complete": True,
            "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "identity": {"account_id": "123456789012", "partition": "aws",
                         "arn": "arn:aws:iam::123456789012:role/collector", "system_id": "policy-service"},
            "regions": ["us-east-1"], "errors": [],
            "volumes": [{"VolumeId": volume, "Encrypted": True, "region": "us-east-1", "KmsKeyId": KEY}
                        for volume in ("vol-0123", "vol-0456")],
            "region_runs": [{"region": "us-east-1", "complete": True, "pages": 2, "volume_count": 2}]}


def seal(settings, scope, body):
    record = seal_payload(settings, plugin=body["source"], mode=body["mode"], scf_targets=["CRY-07"],
                          payload=bind_observation_payload(body, scope))
    create_checkpoint(settings)
    return record


def assess(settings, scope, digest):
    return evaluate_assessment(settings, scope_id=scope.scope_id, spec_sha256=digest)


def policy_source(*, path="policies/encryption.json", scope_id="assessment-test"):
    policy = PolicyObject.model_validate({"policy_id": "encryption-policy", "title": "Encryption policy",
        "people": [{"role": "owner", "name": "Security team"}],
        "process": [{"id": "encryption", "summary": "Production volumes use approved encryption keys."}],
        "control_refs": ["CRY-07"], "scope_refs": [scope_id]})
    raw = dumps(policy.canonical_body())
    source = {"path": path, "commit": "a" * 40, "file_sha256": sha256_bytes(raw), "system_id": "policy-service"}
    payload = {"format": "beacon.git-policy/v1", "source": "git.policy", "mode": "live",
        "ok": True, "collection_complete": True, "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "identity": {"system_id": source["system_id"]}, "path": path, "git_commit": source["commit"],
        "file_sha256": source["file_sha256"], "content": raw.decode(), "policy": policy.canonical_body()}
    return source, payload


@pytest.fixture(autouse=True)
def no_accidental_cloud_calls(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("tests must explicitly replace live collection")
    monkeypatch.setattr(assessments, "collect_named", unexpected)
    monkeypatch.setattr(assessments, "operator_identity", lambda: dict(ACTOR))


def test_spec_import_does_not_approve_execution(initialized):
    settings = load_settings()
    scope, digest = enroll(settings, approved=False)
    seal(settings, scope, ebs_payload())
    before = len(load_records(settings))
    with pytest.raises(BeaconError, match="not approved"):
        assess(settings, scope, digest)
    assert len(load_records(settings)) == before


def test_stored_spec_tampering_is_detected(initialized):
    settings = load_settings()
    _, digest = enroll(settings)
    path = settings.home / "assessment-specs" / f"{digest}.json"
    altered = json.loads(path.read_bytes())
    altered["title"] = "Changed after enrollment"
    path.write_text(json.dumps(altered))
    with pytest.raises(BeaconError, match="digest"):
        load_spec(settings, digest)


@pytest.mark.parametrize("change", [
    lambda spec: spec["criteria"][0].update(validator_id="python:os.system"),
    lambda spec: spec.update(objective_sha256="0" * 64),
    lambda spec: spec.update(catalog_sha256="0" * 64),
    lambda spec: spec["criteria"].append(copy.deepcopy(spec["criteria"][0])),
    lambda spec: spec["criteria"][2].update(policy_path="../secrets.json"),
])
def test_untrusted_spec_cannot_select_code_or_rewrite_requirement(initialized, change):
    settings = load_settings()
    spec = draft_ebs_spec()
    change(spec)
    with pytest.raises(BeaconError):
        import_spec(settings, json.dumps(spec))


def test_changed_validator_implementation_invalidates_prior_approval(initialized, monkeypatch):
    settings = load_settings()
    scope, digest = enroll(settings)
    seal(settings, scope, ebs_payload())
    assert assess(settings, scope, digest)["status"] == "supporting_pass"
    original = Path.read_bytes

    def altered(path):
        contents = original(path)
        return contents + b"\n# changed implementation\n" if path.name == "validators.py" else contents

    monkeypatch.setattr(Path, "read_bytes", altered)
    current = list_assessments(settings, scope_id=scope.scope_id)[0]
    assert current["current"] is False
    result = assess(settings, scope, digest)
    assert {row["status"] for row in result["results"]} == {"unapproved_validator"}
    assert result["status"] == "insufficient"


def test_exact_population_and_keys_support_only_the_narrow_assessment(initialized):
    settings = load_settings()
    scope, digest = enroll(settings)
    record = seal(settings, scope, ebs_payload())
    result = assess(settings, scope, digest)
    assert result["status"] == "supporting_pass"
    assert not result["gaps"] and not result["findings"]
    assert all(row["evidence"][0]["payload_sha256"] == record.payload_sha256 for row in result["results"])
    assert not any(result[key] for key in ("objective_satisfied", "control_satisfied", "assurance_claim"))


@pytest.mark.parametrize("change,gap", [
    (lambda body: body["volumes"].pop(), "population_missing"),
    (lambda body: body["volumes"].append(copy.deepcopy(body["volumes"][0])), "duplicate_volume"),
    (lambda body: body["volumes"][0].update(VolumeId="vol-other"), "population_unexpected"),
    (lambda body: body["region_runs"][0].update(pages=True), "incomplete_region_inventory"),
    (lambda body: body["volumes"][0].update(Encrypted="true"), "malformed_volume"),
    (lambda body: body.update(observed_at="2001-01-01T00:00:00Z"), "evidence_stale"),
    (lambda body: body["identity"].update(account_id="999999999999"), "account_out_of_boundary"),
    (lambda body: body.update(format="untrusted.schema/v1"), "payload_schema_mismatch"),
    (lambda body: body["volumes"][0].update(KmsKeyId="alias/approved"), "key_arn_missing_or_malformed"),
    (lambda body: body.update(identity=[]), "source_identity_missing"),
])
def test_incomplete_or_malformed_evidence_never_passes(initialized, change, gap):
    settings = load_settings()
    scope, digest = enroll(settings)
    body = ebs_payload()
    change(body)
    seal(settings, scope, body)
    result = assess(settings, scope, digest)
    assert result["status"] == "insufficient"
    assert any(gap in value for value in result["gaps"])


def test_partial_scan_preserves_observed_failure_and_blocks_automatic_retry(initialized):
    settings = load_settings()
    scope, digest = enroll(settings, allowed_assessment_collectors=["aws.ebs.encryption"])
    body = ebs_payload()
    body.update(ok=False, collection_complete=False, mode="live_failed", errors=[{"code": "AccessDenied"}])
    body["volumes"][0]["Encrypted"] = False
    seal(settings, scope, body)
    result = assess(settings, scope, digest)
    assert result["status"] == "insufficient"
    failures = [row for row in result["findings"] if row["code"] == "unencrypted_volume"]
    assert failures and all(row["eligible"] is False for row in failures)
    assert collection_plan(settings, scope_id=scope.scope_id)["actions"] == []


def test_new_failed_attempt_supersedes_old_pass(initialized):
    settings = load_settings()
    scope, digest = enroll(settings)
    good = seal(settings, scope, ebs_payload())
    assert assess(settings, scope, digest)["status"] == "supporting_pass"
    failed = ebs_payload()
    failed.update(mode="live_failed", ok=False, collection_complete=False)
    bad = seal(settings, scope, failed)
    result = assess(settings, scope, digest)
    assert result["status"] == "insufficient"
    assert all(row["evidence"][0]["evidence_id"] == bad.evidence_id != good.evidence_id for row in result["results"])


def test_evidence_from_other_enrolled_scope_is_not_reused(initialized):
    settings = load_settings()
    scope, digest = enroll(settings)
    other, _ = enroll(settings, scope_id="other-assessment")
    seal(settings, other, ebs_payload())
    result = assess(settings, scope, digest)
    assert all(row["gaps"] == ["matching_evidence_missing"] for row in result["results"])


def test_one_failed_criterion_cannot_be_averaged_into_a_pass(initialized):
    settings = load_settings()
    scope, digest = enroll(settings)
    body = ebs_payload()
    body["volumes"][1]["KmsKeyId"] = OTHER_KEY
    seal(settings, scope, body)
    result = assess(settings, scope, digest)
    by_id = {row["criterion_id"]: row for row in result["results"]}
    assert by_id["encryption"]["status"] == "supporting_pass"
    assert by_id["approved_keys"]["status"] == result["status"] == "supporting_fail"
    assert result["findings"][0]["code"] == "unapproved_key"


def test_snapshot_cannot_demonstrate_a_whole_operating_period(initialized):
    settings = load_settings()
    scope, digest = enroll(settings, spec=draft_ebs_spec(time_basis="period"))
    seal(settings, scope, ebs_payload())
    result = assess(settings, scope, digest)
    assert result["status"] == "insufficient"
    assert all("operating_period_not_demonstrated" in row["gaps"] for row in result["results"])


@pytest.mark.parametrize("change", [
    lambda body: body["policy"].update(title="Invented normalized policy"),
    lambda body: body.update(content=body["content"] + "\n"),
    lambda body: body.update(git_commit="b" * 40),
    lambda body: body.update(file_sha256="0" * 64),
])
def test_policy_review_binds_exact_approved_bytes_and_source(initialized, change):
    settings = load_settings()
    source, body = policy_source()
    scope, digest = enroll(settings, criteria=("policy",), sources=[source])
    change(body)
    seal(settings, scope, body)
    result = assess(settings, scope, digest)
    assert result["status"] == "insufficient"
    assert result["results"][0]["gaps"] == ["policy_binding_mismatch"]


def test_newer_document_at_another_path_does_not_mask_required_policy(initialized):
    settings = load_settings()
    source, policy = policy_source()
    other_source, other_policy = policy_source(path="policies/other.json")
    scope, digest = enroll(settings, criteria=("policy",), sources=[source, other_source])
    first = seal(settings, scope, policy)
    seal(settings, scope, other_policy)
    result = assess(settings, scope, digest)
    assert result["status"] == "needs_review"
    assert result["results"][0]["evidence"][0]["evidence_id"] == first.evidence_id


def test_document_is_reviewed_without_automatic_approval_or_self_trigger(initialized):
    settings = load_settings()
    source, body = policy_source()
    scope, _ = enroll(settings, criteria=("policy",), sources=[source])
    seal(settings, scope, body)
    refreshed = refresh_assessments(settings, scope_id=scope.scope_id)
    receipt = refreshed["evaluations"][0]
    assert receipt["status"] == "needs_review"
    assert len(review_queue(settings, scope_id=scope.scope_id)) == 1
    review = record_review(settings, receipt_evidence_id=receipt["receipt_evidence_id"], decision="accept",
                           rationale="Reviewed policies/encryption.json, process encryption; obligations match scope.")
    assert review["actor_id"] == ACTOR["actor_id"] and review["authentication"] == "local_os_account"
    assert review["target_sha256"] == receipt["receipt_sha256"]
    assert not any(review[key] for key in ("objective_satisfied", "control_satisfied", "assurance_claim"))
    assert review_queue(settings, scope_id=scope.scope_id) == []
    count = len(load_records(settings))
    repeated = refresh_assessments(settings, scope_id=scope.scope_id)
    assert repeated["unchanged"] == 1 and repeated["evaluations"] == []
    assert len(load_records(settings)) == count


def test_unapproved_reviewer_cannot_attest(initialized, monkeypatch):
    settings = load_settings()
    scope, digest = enroll(settings)
    seal(settings, scope, ebs_payload())
    receipt = assess(settings, scope, digest)
    monkeypatch.setattr(assessments, "operator_identity", lambda: {**ACTOR, "actor_id": "uid:99"})
    with pytest.raises(BeaconError, match="not an approved reviewer"):
        record_review(settings, receipt_evidence_id=receipt["receipt_evidence_id"], decision="accept",
                      rationale="Reviewed the observed source records.")


def test_review_target_must_be_a_verified_assessment(initialized):
    settings = load_settings()
    scope, _ = enroll(settings)
    record = seal(settings, scope, ebs_payload())
    with pytest.raises(BeaconError, match="not a verified assessment"):
        record_review(settings, receipt_evidence_id=record.evidence_id, decision="accept",
                      rationale="Attempted acceptance of raw evidence.")


def test_stale_assessment_review_is_invalidated_and_refresh_runs_once(initialized, monkeypatch):
    settings = load_settings()
    scope, digest = enroll(settings)
    body = ebs_payload()
    seal(settings, scope, body)
    receipt = assess(settings, scope, digest)
    record_review(settings, receipt_evidence_id=receipt["receipt_evidence_id"], decision="accept",
                  rationale="The two evidence rows match the approved inventory and key list.")
    monkeypatch.setattr(assessments, "utcnow", lambda: dt.datetime.fromisoformat(body["observed_at"]) + dt.timedelta(days=2))
    stale = list_assessments(settings, scope_id=scope.scope_id)[0]
    assert not stale["current"] and not stale["review"]["current"]
    with pytest.raises(BeaconError, match="outdated"):
        record_review(settings, receipt_evidence_id=receipt["receipt_evidence_id"], decision="accept",
                      rationale="Cannot override expired observations.")
    refreshed = refresh_assessments(settings, scope_id=scope.scope_id)
    assert len(refreshed["evaluations"]) == 1
    assert refreshed["evaluations"][0]["status"] == "insufficient"
    assert refresh_assessments(settings, scope_id=scope.scope_id)["unchanged"] == 1


def test_newer_receipt_cannot_inherit_prior_review(initialized):
    settings = load_settings()
    scope, digest = enroll(settings)
    seal(settings, scope, ebs_payload())
    first = assess(settings, scope, digest)
    record_review(settings, receipt_evidence_id=first["receipt_evidence_id"], decision="accept",
                  rationale="Checked the first receipt and inventory evidence.")
    seal(settings, scope, ebs_payload())
    assert list_assessments(settings, scope_id=scope.scope_id)[0]["current"] is False
    second = refresh_assessments(settings, scope_id=scope.scope_id)["evaluations"][0]
    current = list_assessments(settings, scope_id=scope.scope_id)[0]
    assert current["receipt"]["receipt_evidence_id"] == second["receipt_evidence_id"]
    assert current["review"] is None
    with pytest.raises(BeaconError, match="outdated"):
        record_review(settings, receipt_evidence_id=first["receipt_evidence_id"], decision="accept",
                      rationale="Cannot accept an assessment replaced by a newer receipt.")


def test_missing_evidence_plan_does_not_grant_collection_permission(initialized, monkeypatch):
    settings = load_settings()
    scope, _ = enroll(settings)
    calls = []
    monkeypatch.setattr(assessments, "collect_named", lambda *args, **kwargs: calls.append(kwargs))
    plan = collection_plan(settings, scope_id=scope.scope_id)
    assert len(plan["actions"]) == 1 and not plan["actions"][0]["authorized"]
    with pytest.raises(BeaconError, match="scope-approved"):
        refresh_assessments(settings, scope_id=scope.scope_id, collect_missing=True)
    assert calls == []


def test_collection_failure_is_durable_and_cooldown_survives_new_settings(initialized, monkeypatch):
    settings = load_settings()
    scope, _ = enroll(settings, allowed_assessment_collectors=["aws.ebs.encryption"], assessment_recollection_seconds=60)
    calls = []

    def broken(current_settings, plugin, context, *, scope_id):
        calls.append(plugin)
        # The start record must precede the cloud request, including abrupt failure.
        records = load_records(current_settings)
        start = json.loads((current_settings.evidence_dir / f"{records[-1].evidence_id}.json").read_bytes())
        assert start["action"] == "collection_started"
        assert context.live is True and scope_id == scope.scope_id
        raise RuntimeError("secret must never be persisted in a failure receipt")

    monkeypatch.setattr(assessments, "collect_named", broken)
    first = refresh_assessments(settings, scope_id=scope.scope_id, collect_missing=True)
    assert calls == ["aws.ebs.encryption"]  # Two criteria share one bounded collection.
    assert first["collections"][0]["status"] == "failed"
    assert first["evaluations"][0]["status"] == "insufficient"
    assert "secret must never" not in json.dumps(first)
    second = refresh_assessments(load_settings(), scope_id=scope.scope_id, collect_missing=True)
    assert second["collections"][0]["status"] == "cooldown"
    assert second["unchanged"] == 1 and len(calls) == 1
    now = dt.datetime.now(dt.timezone.utc)
    monkeypatch.setattr(assessments, "utcnow", lambda: now + dt.timedelta(seconds=61))
    third = refresh_assessments(load_settings(), scope_id=scope.scope_id, collect_missing=True)
    assert third["collections"][0]["status"] == "failed" and len(calls) == 2



def _remote_collect(surface, enrolled_scope_id, **overrides):
    body = {"plugin": "aws.ebs.encryption", "scope_id": enrolled_scope_id, "live": True, **overrides}
    body = {key: value for key, value in body.items() if value is not None}
    if surface == "mcp":
        from beacon.mcp.server import call_tool
        return call_tool("beacon_collect", body)
    from fastapi.testclient import TestClient
    from beacon.gui.app import create_app
    return TestClient(create_app(), headers={"X-Beacon-Request": "1"}).post("/api/collect", json=body).json()


@pytest.mark.parametrize("surface", ["mcp", "web"])
@pytest.mark.parametrize("body", [
    {},                                          # the scope does not approve any collector
    {"plugin": "aws.inspector"},                 # not an assessment collector
    {"scope_id": None},                          # live collection must name a scope
    {"plugin": None, "target": "CRY-07"},        # no target-wide or collect-all live runs
])
def test_remote_live_collection_needs_scope_approval(initialized, surface, body):
    settings = load_settings()
    scope, _ = enroll(settings)
    # The autouse fixture fails the test if any live collector starts.
    assert _remote_collect(surface, scope.scope_id, **body)["code"] == "E_SCOPE"


def test_remote_live_collection_shares_the_refresh_cooldown(initialized, monkeypatch):
    settings = load_settings()
    scope, _ = enroll(settings, allowed_assessment_collectors=["aws.ebs.encryption"],
                      assessment_recollection_seconds=60)
    calls = []

    def collect(current_settings, plugin, context, *, scope_id):
        calls.append((plugin, context.live, context.target, scope_id))
        return {"ok": True, "plugin": plugin, "mode": "live"}

    monkeypatch.setattr(assessments, "collect_named", collect)
    assert _remote_collect("mcp", scope.scope_id)["status"] == "completed"
    assert _remote_collect("web", scope.scope_id)["status"] == "cooldown"
    refreshed = refresh_assessments(load_settings(), scope_id=scope.scope_id, collect_missing=True)
    assert refreshed["collections"][0]["status"] == "cooldown"
    assert calls == [("aws.ebs.encryption", True, "CRY-07", scope.scope_id)]


def test_error_after_the_collector_sealed_does_not_hide_its_record(initialized, monkeypatch):
    settings = load_settings()
    scope, _ = enroll(settings, allowed_assessment_collectors=["aws.ebs.encryption"])

    def sealed_then_failed(current_settings, plugin, context, *, scope_id):
        seal(current_settings, scope, ebs_payload())
        raise RuntimeError("remote publish failed after the local seal")

    monkeypatch.setattr(assessments, "collect_named", sealed_then_failed)
    outcome = bounded_live_collection(settings, scope_id=scope.scope_id, plugin="aws.ebs.encryption")
    assert outcome["status"] == "failed_after_seal"
    ebs = [record for record in load_records(settings) if record.plugin == "aws.ebs.encryption"]
    assert [record.mode for record in ebs] == ["live"]


def _cli_review(receipt_id, *, confirmation=None):
    from click.testing import CliRunner
    from beacon.cli import main
    return CliRunner().invoke(main, ["review-assessment", "--receipt", receipt_id, "--decision", "accept",
                                     "--rationale", "Checked the sealed inventory and key list."],
                              input=None if confirmation is None else confirmation + "\n")


def _reviews(settings):
    return [record for record in load_records(settings) if record.plugin == "beacon.review"]


def test_cli_review_refuses_scripts_and_needs_typed_confirmation(initialized, monkeypatch):
    import beacon.cli as cli
    settings = load_settings()
    scope, digest = enroll(settings)
    seal(settings, scope, ebs_payload())
    receipt_id = assess(settings, scope, digest)["receipt_evidence_id"]
    # CliRunner is not a terminal, like an agent's tool call or a pipeline.
    refused = _cli_review(receipt_id)
    assert refused.exit_code != 0 and "interactive terminal" in refused.output
    monkeypatch.setattr(cli, "_interactive_terminal", lambda: True)
    mistyped = _cli_review(receipt_id, confirmation="not-the-receipt")
    assert mistyped.exit_code != 0 and "did not match" in mistyped.output
    assert _reviews(settings) == []
    confirmed = _cli_review(receipt_id, confirmation=receipt_id)
    assert confirmed.exit_code == 0, confirmed.output
    assert len(_reviews(settings)) == 1


def test_operator_identity_without_a_passwd_entry_keeps_the_uid(monkeypatch):
    import os
    import pwd
    monkeypatch.undo()  # use the real function, not the autouse test identity
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: (_ for _ in ()).throw(KeyError(uid)))
    identity = assessments.operator_identity()
    assert identity == {"actor_id": f"uid:{os.geteuid()}", "account_name": None,
                        "authentication": "local_os_account"}
