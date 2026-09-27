"""Scoped EBS pagination, negative outcomes, and historical receipt binding."""
import datetime as dt
import json
from dataclasses import replace

import boto3
from botocore.stub import Stubber
import pytest

from beacon.assurance.evaluation import evaluate_control, rules_for, list_receipts
from beacon.canonical import dumps
from beacon.config import load_settings
from beacon.crypto.witness import seal_payload, create_checkpoint
from beacon.plugins.aws_ebs import EbsEncryptionPlugin
from beacon.plugins.spec import CollectContext
from beacon.scf.engine import collect_named
from beacon.scf.objective_catalog import objectives
from beacon.scope.bind import bind_observation_payload
from beacon.scope.store import import_scope, new_scope_document


def scoped(settings, *, approved=True, volumes=None, **params):
    body = new_scope_document("aws-assessment").canonical_body()
    body.update(schema_version=2, allowed_evidence_kinds=["cloud_inspector", "policy"],
                boundary={"accounts":["123456789012"], "regions":["us-east-1"]},
                parameters={"approved_rule_sha256":[r["rule_sha256"] for r in rules_for("CRY-07")] if approved else [],
                            "expected_ebs_volumes":volumes or ["us-east-1/vol-0123", "us-east-1/vol-0456"], **params})
    return import_scope(settings, json.dumps(body))


def payload(*, encrypted=True):
    return {"format":"beacon.aws-ebs/v1", "source":"aws.ebs.encryption", "cloud":"aws", "mode":"live",
        "ok":True, "collection_complete":True, "observed_at":dt.datetime.now(dt.timezone.utc).isoformat(),
        "identity":{"account_id":"123456789012", "arn":"arn:aws:iam::123456789012:role/collector", "partition":"aws"},
        "regions":["us-east-1"], "errors":[],
        "volumes":[{"VolumeId":"vol-0123","Encrypted":encrypted,"region":"us-east-1"},
                   {"VolumeId":"vol-0456","Encrypted":True,"region":"us-east-1"}],
        "region_runs":[{"region":"us-east-1", "complete":True,"pages":2,"volume_count":2}]}


def seal(settings, scope, body):
    row = seal_payload(settings, plugin="aws.ebs.encryption", mode=body["mode"], scf_targets=["CRY-07"],
                       payload=bind_observation_payload(body, scope))
    create_checkpoint(settings)
    return row


def result(settings, scope):
    receipt = evaluate_control(settings, scope_id=scope.scope_id, control_ref="CRY-07")
    assert len(receipt["results"]) == 10
    assert receipt["control_satisfied"] is False
    assert not any(row["objective_satisfied"] for row in receipt["results"])
    return next(row for row in receipt["results"] if row["ao_id"] == "CRY-07_A02"), receipt


def test_catalog_keeps_source_taxonomy_and_provenance():
    rows = objectives()
    assert len(rows) == len({row["ao_id"] for row in rows}) == 6446
    assert {row["ppt"] for row in objectives("CRY-07")} == {"Technology", "Process", "Data"}
    assert all(row["source_row"] >= 2 for row in rows)


def test_receipt_records_support_but_exposes_remaining_gaps(initialized):
    settings = load_settings(); scope = scoped(settings)
    record = seal(settings, scope, payload())
    row, receipt = result(settings, scope)
    assert row["status"] == "supporting_pass"
    assert row["evidence"][0]["payload_sha256"] == record.payload_sha256
    assert row["rule_sha256"] in scope.parameters["approved_rule_sha256"]
    assert receipt["summary"]["no_rule"] == 9
    stored = list_receipts(settings)[0]
    assert stored["historical"] and stored["receipt"]["receipt_id"] == receipt["receipt_id"]


@pytest.mark.parametrize("mutation,expected", [
    (lambda b:b.update(mode="fixture"), "ineligible"),
    (lambda b:b.update(mode="live_failed",ok=False), "ineligible"),
    (lambda b:b.update(collection_complete=False), "ineligible"),
    (lambda b:b.update(observed_at="2001-01-01T00:00:00Z"), "ineligible"),
    (lambda b:b.update(observed_at="2999-01-01T00:00:00Z"), "ineligible"),
    (lambda b:b["identity"].update(account_id="999999999999"), "ineligible"),
    (lambda b:b.update(regions=["us-west-2"]), "ineligible"),
    (lambda b:b.update(volumes=[]), "insufficient"),
    (lambda b:b["volumes"].pop(), "insufficient"),
    (lambda b:b["volumes"][0].update(Encrypted="true"), "insufficient"),
    (lambda b:b["volumes"][0].update(Encrypted=False), "supporting_fail"),
    (lambda b:b["region_runs"][0].update(complete=False), "insufficient"),
    # Malformed sealed structure is insufficient, never a crash or a pass.
    (lambda b:b["region_runs"].__setitem__(0, "us-east-1"), "insufficient"),
    (lambda b:b["region_runs"][0].update(region=["us-east-1"]), "insufficient"),
    (lambda b:b["region_runs"][0].update(pages=True), "insufficient"),
    (lambda b:b["region_runs"][0].update(volume_count="2"), "insufficient"),
    (lambda b:b["volumes"][0].update(region=["us-east-1"]), "insufficient"),
    (lambda b:b["volumes"].__setitem__(0, "vol-0123"), "insufficient"),
    (lambda b:b.pop("errors"), "insufficient"),
])
def test_bad_or_incomplete_evidence_never_supports(initialized, mutation, expected):
    settings=load_settings(); scope=scoped(settings); body=payload(); mutation(body); seal(settings,scope,body)
    row,_=result(settings,scope)
    assert row["status"] == expected
    assert row["reasons"]


def test_new_failed_run_supersedes_success(initialized):
    settings=load_settings(); scope=scoped(settings); seal(settings,scope,payload())
    assert result(settings,scope)[0]["status"] == "supporting_pass"
    failed=payload(); failed.update(mode="live_failed",ok=False); seal(settings,scope,failed)
    assert result(settings,scope)[0]["status"] == "ineligible"


def test_unapproved_rule_cannot_produce_support(initialized):
    settings=load_settings(); scope=scoped(settings,approved=False); seal(settings,scope,payload())
    assert result(settings,scope)[0]["status"] == "unapproved_rule"


@pytest.mark.parametrize("failure", [False, True])
def test_real_boto_paginator_preserves_partial_failure(initialized, monkeypatch, failure):
    settings=load_settings(); scope=scoped(settings)
    kwargs={"region_name":"us-east-1","aws_access_key_id":"testing","aws_secret_access_key":"testing"}
    sts=boto3.client("sts", **kwargs); ec2=boto3.client("ec2", **kwargs)
    with Stubber(sts) as identity, Stubber(ec2) as inventory:
        identity.add_response("get_caller_identity", {"Account":"123456789012", "Arn":"arn:aws:iam::123456789012:role/collector", "UserId":"test"}, {})
        inventory.add_response("describe_volumes", {"Volumes":[{"VolumeId":"vol-0123", "Encrypted":True}], "NextToken":"page2"}, {"MaxResults":500})
        if failure:
            inventory.add_client_error("describe_volumes",service_error_code="UnauthorizedOperation", expected_params={"MaxResults":500,"NextToken":"page2"})
        else:
            inventory.add_response("describe_volumes", {"Volumes":[{"VolumeId":"vol-0456", "Encrypted":True}]}, {"MaxResults":500,"NextToken":"page2"})
        class Session:
            def client(self, name, **kwargs):
                return sts if name=="sts" else ec2
        monkeypatch.setattr("beacon.plugins.aws_ebs.boto3.Session", Session)
        run=collect_named(settings,"aws.ebs.encryption",CollectContext(live=True),scope_id=scope.scope_id)
        assert run["ok"] is not failure
        row,_=result(settings,scope)
        assert row["status"] == ("ineligible" if failure else "supporting_pass")
        identity.assert_no_pending_responses();inventory.assert_no_pending_responses()


def test_receipt_listing_ignores_records_that_only_borrow_the_evaluator_name(initialized):
    settings=load_settings(); scope=scoped(settings)
    forged=bind_observation_payload({"format":"beacon.evaluation/v2","control_satisfied":True}, scope)
    seal_payload(settings, plugin="beacon.evaluator", mode="live", scf_targets=["CRY-07"], payload=forged)
    create_checkpoint(settings)
    assert list_receipts(settings, scope_id=scope.scope_id) == []
