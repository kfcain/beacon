"""Regression coverage for previously independent output and custody paths."""
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import sys

import pytest

from beacon.assurance.admission import verified_snapshot
from beacon.assurance.compile import compile_20x_drafts
from beacon.assurance.index import load_evidence_ledger, ledger_method_report
from beacon.canonical import dumps, sha256_obj
from beacon.config import load_settings
from beacon.crypto.enrollment import enroll, enroll_anchor
from beacon.crypto.trust import read_trust, external_head
from beacon.crypto.witness import check_chain, create_checkpoint, load_records, seal_payload
from beacon.errors import BeaconError
from beacon.push import write_pack
from beacon.scope.store import init_scope
from beacon.scf.engine import collect_named
from beacon.plugins.spec import CollectContext


def observation(settings):
    return seal_payload(settings, plugin="test", mode="fixture", scf_targets=["CRY-07"], payload={"mode":"fixture"})


@pytest.mark.parametrize("output", [lambda s: write_pack(s), lambda s: load_evidence_ledger(s),
    lambda s: ledger_method_report(s, package_class="c"), lambda s: compile_20x_drafts(s, package_class="c")])
def test_every_output_rejects_uncheckpointed_history(initialized, output):
    settings = load_settings()
    observation(settings)
    with pytest.raises(BeaconError, match="checkpoint"):
        output(settings)


@pytest.mark.parametrize("corruption", ["payload", "signature", "checkpoint", "scope"])
def test_outputs_reject_corrupted_history(initialized, corruption):
    settings = load_settings()
    scope = init_scope(settings, "assessment")
    result = collect_named(settings, "aws.inspector", CollectContext(live=False), scope_id=scope.scope_id)
    if corruption == "payload":
        (settings.evidence_dir / f"{result['evidence_id']}.json").write_text('{}')
    elif corruption == "signature":
        rows = [r.to_dict() for r in load_records(settings)]
        rows[0]["recorder_sig"] = "00" * 64
        settings.chain_path.write_bytes(dumps(rows[0])+b'\n')
    elif corruption == "checkpoint":
        settings.checkpoints_path.write_text('[]\n')
    else:
        path = settings.home / "scopes" / "assessment.json"
        body = json.loads(path.read_bytes()); body["data_classes"] = ["changed"]
        path.write_bytes(dumps(body))
    for output in [write_pack, load_evidence_ledger, verified_snapshot]:
        with pytest.raises(BeaconError):
            output(settings)


def test_fixture_tags_never_satisfy_method_count(initialized):
    settings = load_settings(); scope = init_scope(settings, "assessment")
    seal_payload(settings, plugin="aws.inspector", mode="fixture", scf_targets=["CRY-07"], payload={
        "source":"aws.inspector", "mode":"fixture", "ok":True, "scope_id":scope.scope_id,
        "scope_sha256":scope.content_sha256(), "ksi_id":"test-ksi",
        "tags":["evidence:cloud_inspector", "automation:automated", "control:CRY-07"]})
    create_checkpoint(settings)
    report = ledger_method_report(settings, package_class="c")
    assert report.counts[0].automated_method_count == 0
    assert report.counts[0].shortfall == 2
    assert "not_live" in report.excluded_ineligible[0]


def test_pack_cannot_change_signed_payload(initialized, tmp_path):
    settings = load_settings(); observation(settings); create_checkpoint(settings)
    pack = write_pack(settings, tmp_path / "pack.json")
    body = json.loads(pack.path.read_bytes()); body["evidence"][0]["payload"] = '{}'
    pack.path.write_bytes(dumps(body))
    with pytest.raises(BeaconError):
        load_evidence_ledger(settings, pack_path=pack.path)


def test_chain_only_and_entire_workspace_rollbacks_are_detected(initialized, tmp_path):
    settings = load_settings(); observation(settings); create_checkpoint(settings)
    anchored = replace(settings, anchor_dir=tmp_path / "external", require_external_anchor=True)
    enroll_anchor(anchored)
    old = {path: path.read_bytes() for path in [settings.chain_path, settings.checkpoints_path, settings.home / "retained-head.json"]}
    observation(anchored); create_checkpoint(anchored)
    # A chain-only rollback fails against the local head.
    settings.chain_path.write_bytes(old[settings.chain_path]); settings.checkpoints_path.write_bytes(old[settings.checkpoints_path])
    with pytest.raises(BeaconError) as error:
        check_chain(settings)
    assert error.value.code == "E_CONTINUITY"
    # Even restoring the old local head fails against the external head.
    (settings.home / "retained-head.json").write_bytes(old[settings.home / "retained-head.json"])
    with pytest.raises(BeaconError) as error:
        check_chain(anchored)
    assert error.value.code == "E_CONTINUITY"


def test_legacy_enrollment_is_explicit_and_cannot_reset_trust(initialized):
    settings = load_settings(); observation(settings); create_checkpoint(settings)
    trust = read_trust(settings); records = load_records(settings)
    kwargs = {key: trust[key] for key in ["recorder", "witness", "tsa_sha256", "workspace_id"]}
    kwargs.update(expected_seq=len(records), expected_head=sha256_obj(records[-1].to_dict()))
    (settings.home / "trust.json").unlink(); (settings.home / "retained-head.json").unlink()
    with pytest.raises(BeaconError) as error:
        check_chain(settings)
    assert error.value.code == "E_TRUST"
    assert enroll(settings, **kwargs)["ok"]
    with pytest.raises(BeaconError):
        enroll(settings, **kwargs)


def test_unregistered_signer_cannot_append(initialized, tmp_path):
    from beacon.crypto.keys import generate_distinct_roles
    settings = load_settings()
    keys = tmp_path / "other-keys"; keys.mkdir()
    recorder, witness = generate_distinct_roles(keys)
    with pytest.raises(BeaconError) as error:
        seal_payload(settings, plugin="x", mode="live", scf_targets=[], payload={}, recorder=recorder, witness=witness)
    assert error.value.code == "E_UNTRUSTED_SIGNER"
    assert load_records(settings) == []


def test_parallel_processes_preserve_sequence_and_checkpoints(initialized):
    code = """from beacon.config import load_settings
from beacon.crypto.witness import seal_payload, create_checkpoint
s=load_settings()
for i in range(3):
 seal_payload(s,plugin='parallel',mode='fixture',scf_targets=[],payload={'index':i})
create_checkpoint(s)
"""
    processes = [subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(3)]
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr.decode()
    settings = load_settings(); create_checkpoint(settings)
    assert [row.seq for row in load_records(settings)] == list(range(1,10))
    assert check_chain(settings)["ok"]


@pytest.mark.parametrize("tamper", [
    lambda row: row.update(seq=str(row["seq"])),
    lambda row: row.update(v=True),
    lambda row: row.update(note="not signed"),
    lambda row: row.update(scf_targets="CRY-07"),
])
def test_chain_records_are_parsed_exactly(initialized, tamper):
    settings = load_settings()
    observation(settings)
    create_checkpoint(settings)
    row = json.loads(settings.chain_path.read_text().splitlines()[0])
    tamper(row)
    settings.chain_path.write_text(json.dumps(row) + "\n")
    with pytest.raises(BeaconError, match="malformed witness chain"):
        check_chain(settings)


def test_framework_exclusions_are_enforced(initialized):
    import datetime as dt
    from beacon.assurance.admission import eligibility
    from beacon.scope.bind import bind_observation_payload
    from beacon.scope.store import import_scope, new_scope_document
    settings = load_settings()
    body = new_scope_document("framework-scope").canonical_body()
    conflict = dict(body, exclusions=[{"kind": "framework", "value": body["frameworks"][0], "reason": "not-assessed"}])
    with pytest.raises(BeaconError, match="excludes"):
        import_scope(settings, json.dumps(conflict))
    body.update(schema_version=2, allowed_evidence_kinds=["cloud_inspector"],
                boundary={"accounts": ["123456789012"], "regions": ["us-east-1"]},
                exclusions=[{"kind": "framework", "value": "americas-bra-lgpd-2018", "reason": "not-assessed"}])
    scope = import_scope(settings, json.dumps(body))

    def sealed(tags):
        payload = bind_observation_payload({"format": "beacon.aws-ebs/v1", "source": "aws.ebs.encryption",
            "cloud": "aws", "mode": "live", "ok": True, "collection_complete": True,
            "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(), "regions": ["us-east-1"],
            "identity": {"account_id": "123456789012", "partition": "aws",
                         "arn": "arn:aws:iam::123456789012:role/collector"}, "tags": tags}, scope)
        record = seal_payload(settings, plugin="aws.ebs.encryption", mode="live", scf_targets=["CRY-07"], payload=payload)
        return eligibility(settings, record, payload)

    assert "excluded_framework" in sealed(["framework:americas-bra-lgpd-2018"])
    assert sealed(["control:CRY-07"]) == ()
