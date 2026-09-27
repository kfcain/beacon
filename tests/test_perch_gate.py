"""Perch Gate v0: AO map, receipt, and the mock CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from beacon.cli import main
from beacon.errors import BeaconError
from beacon.perch_gate import (
    build_mock_receipt,
    build_receipt,
    build_scan_receipt,
    merge_rule_texts,
    parse_rule_file,
    repo_root,
    validate_receipt,
    verify_pack,
)

ROOT = repo_root()


def test_pack_matches_pinned_objectives():
    ao_map = verify_pack(ROOT)
    names = [rule["name"] for rule in ao_map["rules"]]
    assert names == [
        "tf-encryption-at-rest",
        "tf-no-public-acl",
        "tf-required-logging",
        "tf-no-plaintext-secrets",
    ]
    by_name = {rule["name"]: rule for rule in ao_map["rules"]}
    assert by_name["tf-encryption-at-rest"]["scf_id"] == "CRY-07"
    assert by_name["tf-encryption-at-rest"]["ao_id"] == "CRY-07_A02"
    assert by_name["tf-encryption-at-rest"]["control_json"] == "beacon/scf/offline/CRY-07.json"
    assert "general-nist-800-53-r5-2" in by_name["tf-encryption-at-rest"]["framework_hops"]
    assert by_name["tf-no-public-acl"]["scf_id"] == "IAC-25"
    assert by_name["tf-no-public-acl"]["ao_id"] == "IAC-25_A06"
    assert "framework_hops" not in by_name["tf-no-public-acl"]
    assert "control_json" not in by_name["tf-no-public-acl"]
    assert by_name["tf-required-logging"]["ao_id"] == "MON-04_A02"
    assert by_name["tf-no-plaintext-secrets"]["ao_id"] == "CFG-17.2_A04"


def test_mock_receipt_stays_unverified():
    receipt = build_mock_receipt(ROOT)
    validate_receipt(receipt)
    assert receipt["kind"] == "perch_gate"
    assert receipt["claim_status"] == "unverified"
    assert receipt["sealed"] is False
    assert receipt["live_api"] is False
    assert receipt["perch_version"] == "not-run"
    assert receipt["failing"] is False
    assert receipt["problem_count"] == 0
    assert receipt["ao_hits"] == []
    assert receipt["scope_id"] is None
    assert receipt["scope_sha256"] is None


def test_scan_receipt_maps_issue_to_ao(tmp_path: Path):
    path = _write_scan(
        tmp_path,
        [
            {
                "id": "abc123",
                "rule": "tf-encryption-at-rest",
                "path": "deploy/aws/s3.tf",
            }
        ],
        status="complete",
    )
    receipt = build_scan_receipt(
        path,
        root=ROOT,
        repo="kfcain/beacon",
        commit_sha="a" * 40,
        perch_version="0.3.5",
        exit_code=3,
        live_api=True,
    )
    assert receipt["live_api"] is True
    assert receipt["failing"] is True
    assert receipt["problem_count"] == 1
    assert receipt["claim_status"] == "unverified"
    assert receipt["ao_hits"] == [
        {"scf_id": "CRY-07", "issue_ids": ["abc123"], "ao_id": "CRY-07_A02"}
    ]


def test_unknown_rule_and_clean_exit_with_problems_fail(tmp_path: Path):
    with pytest.raises(BeaconError) as unknown:
        build_scan_receipt(
            _write_scan(tmp_path, [{"id": "x", "rule": "made-up"}], status="complete"),
            root=ROOT,
            repo="kfcain/beacon",
            commit_sha="b" * 40,
            perch_version="0.3.5",
            exit_code=3,
            live_api=True,
        )
    assert unknown.value.code == "E_PERCH"
    with pytest.raises(BeaconError):
        build_scan_receipt(
            _write_scan(tmp_path, [{"id": "x", "rule": "tf-no-public-acl"}], status="complete"),
            root=ROOT,
            repo="kfcain/beacon",
            commit_sha="c" * 40,
            perch_version="0.3.5",
            exit_code=0,
            live_api=True,
        )


def test_incomplete_scan_is_rejected(tmp_path: Path):
    path = _write_scan(tmp_path, [], status="incomplete")
    with pytest.raises(BeaconError) as caught:
        build_scan_receipt(
            path,
            root=ROOT,
            repo="kfcain/beacon",
            commit_sha="d" * 40,
            perch_version="0.3.5",
            exit_code=0,
            live_api=True,
        )
    assert caught.value.code == "E_PERCH"


def test_duplicate_comment_and_later_rule_file():
    text = "- name: example\n# beacon.scf_id: CRY-07\n# beacon.scf_id: IAC-25\n"
    with pytest.raises(BeaconError):
        parse_rule_file(text)
    first = (
        ".perch/rules/a.yaml",
        "# beacon.scf_id: CRY-07\n- name: tf-encryption-at-rest\n  each: file\n",
    )
    later = (
        ".perch/rules/b.yaml",
        "# beacon.scf_id: CRY-07\n- name: tf-encryption-at-rest\n  disabled: true\n",
    )
    merged = merge_rule_texts([first, later])
    assert merged[0][0]["disabled"] == "true"
    assert "each" not in merged[0][0]


def test_scf_id_yaml_key_is_rejected():
    text = "- name: example\n  scf_id: CRY-07\n  ensure: >\n    Storage is encrypted.\n"
    with pytest.raises(BeaconError) as caught:
        parse_rule_file(text)
    assert caught.value.code == "E_PERCH"


def test_live_api_without_scan_json_fails():
    with pytest.raises(BeaconError) as caught:
        build_receipt(
            root=ROOT,
            repo="kfcain/beacon",
            commit_sha="e" * 40,
            perch_version="0.3.5",
            exit_code=0,
            live_api=True,
        )
    assert caught.value.code == "E_PERCH"


def test_claim_word_is_rejected():
    receipt = build_mock_receipt(ROOT)
    receipt["claim_status"] = "compliant"
    with pytest.raises(BeaconError):
        validate_receipt(receipt)


def test_cli_live_api_without_scan_fails():
    result = CliRunner().invoke(
        main,
        [
            "perch-receipt",
            "--live-api",
            "--exit-code",
            "0",
            "--repo",
            "kfcain/beacon",
            "--commit",
            "abc",
            "--perch-version",
            "0.3.5",
        ],
    )
    assert result.exit_code == 2
    assert "live_api requires the scan JSON" in (result.output + (result.stderr or ""))


def test_cli_mock_prints_unverified():
    result = CliRunner().invoke(main, ["perch-receipt", "--mock"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["claim_status"] == "unverified"
    assert payload["sealed"] is False
    assert payload["live_api"] is False


def _write_scan(directory: Path, issues: list[dict], *, status: str) -> Path:
    path = directory / "perch-scan.json"
    body = {"run": {"status": status, "incomplete": [] if status == "complete" else ["miss"]}, "issues": issues}
    path.write_text(json.dumps(body), encoding="utf-8")
    return path
