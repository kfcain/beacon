"""Approved Git delivery facts: change gate, release image, and cluster boundary."""

from __future__ import annotations

import json
import subprocess

import pytest
from click.testing import CliRunner

from beacon.assurance.admission import eligibility
from beacon.assurance.delivery import capture_delivery, extract_delivery
from beacon.canonical import sha256_bytes
from beacon.cli import main
from beacon.config import load_settings
from beacon.crypto.witness import load_records
from beacon.errors import BeaconError
from beacon.scope.store import import_scope, new_scope_document
from beacon.scope.v2 import parse_scope

WORKFLOW = """\
name: Validate
jobs:
  checkov:
    steps:
      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          soft_fail: true
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          exit-code: "1"
"""

RELEASE = """\
image: demo/app:b251b734d4dab4cf11949f9b5c92c2dc279ca304
"""

FLOATING = """\
image:
  repository: nginx
  tag: "1.27"
"""

BOUNDARY = """\
cluster_endpoint_public_access = true
cluster_endpoint_public_access_cidrs = [
  var.cluster_public_access_cidr
]
subnet_ids = module.vpc.private_subnets
principal_arn = var.cluster_admin_principal_arn
policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
"""

OPEN_BOUNDARY = """\
cluster_endpoint_public_access = true
cluster_endpoint_public_access_cidrs = ["0.0.0.0/0"]
subnet_ids = module.vpc.public_subnets
principal_arn = "arn:aws:iam::123456789012:user/admin"
"""


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _commit(root) -> str:
    _git(root, "add", ".")
    _git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "delivery")
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _source(path: str, commit: str, raw: bytes, kind: str) -> dict:
    return {
        "path": path,
        "commit": commit,
        "file_sha256": sha256_bytes(raw),
        "system_id": "portfolio-eks",
        "kind": kind,
    }


def _enroll(settings, scope_id: str, sources: list[dict]):
    body = new_scope_document(scope_id).canonical_body()
    body.update(
        schema_version=2,
        allowed_evidence_kinds=["drop_in"],
        boundary={"systems": ["portfolio-eks"]},
        parameters={"delivery_sources": sources},
    )
    return import_scope(settings, json.dumps(body))


def test_template_image_and_missing_gate_stay_visible():
    facts, gaps = extract_delivery(
        "release_manifest",
        b'image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"\n',
    )
    assert facts["images"] == [{"identity": "unresolved"}]
    assert gaps == ["image_reference_unresolved"]
    _facts, gaps = extract_delivery("change_workflow", b"name: Validate\n")
    assert gaps == ["security_gate_missing"]
    facts, gaps = extract_delivery(
        "release_manifest",
        b"image: demo/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    )
    assert facts["images"] == [{"identity": "digest"}]
    assert gaps == []


def test_gate_posture_does_not_treat_a_weak_scan_as_blocking():
    advisory, gaps = extract_delivery("change_workflow", b"""\
      - name: Audit
        run: npm audit --audit-level=none
      - name: Scan
        run: trivy fs --exit-code 1 .
        continue-on-error: true
      - uses: bridgecrewio/checkov-action@v12
        with:
          soft_fail: "true"
# exit-code: "1"
""")
    assert advisory["gates"] == [
        {"tool": "npm-audit", "posture": "advisory"},
        {"tool": "trivy", "posture": "advisory"},
        {"tool": "checkov", "posture": "advisory"},
    ]
    assert gaps == [
        "gate_not_blocking:npm-audit",
        "gate_not_blocking:trivy",
        "gate_not_blocking:checkov",
    ]


def test_committed_admin_arn_and_ipv6_world_cidr_are_gaps():
    _facts, gaps = extract_delivery("cluster_boundary", """\
cluster_endpoint_public_access = true
cluster_endpoint_public_access_cidrs = ["::/0"]
principal_arn = var.cluster_admin_principal_arn
variable "cluster_admin_principal_arn" {
  default = "arn:aws:iam::123456789012:user/admin"
}
subnet_ids = module.vpc.private_subnets
""".encode())
    assert "admin_arn_committed" in gaps
    assert "api_open_to_world" in gaps
    assert "123456789012" not in json.dumps(_facts)


def test_scope_rejects_two_kinds_for_one_commit_path():
    body = new_scope_document("two-kinds").canonical_body()
    source = {
        "path": "a.yml", "commit": "a" * 40, "file_sha256": "b" * 64,
        "system_id": "portfolio-eks",
    }
    body.update(schema_version=2, allowed_evidence_kinds=["drop_in"], parameters={"delivery_sources": [
        {**source, "kind": "change_workflow"},
        {**source, "kind": "release_manifest"},
    ]})
    with pytest.raises(ValueError, match="must not repeat"):
        parse_scope(json.dumps(body))


def test_scope_rejects_unknown_delivery_kind():
    body = new_scope_document("bad-delivery").canonical_body()
    body.update(schema_version=2, allowed_evidence_kinds=["drop_in"], parameters={"delivery_sources": [{
        "path": "a.yml", "commit": "a" * 40, "file_sha256": "b" * 64,
        "system_id": "portfolio-eks", "kind": "screenshot"}]})
    with pytest.raises(ValueError, match="kind is unknown"):
        parse_scope(json.dumps(body))


def test_delivery_seals_facts_and_ignores_working_tree(initialized, tmp_path):
    root = tmp_path / "delivery"
    root.mkdir()
    _git(root, "init")
    files = {
        ".github/workflows/validate.yml": WORKFLOW.encode(),
        "manifest/deployment.yml": RELEASE.encode(),
        "helm/demo-app/values.yaml": FLOATING.encode(),
        "terraform/main.tf": BOUNDARY.encode(),
    }
    for path, raw in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    commit = _commit(root)
    sources = [
        _source(".github/workflows/validate.yml", commit, files[".github/workflows/validate.yml"], "change_workflow"),
        _source("manifest/deployment.yml", commit, files["manifest/deployment.yml"], "release_manifest"),
        _source("helm/demo-app/values.yaml", commit, files["helm/demo-app/values.yaml"], "release_manifest"),
        _source("terraform/main.tf", commit, files["terraform/main.tf"], "cluster_boundary"),
    ]
    settings = load_settings()
    scope = _enroll(settings, "portfolio-eks", sources)
    (root / "terraform/main.tf").write_text(OPEN_BOUNDARY)
    workflow = capture_delivery(
        settings, scope_id=scope.scope_id, root=root,
        path=".github/workflows/validate.yml", commit=commit,
    )
    assert workflow["assurance_claim"] is False
    assert workflow["facts"]["gates"] == [
        {"tool": "checkov", "posture": "advisory"},
        {"tool": "trivy", "posture": "blocking"},
    ]
    assert workflow["gaps"] == ["gate_not_blocking:checkov"]
    release = capture_delivery(
        settings, scope_id=scope.scope_id, root=root,
        path="manifest/deployment.yml", commit=commit,
    )
    assert release["facts"]["images"] == [{"identity": "git_sha"}]
    assert release["gaps"] == []
    floating = capture_delivery(
        settings, scope_id=scope.scope_id, root=root,
        path="helm/demo-app/values.yaml", commit=commit,
    )
    assert floating["facts"]["images"] == [{"identity": "floating"}]
    assert floating["gaps"] == ["floating_image_tag"]
    boundary = capture_delivery(
        settings, scope_id=scope.scope_id, root=root,
        path="terraform/main.tf", commit=commit,
    )
    assert boundary["facts"]["public_endpoint"] == "enabled"
    assert boundary["facts"]["api_cidr_source"] == "variable"
    assert boundary["facts"]["api_open_to_world"] is False
    assert boundary["facts"]["admin_principal_source"] == "variable"
    assert boundary["facts"]["node_subnets"] == "private"
    assert boundary["facts"]["broad_cluster_admin_policy"] is True
    assert boundary["gaps"] == ["broad_cluster_admin_policy"]
    stored = (settings.evidence_dir / f"{boundary['evidence_id']}.json").read_text(encoding="utf-8")
    assert "AmazonEKSClusterAdminPolicy" not in stored
    assert "arn:aws" not in stored
    assert "content" not in json.loads(stored)
    record = load_records(settings)[-1]
    payload = json.loads(stored)
    assert eligibility(settings, record, payload) == ()
    with pytest.raises(BeaconError):
        capture_delivery(settings, scope_id=scope.scope_id, root=root, path="../x.yml", commit=commit)


def test_open_boundary_is_a_gap_without_copying_literals(initialized, tmp_path):
    root = tmp_path / "open"
    root.mkdir()
    _git(root, "init")
    raw = OPEN_BOUNDARY.encode()
    (root / "main.tf").write_bytes(raw)
    commit = _commit(root)
    settings = load_settings()
    scope = _enroll(settings, "open-boundary", [_source("main.tf", commit, raw, "cluster_boundary")])
    result = capture_delivery(settings, scope_id=scope.scope_id, root=root, path="main.tf", commit=commit)
    assert result["gaps"] == [
        "api_open_to_world",
        "api_cidr_committed",
        "admin_arn_committed",
        "nodes_on_public_subnets",
    ]
    stored = (settings.evidence_dir / f"{result['evidence_id']}.json").read_text(encoding="utf-8")
    assert "123456789012" not in stored
    assert "0.0.0.0/0" not in stored
    assert "arn:aws" not in stored


def test_cli_seals_one_approved_file(initialized, tmp_path):
    root = tmp_path / "cli"
    root.mkdir()
    _git(root, "init")
    raw = RELEASE.encode()
    (root / "deployment.yml").write_bytes(raw)
    commit = _commit(root)
    settings = load_settings()
    scope = _enroll(settings, "cli-delivery", [_source("deployment.yml", commit, raw, "release_manifest")])
    result = CliRunner().invoke(main, [
        "delivery", "--scope", scope.scope_id, "--root", str(root),
        "--path", "deployment.yml", "--commit", commit,
    ])
    assert result.exit_code == 0, result.output
    body = json.loads(result.output)
    assert body["assurance_claim"] is False
    assert body["facts"]["images"] == [{"identity": "git_sha"}]
