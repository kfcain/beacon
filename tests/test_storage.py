"""S3 evidence lake, DynamoDB index, sync/pull. Offline paths need no AWS."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from beacon.canonical import sha256_bytes
from beacon.cli import main
from beacon.config import load_settings
from beacon.crypto.witness import check_chain, load_checkpoints, load_records, seal_payload
from beacon.errors import E_NO_CHECKPOINT, E_REMOTE, BeaconError
from beacon.plugins.spec import CollectContext
from beacon.scf.engine import collect_named
from beacon.storage.s3 import (
    assert_upload_allowed,
    checkpoint_id,
    checkpoints_jsonl_key,
    evidence_object_key,
    pack_object_key,
    pull_workspace,
    records_jsonl_key,
    sync_workspace,
)
from beacon.workspace import seed_workspace

boto3 = pytest.importorskip("boto3")
pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

BUCKET = "beacon-evidence-test"
TABLE = "beacon-artifact-index"
REGION = "us-east-1"
TENANT = "tenant-a"
WORKSPACE = "ws-1"


def _aws_env(monkeypatch: pytest.MonkeyPatch, kms_arn: str, *, prefix: str = "") -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.setenv("BEACON_S3_BUCKET", BUCKET)
    monkeypatch.setenv("BEACON_KMS_KEY_ARN", kms_arn)
    monkeypatch.setenv("BEACON_DDB_TABLE", TABLE)
    monkeypatch.setenv("BEACON_TENANT_ID", TENANT)
    monkeypatch.setenv("BEACON_WORKSPACE_ID", WORKSPACE)
    monkeypatch.setenv("BEACON_OBJECT_LOCK_MODE", "GOVERNANCE")
    monkeypatch.setenv("BEACON_OBJECT_LOCK_DAYS", "30")
    if prefix:
        monkeypatch.setenv("BEACON_S3_PREFIX", prefix)
    else:
        monkeypatch.delenv("BEACON_S3_PREFIX", raising=False)


def _provision_lake() -> str:
    kms = boto3.client("kms", region_name=REGION)
    key = kms.create_key(Description="beacon-evidence")["KeyMetadata"]
    kms.create_alias(AliasName="alias/beacon-evidence", TargetKeyId=key["KeyId"])
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
    s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object_lock_configuration(
        Bucket=BUCKET,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}},
        },
    )
    s3.put_bucket_encryption(
        Bucket=BUCKET,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": key["Arn"],
                    },
                    "BucketKeyEnabled": True,
                }
            ]
        },
    )
    ddb = boto3.client("dynamodb", region_name=REGION)
    ddb.create_table(
        TableName=TABLE,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.get_waiter("table_exists").wait(TableName=TABLE)
    return key["Arn"]


@pytest.fixture
def aws_lake(initialized: Path, monkeypatch: pytest.MonkeyPatch):
    mock = mock_aws()
    mock.start()
    try:
        kms_arn = _provision_lake()
        _aws_env(monkeypatch, kms_arn)
        yield {
            "kms_arn": kms_arn,
            "s3": boto3.client("s3", region_name=REGION),
            "ddb": boto3.resource("dynamodb", region_name=REGION).Table(TABLE),
        }
    finally:
        mock.stop()


def test_kms_defaults_to_alias_when_bucket_set(beacon_home: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BEACON_S3_BUCKET", "beacon-evidence-test")
    monkeypatch.setenv("BEACON_TENANT_ID", "tenant-a")
    monkeypatch.setenv("BEACON_WORKSPACE_ID", "ws-1")
    settings = load_settings()
    assert settings.kms_key_arn == "alias/beacon-evidence"
    assert settings.ddb_table == "beacon-artifact-index"


def test_object_key_scheme():
    assert evidence_object_key("t1", "w1", "ev-1") == "t1/w1/evidence/ev-1.json"
    assert records_jsonl_key("t1", "w1") == "t1/w1/chain/records.jsonl"
    assert checkpoints_jsonl_key("t1", "w1") == "t1/w1/chain/checkpoints.jsonl"
    assert (
        pack_object_key("t1", "w1", "20260909T120000Z", prefix="lake")
        == "lake/t1/w1/export/beacon-pack-20260909T120000Z.json"
    )


def test_refuses_private_key_material(initialized: Path):
    settings = load_settings()
    sec = settings.export_dir / "secret.sec"
    sec.write_text("nope", encoding="utf-8")
    with pytest.raises(BeaconError) as caught:
        assert_upload_allowed(settings, sec)
    assert caught.value.code == E_REMOTE
    with pytest.raises(BeaconError) as caught_pem:
        assert_upload_allowed(settings, settings.keys_dir / "recorder.pem")
    assert caught_pem.value.code == E_REMOTE
    with pytest.raises(BeaconError) as caught_tsa:
        assert_upload_allowed(settings, settings.keys_dir / "tsa.pem")
    assert caught_tsa.value.code == E_REMOTE
    with pytest.raises(BeaconError) as caught_pub:
        assert_upload_allowed(settings, settings.keys_dir / "recorder.pub")
    assert caught_pub.value.code == E_REMOTE
    with pytest.raises(BeaconError) as caught_cfg:
        assert_upload_allowed(settings, settings.home / "config.json")
    assert caught_cfg.value.code == E_REMOTE
    cache = settings.cache_dir / "scf" / "IAC-01.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("{}", encoding="utf-8")
    with pytest.raises(BeaconError) as caught_cache:
        assert_upload_allowed(settings, cache)
    assert caught_cache.value.code == E_REMOTE


def test_collect_skips_remote_when_bucket_unset(initialized: Path):
    result = collect_named(load_settings(), "aws.inspector", CollectContext(live=False))
    assert "remote" not in result
    assert result["evidence_id"]


def test_require_remote_fail_closed_without_bucket(initialized: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BEACON_REQUIRE_REMOTE", "1")
    with pytest.raises(BeaconError) as caught:
        collect_named(load_settings(), "aws.inspector", CollectContext(live=False))
    assert caught.value.code == E_REMOTE


def test_cli_sync_without_bucket_fails(initialized: Path):
    runner = CliRunner()
    result = runner.invoke(main, ["sync"])
    assert result.exit_code != 0
    assert E_REMOTE in result.output


def test_witness_fail_closed_with_s3_configured(aws_lake):
    settings = load_settings()
    seal_payload(
        settings,
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["IAC-01"],
        payload={"n": 1},
    )
    with pytest.raises(BeaconError) as caught:
        check_chain(settings)
    assert caught.value.code == E_NO_CHECKPOINT


def test_collect_dual_writes_s3_and_index(aws_lake):
    settings = load_settings()
    result = collect_named(settings, "aws.inspector", CollectContext(live=False))
    assert result["remote"]["ok"] is True
    record = load_records(settings)[0]
    key = evidence_object_key(TENANT, WORKSPACE, record.evidence_id)
    s3 = aws_lake["s3"]
    head = s3.head_object(Bucket=BUCKET, Key=key)
    meta = {k.lower(): v for k, v in (head.get("Metadata") or {}).items()}
    assert meta["sha256"] == record.payload_sha256
    assert meta["plugin"] == "aws.inspector"
    assert "iac-01" in meta["scf_targets"].lower() or "IAC-01" in meta["scf_targets"]
    assert meta["record_id"] == record.evidence_id
    assert meta["sealed_at"] == record.ts
    assert head.get("ServerSideEncryption") == "aws:kms"
    assert head.get("ObjectLockMode") in {None, "GOVERNANCE"}
    s3.head_object(Bucket=BUCKET, Key=records_jsonl_key(TENANT, WORKSPACE))
    s3.head_object(Bucket=BUCKET, Key=checkpoints_jsonl_key(TENANT, WORKSPACE))
    ddb = aws_lake["ddb"]
    ev_item = ddb.get_item(Key={"pk": f"{TENANT}#{WORKSPACE}", "sk": f"EVIDENCE#{record.evidence_id}"})[
        "Item"
    ]
    assert ev_item["s3_uri"] == f"s3://{BUCKET}/{key}"
    assert ev_item["sha256"] == record.payload_sha256
    listed = [
        obj["Key"]
        for obj in s3.list_objects_v2(Bucket=BUCKET).get("Contents") or []
    ]
    for key_name in listed:
        assert "/keys/" not in key_name
        assert "/cache/" not in key_name
        assert not key_name.endswith("config.json")
        assert "/exports/" not in key_name
        assert "/meta/" not in key_name
        parts = key_name.split("/")
        assert "evidence" not in parts or parts[-1].endswith(".json")
    assert "IAC-01" in list(ev_item["control_ids"])
    fresh = ddb.get_item(Key={"pk": f"{TENANT}#{WORKSPACE}", "sk": "FRESH#aws.inspector"})["Item"]
    assert fresh["s3_uri"] == ev_item["s3_uri"]
    cp = load_checkpoints(settings)[0]
    cp_item = ddb.get_item(
        Key={"pk": f"{TENANT}#{WORKSPACE}", "sk": f"CP#{checkpoint_id(cp)}"}
    )["Item"]
    assert cp_item["merkle_root"] == cp.merkle_root
    checked = check_chain(settings)
    assert checked["ok"] is True


def test_push_dual_writes_pack(aws_lake):
    from beacon.push import write_pack

    settings = load_settings()
    seed_workspace(settings)
    result = write_pack(settings)
    assert result.path.exists()
    assert result.remote is not None
    pack_uri = result.remote["pack"]["s3_uri"]
    assert pack_uri.endswith(f"/export/beacon-pack-{result.remote['pack']['pack_id']}.json")
    assert "/export/beacon-pack-" in pack_uri
    assert "/keys/" not in pack_uri
    body = aws_lake["s3"].get_object(
        Bucket=BUCKET,
        Key=pack_uri.split(f"s3://{BUCKET}/", 1)[1],
    )["Body"].read()
    assert sha256_bytes(body) == result.remote["pack"]["sha256"]
    assert b"recorder.pem" not in body
    assert b"BEGIN PRIVATE KEY" not in body
    record = load_records(settings)[0]
    ev_item = aws_lake["ddb"].get_item(
        Key={"pk": f"{TENANT}#{WORKSPACE}", "sk": f"EVIDENCE#{record.evidence_id}"}
    )["Item"]
    assert ev_item["pack_id"] == result.remote["pack"]["pack_id"]


def test_sync_and_pull_roundtrip(aws_lake):
    settings = load_settings()
    collect_named(settings, "aws.inspector", CollectContext(live=False))
    sync = sync_workspace(settings)
    assert sync["ok"] is True
    evidence_files = list(settings.evidence_dir.glob("*.json"))
    assert evidence_files
    payload = evidence_files[0].read_bytes()
    evidence_files[0].unlink()
    settings.chain_path.write_text("", encoding="utf-8")
    settings.checkpoints_path.write_text("", encoding="utf-8")
    pulled = pull_workspace(settings)
    assert pulled["ok"] is True
    assert pulled["verified"] >= 1
    restored = list(settings.evidence_dir.glob("*.json"))
    assert restored
    assert restored[0].read_bytes() == payload
    checked = check_chain(settings)
    assert checked["ok"] is True


def test_pull_detects_hash_mismatch(aws_lake):
    settings = load_settings()
    collect_named(settings, "aws.inspector", CollectContext(live=False))
    record = load_records(settings)[0]
    key = evidence_object_key(TENANT, WORKSPACE, record.evidence_id)
    aws_lake["s3"].put_object(
        Bucket=BUCKET,
        Key=key,
        Body=b'{"tampered":true}',
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=aws_lake["kms_arn"],
    )
    settings.evidence_dir.joinpath(f"{record.evidence_id}.json").unlink()
    with pytest.raises(BeaconError) as caught:
        pull_workspace(settings)
    assert caught.value.code == E_REMOTE
    assert "sha256" in str(caught.value).lower()


def test_cli_sync_pull(aws_lake):
    runner = CliRunner()
    collect = runner.invoke(main, ["collect", "--plugin", "aws.inspector", "--fixture"])
    assert collect.exit_code == 0
    sync = runner.invoke(main, ["sync"])
    assert sync.exit_code == 0
    pull = runner.invoke(main, ["pull"])
    assert pull.exit_code == 0


def test_prefix_is_applied(initialized: Path, monkeypatch: pytest.MonkeyPatch):
    mock = mock_aws()
    mock.start()
    try:
        kms_arn = _provision_lake()
        _aws_env(monkeypatch, kms_arn, prefix="lake")
        settings = load_settings()
        result = collect_named(settings, "aws.inspector", CollectContext(live=False))
        record = load_records(settings)[0]
        key = evidence_object_key(TENANT, WORKSPACE, record.evidence_id, prefix="lake")
        assert key.startswith("lake/")
        boto3.client("s3", region_name=REGION).head_object(Bucket=BUCKET, Key=key)
        assert result["remote"]["ok"] is True
    finally:
        mock.stop()


def test_invalid_tenant_id_fail_closed(aws_lake, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BEACON_TENANT_ID", "acme#prod")
    with pytest.raises(BeaconError) as caught:
        collect_named(load_settings(), "aws.inspector", CollectContext(live=False))
    assert caught.value.code == E_REMOTE


def test_pull_rejects_foreign_s3_uri(aws_lake):
    collect_named(load_settings(), "aws.inspector", CollectContext(live=False))
    aws_lake["ddb"].put_item(
        Item={
            "pk": f"{TENANT}#{WORKSPACE}",
            "sk": "EVIDENCE#aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "s3_uri": "s3://other-bucket/secret.json",
            "sha256": "00" * 32,
            "record_s3_uri": "s3://other-bucket/record.json",
            "record_sha256": "11" * 32,
        }
    )
    with pytest.raises(BeaconError) as caught:
        pull_workspace(load_settings())
    assert caught.value.code == E_REMOTE
    assert "bucket mismatch" in str(caught.value).lower()


def test_pull_rejects_path_traversal_sk(aws_lake):
    collect_named(load_settings(), "aws.inspector", CollectContext(live=False))
    aws_lake["ddb"].put_item(
        Item={
            "pk": f"{TENANT}#{WORKSPACE}",
            "sk": "EVIDENCE#../../config",
            "s3_uri": f"s3://{BUCKET}/{TENANT}/{WORKSPACE}/evidence/2026/09/ev.json",
            "sha256": "00" * 32,
            "record_s3_uri": f"s3://{BUCKET}/{TENANT}/{WORKSPACE}/chain/records/ev.json",
            "record_sha256": "11" * 32,
        }
    )
    with pytest.raises(BeaconError) as caught:
        pull_workspace(load_settings())
    assert caught.value.code == E_REMOTE


def test_iam_docs_omit_delete_object():
    iam = Path("deploy/aws/iam.tf").read_text(encoding="utf-8")
    assert "DeleteObject" not in iam
    assert "BypassGovernanceRetention" not in iam
    assert "GenerateDataKey" in iam
    bucket = Path("deploy/aws/s3.tf").read_text(encoding="utf-8")
    assert "object_lock_enabled = true" in bucket
    assert "BucketOwnerEnforced" in bucket
    assert "DenyDeleteObject" in bucket
    assert "STANDARD_IA" in bucket
    assert "GLACIER" in bucket
    kms = Path("deploy/aws/kms.tf").read_text(encoding="utf-8")
    assert "alias/beacon-evidence" in Path("deploy/aws/variables.tf").read_text(encoding="utf-8")
    assert "enable_key_rotation" in kms
