"""Lake log collector: fixture, live fail-closed, and witness seal."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from beacon.config import load_settings
from beacon.crypto.witness import check_chain, load_records, seal_payload
from beacon.errors import E_NO_CHECKPOINT, BeaconError
from beacon.plugins.lake_logs import (
    PLUGIN_NAME,
    LakeLogPlugin,
    parse_cloudtrail_data_events,
    parse_s3_access_log,
)
from beacon.plugins.loader import load_plugins
from beacon.plugins.spec import CollectContext
from beacon.scf.engine import collect_named

boto3 = pytest.importorskip("boto3")
pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

REGION = "us-east-1"
LOGS_BUCKET = "beacon-evidence-logs-test"
ACCESS_LINE = (
    "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be "
    "beacon-evidence-fixture [21/Sep/2026:12:00:00 +0000] 192.0.2.10 requester REQ123 "
    "REST.GET.OBJECT tenant/ws/observations/example.json "
    '"GET /beacon-evidence-fixture/tenant/ws/observations/example.json?token=QUERYSECRET '
    'HTTP/1.1" 200 - - 128 20 "-" "beacon" - SigV4 - -\n'
)
TRAIL = {
    "Records": [
        {
            "eventTime": "2026-09-21T12:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": "us-east-1",
            "eventCategory": "Data",
            "managementEvent": False,
            "readOnly": True,
            "recipientAccountId": "123456789012",
            "eventID": "11111111-2222-3333-4444-555555555555",
            "resources": [
                {
                    "type": "AWS::S3::Object",
                    "ARN": "arn:aws:s3:::beacon-evidence-fixture/tenant/ws/observations/example.json",
                }
            ],
            "userIdentity": {"type": "AssumedRole", "accessKeyId": "ASIAEXAMPLE"},
            "requestParameters": {
                "bucketName": "beacon-evidence-fixture",
                "x-amz-server-side-encryption-customer-key": "SECRETKEY",
            },
        }
    ]
}


def _aws(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_REGION", REGION)


def _put_pair(s3, *, trail_body: bytes, trail_key: str, access_body: bytes | None = None) -> None:
    s3.create_bucket(Bucket=LOGS_BUCKET)
    s3.put_object(
        Bucket=LOGS_BUCKET,
        Key="s3-access-logs/2026-09-21",
        Body=access_body if access_body is not None else ACCESS_LINE.encode("utf-8"),
    )
    s3.put_object(Bucket=LOGS_BUCKET, Key=trail_key, Body=trail_body)


def test_plugin_is_builtin(initialized: Path) -> None:
    plugins = load_plugins(load_settings())
    assert PLUGIN_NAME in plugins
    assert plugins[PLUGIN_NAME].spec.scf_targets == ("IAC-01",)


def test_fixture_seals_extract_without_secrets(initialized: Path) -> None:
    result = LakeLogPlugin().collect(CollectContext(live=False))
    assert result.ok is True
    assert result.mode == "fixture"
    blob = json.dumps(result.payload)
    assert "QUERYSECRET" not in blob
    assert "ASIAEXAMPLE" not in blob
    assert "SECRETKEY" not in blob
    assert "accessKeyId" not in blob
    classes = {item["log_class"] for item in result.payload["observations"]}
    assert classes == {"s3_access_log", "cloudtrail_data_event"}
    assert result.payload["complete"] is True
    assert result.payload["class_separation"]["raw_logs_remain_in_logging_bucket"] is True
    statuses = {item["check"]: item["status"] for item in result.payload["findings"]}
    assert statuses == {
        "s3_access_log_ingest": "collected",
        "cloudtrail_data_event_ingest": "collected",
    }
    assert all(item["scf"] == "IAC-01" for item in result.payload["findings"])
    access = next(item for item in result.payload["observations"] if item["log_class"] == "s3_access_log")
    assert access["records"][0]["operation"] == "REST.GET.OBJECT"
    assert access["records"][0]["http_status"] == 200
    assert "line_sha256" in access["records"][0]


def test_live_without_bucket_is_live_failed(initialized: Path) -> None:
    result = LakeLogPlugin().collect(CollectContext(live=True))
    assert result.ok is False
    assert result.mode == "live_failed"
    assert result.payload["findings"] == []
    assert "BEACON_LOGS_BUCKET" in str(result.error)


def test_auto_with_bucket_does_not_rewrite_failure_as_fixture(
    initialized: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _aws(monkeypatch)
    monkeypatch.setenv("BEACON_LOGS_BUCKET", LOGS_BUCKET)
    with mock_aws():
        result = LakeLogPlugin().collect(CollectContext())
    assert result.ok is False
    assert result.mode == "live_failed"
    assert result.payload["findings"] == []


def test_live_malformed_cloudtrail_is_live_failed(initialized: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws(monkeypatch)
    monkeypatch.setenv("BEACON_LOGS_BUCKET", LOGS_BUCKET)
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=LOGS_BUCKET)
        s3.put_object(Bucket=LOGS_BUCKET, Key="s3-access-logs/ok", Body=ACCESS_LINE.encode("utf-8"))
        s3.put_object(
            Bucket=LOGS_BUCKET,
            Key="cloudtrail/AWSLogs/123/CloudTrail/us-east-1/bad.json",
            Body=b'{"error":"unavailable"}',
        )
        result = LakeLogPlugin().collect(CollectContext(live=True))
    assert result.ok is False
    assert result.mode == "live_failed"
    assert result.payload["findings"] == []
    assert result.payload["observations"] == []


def test_auto_without_bucket_uses_fixture(initialized: Path) -> None:
    result = LakeLogPlugin().collect(CollectContext())
    assert result.ok is True
    assert result.mode == "fixture"
    assert result.payload["fixture_reason"] == "no_logs_bucket"


def test_foreign_target_is_refused(initialized: Path) -> None:
    result = LakeLogPlugin().collect(CollectContext(target="CRY-05", live=False))
    assert result.ok is False
    assert result.mode == "failed"
    assert result.scf_targets == ()
    assert result.payload["findings"] == []
    assert "scf" not in result.payload


def test_child_control_id_is_refused(initialized: Path) -> None:
    result = LakeLogPlugin().collect(CollectContext(target="IAC-01.1", live=False))
    assert result.ok is False
    assert result.mode == "failed"
    assert result.scf_targets == ()


def test_foreign_target_is_not_sealed_as_iac_01(initialized: Path) -> None:
    sealed = collect_named(
        load_settings(),
        PLUGIN_NAME,
        CollectContext(target="CRY-05", live=False),
    )
    assert sealed["ok"] is False
    assert sealed["scf_targets"] == []
    record = load_records(load_settings())[0]
    assert record.scf_targets == []
    evidence = json.loads(
        (load_settings().evidence_dir / f"{record.evidence_id}.json").read_text(encoding="utf-8")
    )
    assert "scf" not in evidence


def test_invalid_bucket_name_is_live_failed(initialized: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BEACON_LOGS_BUCKET", "../evidence")
    result = LakeLogPlugin().collect(CollectContext(live=True))
    assert result.mode == "live_failed"
    assert result.payload["findings"] == []


def test_bad_access_line_fails_closed() -> None:
    with pytest.raises(RuntimeError):
        parse_s3_access_log(b"this is not an access log\n", "s3-access-logs/bad")


def test_access_log_status_is_the_field_after_the_request_uri() -> None:
    line = (
        "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be "
        "bucket [21/Sep/2026:12:00:00 +0000] 192.0.2.10 requester REQ "
        'REST.GET.OBJECT key "GET /bucket/key" 200 " HTTP/1.1" 403 - -\n'
    )
    rows = parse_s3_access_log(line.encode("utf-8"), "s3-access-logs/spoof")
    assert rows[0]["http_status"] == 403
    assert "GET /bucket" not in json.dumps(rows)


def test_lifecycle_operation_is_an_access_record() -> None:
    line = (
        "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be "
        "beacon-evidence-fixture [21/Sep/2026:12:00:00 +0000] - AmazonS3 REQ "
        "S3.EXPIRE.OBJECT tenant/ws/old.json - - - - - - - - - - - -\n"
    )
    rows = parse_s3_access_log(line.encode("utf-8"), "s3-access-logs/lifecycle")
    assert rows[0]["operation"] == "S3.EXPIRE.OBJECT"
    assert rows[0]["http_status"] is None


def test_unmarked_s3_event_is_not_a_data_event() -> None:
    body = json.dumps(
        {"Records": [{"eventSource": "s3.amazonaws.com", "eventName": "CreateBucket"}]}
    ).encode("utf-8")
    with pytest.raises(RuntimeError, match="no S3 data events"):
        parse_cloudtrail_data_events(body, "cloudtrail/file.json")


def test_gzip_expansion_is_capped() -> None:
    body = json.dumps({"Records": [TRAIL["Records"][0]] * 2000}).encode("utf-8")
    compressed = gzip.compress(body)
    with pytest.raises(RuntimeError, match="expands past"):
        parse_cloudtrail_data_events(compressed, "cloudtrail/file.json.gz", max_bytes=1000)


def test_management_event_is_not_a_data_event() -> None:
    body = json.dumps(
        {
            "Records": [
                {
                    "eventSource": "s3.amazonaws.com",
                    "eventName": "CreateBucket",
                    "eventCategory": "Management",
                    "managementEvent": True,
                }
            ]
        }
    ).encode("utf-8")
    with pytest.raises(RuntimeError, match="no S3 data events"):
        parse_cloudtrail_data_events(body, "cloudtrail/file.json")


def test_live_read_seals_both_classes(initialized: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws(monkeypatch)
    monkeypatch.setenv("BEACON_LOGS_BUCKET", LOGS_BUCKET)
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        _put_pair(
            s3,
            trail_key="cloudtrail/AWSLogs/123/CloudTrail/us-east-1/2026/09/21/file.json.gz",
            trail_body=gzip.compress(json.dumps(TRAIL).encode("utf-8")),
        )
        s3.put_object(
            Bucket=LOGS_BUCKET,
            Key="cloudtrail/AWSLogs/123/CloudTrail-Digest/us-east-1/digest.json.gz",
            Body=b"not-a-data-event",
        )
        result = LakeLogPlugin().collect(CollectContext(live=True))
    assert result.ok is True
    assert result.mode == "live"
    blob = json.dumps(result.payload)
    assert "ASIAEXAMPLE" not in blob
    assert "SECRETKEY" not in blob
    keys = {item["key"] for item in result.payload["observations"]}
    assert "cloudtrail/AWSLogs/123/CloudTrail-Digest/us-east-1/digest.json.gz" not in keys
    assert any(key.endswith(".json.gz") for key in keys)


def test_live_missing_cloudtrail_is_live_failed(initialized: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws(monkeypatch)
    monkeypatch.setenv("BEACON_LOGS_BUCKET", LOGS_BUCKET)
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=LOGS_BUCKET)
        s3.put_object(Bucket=LOGS_BUCKET, Key="s3-access-logs/only", Body=ACCESS_LINE.encode("utf-8"))
        result = LakeLogPlugin().collect(CollectContext(live=True))
    assert result.ok is False
    assert result.mode == "live_failed"
    assert result.payload["findings"] == []
    assert result.payload["observations"] == []


def test_live_missing_bucket_is_live_failed(initialized: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws(monkeypatch)
    monkeypatch.setenv("BEACON_LOGS_BUCKET", LOGS_BUCKET)
    with mock_aws():
        result = LakeLogPlugin().collect(CollectContext(live=True))
    assert result.mode == "live_failed"
    assert "NoSuchBucket" in str(result.error) or "S3" in str(result.error)


def test_truncated_list_is_partial(initialized: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws(monkeypatch)
    monkeypatch.setenv("BEACON_LOGS_BUCKET", LOGS_BUCKET)
    monkeypatch.setenv("BEACON_LOGS_MAX_OBJECTS", "1")
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=LOGS_BUCKET)
        s3.put_object(Bucket=LOGS_BUCKET, Key="s3-access-logs/a", Body=ACCESS_LINE.encode("utf-8"))
        s3.put_object(Bucket=LOGS_BUCKET, Key="s3-access-logs/b", Body=ACCESS_LINE.encode("utf-8"))
        s3.put_object(
            Bucket=LOGS_BUCKET,
            Key="cloudtrail/AWSLogs/123/CloudTrail/us-east-1/file.json",
            Body=json.dumps(TRAIL).encode("utf-8"),
        )
        result = LakeLogPlugin().collect(CollectContext(live=True))
    assert result.ok is True
    assert result.payload["complete"] is False
    access = next(item for item in result.payload["findings"] if item["check"] == "s3_access_log_ingest")
    assert access["status"] == "collected_partial"


def test_collect_named_checks_chain(initialized: Path) -> None:
    sealed = collect_named(load_settings(), PLUGIN_NAME, CollectContext(live=False))
    assert sealed["ok"] is True
    assert sealed["mode"] == "fixture"
    assert sealed["checkpoint"]["merkle_root"]
    check_chain(load_settings())


def test_seal_without_checkpoint_fails_closed(initialized: Path) -> None:
    result = LakeLogPlugin().collect(CollectContext(live=False))
    seal_payload(
        load_settings(),
        plugin=PLUGIN_NAME,
        mode=result.mode,
        scf_targets=["IAC-01"],
        payload=result.payload,
    )
    with pytest.raises(BeaconError) as caught:
        check_chain(load_settings())
    assert caught.value.code == E_NO_CHECKPOINT
