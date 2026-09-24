"""Read S3 access logs and CloudTrail data events. Seal them as observations.

Raw AWS objects stay in the logging bucket. This plugin does not copy those
objects into the evidence bucket. The witness seal stores a bounded extract
plus the SHA-256 of each object. ``publish_sealed_record`` then writes the
Beacon observation and the derived finding.
"""

from __future__ import annotations

import gzip
import io
import json
import re
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from beacon.canonical import sha256_bytes
from beacon.config import env
from beacon.plugins.spec import CollectContext, CollectResult, FetcherSpec

PLUGIN_NAME = "aws.lake.logs"
SCHEMA_VERSION = "1.0"
# 2026.3 IAC-02 is legacy IAC-01 (IAM). 2026.3 IAC-01 is a new policy control.
SCF_TARGET = "IAC-02"
S3_ACCESS_LOG_PREFIX = "s3-access-logs/"
CLOUDTRAIL_PREFIX = "cloudtrail/"
DEFAULT_MAX_OBJECTS = 25
DEFAULT_MAX_BYTES = 20 * 1024 * 1024
SAMPLE_LIMIT = 5
_MAX_LIST_PAGES = 40
_DATE_LOOKBACK_DAYS = 366
_LIST_PAGE_SIZE = 1000
FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "aws.lake.logs.json"

_BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_ACCESS_TIME = re.compile(r"\[[^\[\]]+\]")
_ACCESS_OP_FIELD = re.compile(r"^(?:REST|SOAP|WEBSITE|BATCH|S3)\.[A-Z0-9._]+$")
_ACCESS_STATUS_AFTER_HTTP = re.compile(r'HTTP/\d(?:\.\d)?"\s+(\d{3}|-)\b')
_ACCESS_BUCKET = re.compile(r"^\S+\s+(\S+)\s+\[")
_ACCESS_DAY_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}")

_TRAIL_FIELDS = (
    "eventID",
    "eventTime",
    "eventName",
    "eventSource",
    "eventCategory",
    "awsRegion",
    "readOnly",
    "managementEvent",
    "recipientAccountId",
    "errorCode",
)


def _positive_int(name: str, default: int) -> int:
    raw = env(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw).strip())
    except ValueError as exc:
        raise ValueError(f"BEACON_{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"BEACON_{name} must be a positive integer")
    return value


def _prefix_ok(value: str) -> bool:
    if not value.endswith("/") or value.startswith("/") or len(value) > 128:
        return False
    return ".." not in value and "\\" not in value and "//" not in value


def _prefix(name: str, default: str) -> str:
    raw = (env(name) or "").strip() or default
    if not _prefix_ok(raw):
        raise ValueError(f"BEACON_{name} is not a safe S3 prefix")
    return raw


def _logs_bucket() -> str | None:
    raw = (env("LOGS_BUCKET") or "").strip()
    if not raw:
        return None
    if not _BUCKET_NAME.fullmatch(raw):
        raise ValueError("BEACON_LOGS_BUCKET is not a valid S3 bucket name")
    return raw


def _target_allowed(ctx: CollectContext) -> bool:
    if not ctx.target:
        return True
    return ctx.target.strip().upper() == SCF_TARGET


def _targets_for(_ctx: CollectContext) -> tuple[str, ...]:
    return (SCF_TARGET,)


def _key_ok(key: str) -> bool:
    if not key or key.startswith("/") or key.endswith("/") or len(key) > 1024:
        return False
    return ".." not in key and "\\" not in key


def _aws_failure(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        code = str(exc.response.get("Error", {}).get("Code") or "ClientError")
        return f"S3 {code}"
    if isinstance(exc, BotoCoreError):
        return "S3 request failed"
    return str(exc)


def _safe_error(exc: Exception) -> str:
    text = str(exc).splitlines()[0].strip() if str(exc) else exc.__class__.__name__
    return text[:300]


def _is_cloudtrail_data_log(key: str) -> bool:
    folded = key.casefold()
    if "cloudtrail-digest" in folded:
        return False
    return folded.endswith(".json") or folded.endswith(".json.gz")


def _split_log_fields(line: str) -> list[str]:
    """Split an access-log line. Quoted fields stay one field. Do not keep the text."""
    fields: list[str] = []
    buf: list[str] = []
    in_quotes = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and line[i + 1] == '"':
            buf.append('"')
            i += 2
            continue
        if ch == '"' and in_quotes and i + 1 < len(line) and line[i + 1] == '"':
            buf.append('"')
            i += 2
            continue
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
            i += 1
            continue
        if ch == " " and not in_quotes:
            if buf:
                fields.append("".join(buf))
                buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        fields.append("".join(buf))
    return fields


def _operation_field(fields: list[str]) -> str | None:
    for field in fields:
        if _ACCESS_OP_FIELD.fullmatch(field):
            return field
    return None


def _http_status(line: str, operation: str) -> int | None:
    """Status is the token after the last request-URI, not a number inside that URI."""
    matches = list(_ACCESS_STATUS_AFTER_HTTP.finditer(line))
    if matches:
        token = matches[-1].group(1)
        if token == "-":
            return None
        return int(token)
    if operation.startswith("S3."):
        return None
    return None


def _parse_access_line(line: str) -> dict[str, Any] | None:
    if _ACCESS_TIME.search(line) is None:
        return None
    fields = _split_log_fields(line)
    operation = _operation_field(fields)
    if operation is None:
        return None
    if _ACCESS_STATUS_AFTER_HTTP.search(line) is None and not operation.startswith("S3."):
        return None
    bucket = _ACCESS_BUCKET.match(line)
    row: dict[str, Any] = {
        "operation": operation,
        "http_status": _http_status(line, operation),
        "line_sha256": sha256_bytes(line.encode("utf-8")),
    }
    if bucket is not None:
        row["bucket_name"] = bucket.group(1)
    return row


def parse_s3_access_log(body: bytes, key: str) -> list[dict[str, Any]]:
    """Parse an S3 server access log. Reject lines that are not access records."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"S3 access log is not UTF-8: {key}") from exc
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parsed = _parse_access_line(line)
        if parsed is None:
            raise RuntimeError(f"S3 access log line is not a server access record: {key}")
        rows.append(parsed)
    if not rows:
        raise RuntimeError(f"S3 access log has no records: {key}")
    return rows


def _is_s3_data_event(row: dict[str, Any]) -> bool:
    if row.get("eventSource") != "s3.amazonaws.com":
        return False
    name = row.get("eventName")
    if not isinstance(name, str) or not name.strip():
        return False
    category = row.get("eventCategory")
    if category == "Data":
        return True
    return row.get("managementEvent") is False and category in (None, "Data")


def _resource_arns(row: dict[str, Any]) -> list[str]:
    found: list[str] = []
    resources = row.get("resources")
    if not isinstance(resources, list):
        return found
    for item in resources:
        if not isinstance(item, dict):
            continue
        arn = item.get("ARN")
        if isinstance(arn, str) and arn.strip():
            found.append(arn.strip()[:512])
        if len(found) >= SAMPLE_LIMIT:
            break
    return found


def _public_trail_record(row: dict[str, Any]) -> dict[str, Any]:
    public: dict[str, Any] = {}
    for field in _TRAIL_FIELDS:
        value = row.get(field)
        if isinstance(value, str) and value.strip():
            public[field] = value.strip()[:256]
        elif isinstance(value, bool):
            public[field] = value
    arns = _resource_arns(row)
    if arns:
        public["resource_arns"] = arns
    return public


def _gunzip_if_needed(key: str, body: bytes, max_bytes: int) -> bytes:
    if not (key.casefold().endswith(".gz") or body.startswith(b"\x1f\x8b")):
        return body
    chunks: list[bytes] = []
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as decoder:
            while True:
                chunk = decoder.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise RuntimeError(f"CloudTrail object expands past {max_bytes} bytes: {key}")
                chunks.append(chunk)
    except RuntimeError:
        raise
    except (gzip.BadGzipFile, EOFError, OSError, zlib.error) as exc:
        raise RuntimeError(f"CloudTrail object is not valid gzip: {key}") from exc
    return b"".join(chunks)


def parse_cloudtrail_data_events(
    body: bytes, key: str, *, max_bytes: int = DEFAULT_MAX_BYTES
) -> list[dict[str, Any]]:
    """Parse a CloudTrail log and keep marked S3 data events only."""
    raw = _gunzip_if_needed(key, body, max_bytes)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"CloudTrail object is not JSON: {key}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"CloudTrail object is not a JSON object: {key}")
    records = data.get("Records")
    if not isinstance(records, list) or not records:
        raise RuntimeError(f"CloudTrail object has no Records: {key}")
    kept: list[dict[str, Any]] = []
    for row in records:
        if not isinstance(row, dict):
            raise RuntimeError(f"CloudTrail record is not an object: {key}")
        if _is_s3_data_event(row):
            kept.append(_public_trail_record(row))
    if not kept:
        raise RuntimeError(f"CloudTrail object has no S3 data events: {key}")
    return kept


def _observation(
    log_class: str,
    bucket: str,
    key: str,
    raw: bytes,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    shown = records[:SAMPLE_LIMIT]
    return {
        "log_class": log_class,
        "bucket": bucket,
        "key": key,
        "sha256": sha256_bytes(raw),
        "byte_len": len(raw),
        "record_count": len(records),
        "records_truncated": len(records) > SAMPLE_LIMIT,
        "records": shown,
    }


def _finding(check: str, status: str, count: int, scf: str) -> dict[str, Any]:
    return {
        "scf": scf,
        "check": check,
        "status": status,
        "severity": "info",
        "observation_count": count,
        "detail": (
            "Logging-bucket objects were read and sealed as observations. "
            "Raw AWS log files stay in the logging bucket. "
            "This finding does not assert that the control is met."
        ),
    }


def _class_status(truncated: bool) -> str:
    if truncated:
        return "collected_partial"
    return "collected"


def _success_payload(
    *,
    mode: str,
    ctx: CollectContext,
    bucket: str,
    observations: list[dict[str, Any]],
    access_truncated: bool,
    trail_truncated: bool,
    fixture_reason: str | None,
) -> dict[str, Any]:
    scf = _targets_for(ctx)[0]
    access_count = sum(1 for item in observations if item["log_class"] == "s3_access_log")
    trail_count = sum(1 for item in observations if item["log_class"] == "cloudtrail_data_event")
    complete = not access_truncated and not trail_truncated
    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": PLUGIN_NAME,
        "cloud": "aws",
        "mode": mode,
        "ok": True,
        "target": ctx.target,
        "scf": scf,
        "logs_bucket": bucket,
        "complete": complete,
        "truncated": not complete,
        "class_separation": {
            "raw_logs_remain_in_logging_bucket": True,
            "observation_beacon_class": "observation",
            "finding_beacon_class": "finding",
        },
        "coverage": {
            "s3_access_log": {"objects": access_count, "truncated": access_truncated},
            "cloudtrail_data_event": {"objects": trail_count, "truncated": trail_truncated},
        },
        "observations": observations,
        "findings": [
            _finding("s3_access_log_ingest", _class_status(access_truncated), access_count, scf),
            _finding(
                "cloudtrail_data_event_ingest",
                _class_status(trail_truncated),
                trail_count,
                scf,
            ),
        ],
    }
    if fixture_reason:
        body["fixture_reason"] = fixture_reason
    return body


def _failure_payload(
    ctx: CollectContext,
    mode: str,
    error: str,
    *,
    reason: str | None = None,
    scf: str | None = SCF_TARGET,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": PLUGIN_NAME,
        "cloud": "aws",
        "mode": mode,
        "ok": False,
        "target": ctx.target,
        "complete": False,
        "truncated": False,
        "observations": [],
        "findings": [],
        "error": error,
    }
    if scf is not None:
        body["scf"] = scf
    if reason:
        body["fixture_reason"] = reason
    return body


def _s3_list(
    client: Any,
    bucket: str,
    prefix: str,
    *,
    token: str | None = None,
    delimiter: str | None = None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": _LIST_PAGE_SIZE}
    if token:
        kwargs["ContinuationToken"] = token
    if delimiter:
        kwargs["Delimiter"] = delimiter
    try:
        response = client.list_objects_v2(**kwargs)
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(_aws_failure(exc)) from exc
    if not isinstance(response, dict):
        raise RuntimeError("S3 request failed")
    return response


def _require_key(key: str) -> None:
    if not _key_ok(key):
        raise RuntimeError(f"refusing log object key: {key[:128]}")


def _page_keys(client: Any, bucket: str, prefix: str) -> tuple[list[str], bool]:
    """Return object keys under ``prefix``. The flag is true when the page cap stops the walk."""
    keys: list[str] = []
    token: str | None = None
    for _page in range(_MAX_LIST_PAGES):
        response = _s3_list(client, bucket, prefix, token=token)
        for item in response.get("Contents") or []:
            key = str(item.get("Key") or "")
            if not key or key.endswith("/"):
                continue
            keys.append(key)
        if not response.get("IsTruncated"):
            return keys, False
        token = response.get("NextContinuationToken")
        if not token:
            return keys, True
    return keys, True


def _list_level(client: Any, bucket: str, prefix: str) -> tuple[list[str], list[str], bool]:
    """Return keys and child prefixes at one ``/`` level."""
    keys: list[str] = []
    children: list[str] = []
    token: str | None = None
    for _page in range(_MAX_LIST_PAGES):
        response = _s3_list(client, bucket, prefix, token=token, delimiter="/")
        for item in response.get("Contents") or []:
            key = str(item.get("Key") or "")
            if not key or key.endswith("/"):
                continue
            keys.append(key)
        for item in response.get("CommonPrefixes") or []:
            child = str(item.get("Prefix") or "")
            if child:
                children.append(child)
        if not response.get("IsTruncated"):
            return keys, children, False
        token = response.get("NextContinuationToken")
        if not token:
            return keys, children, True
    return keys, children, True


def _tail_match(
    keys: list[str],
    limit: int,
    predicate: Callable[[str], bool],
    truncated: bool,
) -> tuple[list[str], bool]:
    """Keep the lexicographically last ``limit`` keys that pass ``predicate``."""
    matched: list[str] = []
    for key in keys:
        _require_key(key)
        if predicate(key):
            matched.append(key)
    matched.sort()
    if len(matched) > limit:
        return matched[-limit:], True
    return matched, truncated


def _is_digest_prefix(prefix: str) -> bool:
    """CloudTrail digest keys sort before ``CloudTrail/`` data-event keys."""
    return "cloudtrail-digest/" in prefix.casefold()


def _newest_slice_keys(client: Any, bucket: str, day_prefix: str, limit: int) -> tuple[list[str], bool]:
    """Keys under one UTC day. A truncated day is read from the newest hour backward."""
    keys, truncated = _page_keys(client, bucket, day_prefix)
    if not truncated:
        return keys, False
    gathered: list[str] = []
    for hour in range(23, -1, -1):
        hour_keys, hour_truncated = _page_keys(client, bucket, f"{day_prefix}-{hour:02d}")
        gathered.extend(hour_keys)
        if hour_truncated or len(gathered) >= limit:
            return gathered, True
    return gathered, True


def _newest_dated_flat(
    client: Any,
    bucket: str,
    prefix: str,
    limit: int,
    predicate: Callable[[str], bool],
) -> tuple[list[str], bool] | None:
    """Newest access-log keys. Names start with ``YYYY-MM-DD``. None when no dated key exists."""
    today = datetime.now(timezone.utc).date()
    found: list[str] = []
    saw = False
    for back in range(_DATE_LOOKBACK_DAYS):
        day = today - timedelta(days=back)
        day_prefix = f"{prefix}{day.isoformat()}"
        day_keys, _day_truncated = _newest_slice_keys(client, bucket, day_prefix, limit)
        for key in day_keys:
            if not key.startswith(prefix):
                continue
            if _ACCESS_DAY_STAMP.match(key[len(prefix) :]) is None:
                continue
            _require_key(key)
            if predicate(key):
                found.append(key)
                saw = True
        if len(found) >= limit:
            break
    if not saw:
        return None
    found.sort()
    if len(found) > limit:
        found = found[-limit:]
    return found, True


def _newest_under(
    client: Any,
    bucket: str,
    prefix: str,
    limit: int,
    predicate: Callable[[str], bool],
) -> tuple[list[str], bool]:
    """Newest matching keys under ``prefix``.

    ListObjectsV2 is ascending. Access-log keys and CloudTrail data-event keys
    encode time, so the last key is the newest. The module trail is single-region,
    and date folders are zero-padded, so the last child prefix is the newest folder.
    """
    if limit <= 0:
        return [], True
    objects, children, level_trunc = _list_level(client, bucket, prefix)
    children = sorted(child for child in children if not _is_digest_prefix(child))
    if children and objects:
        keys, scan_trunc = _page_keys(client, bucket, prefix)
        return _tail_match(keys, limit, predicate, scan_trunc or level_trunc)
    if children:
        selected: list[str] = []
        truncated = level_trunc
        for index, child in enumerate(reversed(children)):
            need = limit - len(selected)
            if need <= 0:
                return selected[-limit:], True
            child_keys, child_trunc = _newest_under(client, bucket, child, need, predicate)
            selected = child_keys + selected
            if child_trunc or len(selected) >= limit:
                more_children = index < len(children) - 1
                return selected[-limit:], truncated or child_trunc or more_children
        if len(selected) > limit:
            return selected[-limit:], True
        return selected, truncated
    if level_trunc:
        dated = _newest_dated_flat(client, bucket, prefix, limit, predicate)
        if dated is not None:
            return dated
    return _tail_match(objects, limit, predicate, level_trunc)


def _list_keys(
    client: Any,
    bucket: str,
    prefix: str,
    limit: int,
    predicate: Callable[[str], bool],
) -> tuple[list[str], bool]:
    """Return up to ``limit`` newest keys. Skip keys the predicate rejects."""
    return _newest_under(client, bucket, prefix, limit, predicate)


def _read_object(client: Any, bucket: str, key: str, max_bytes: int) -> bytes:
    try:
        response = client.get_object(Bucket=bucket, Key=key)
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"{_aws_failure(exc)} for {key}") from exc
    stream = response["Body"]
    try:
        try:
            body = stream.read(max_bytes + 1)
        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(f"{_aws_failure(exc)} for {key}") from exc
    finally:
        stream.close()
    if len(body) > max_bytes:
        raise RuntimeError(f"log object exceeds {max_bytes} bytes: {key}")
    if not body:
        raise RuntimeError(f"log object is empty: {key}")
    return body


def _ingest_live(client: Any, bucket: str) -> tuple[list[dict[str, Any]], bool, bool]:
    limit = _positive_int("LOGS_MAX_OBJECTS", DEFAULT_MAX_OBJECTS)
    max_bytes = _positive_int("LOGS_MAX_BYTES", DEFAULT_MAX_BYTES)
    access_prefix = _prefix("LOGS_ACCESS_PREFIX", S3_ACCESS_LOG_PREFIX)
    trail_prefix = _prefix("LOGS_CLOUDTRAIL_PREFIX", CLOUDTRAIL_PREFIX)
    access_keys, access_truncated = _list_keys(client, bucket, access_prefix, limit, lambda _key: True)
    trail_keys, trail_list_truncated = _list_keys(
        client, bucket, trail_prefix, limit, _is_cloudtrail_data_log
    )
    if not access_keys:
        raise RuntimeError("logging bucket has no S3 access log objects")
    if not trail_keys:
        raise RuntimeError("logging bucket has no CloudTrail data-event objects")
    observations: list[dict[str, Any]] = []
    for key in access_keys:
        raw = _read_object(client, bucket, key, max_bytes)
        records = parse_s3_access_log(raw, key)
        observations.append(_observation("s3_access_log", bucket, key, raw, records))
    for key in trail_keys:
        raw = _read_object(client, bucket, key, max_bytes)
        records = parse_cloudtrail_data_events(raw, key, max_bytes=max_bytes)
        observations.append(_observation("cloudtrail_data_event", bucket, key, raw, records))
    return observations, access_truncated, trail_list_truncated


class LakeLogPlugin:
    """Builtin collector for the evidence-lake logging bucket."""

    spec = FetcherSpec(
        name=PLUGIN_NAME,
        version="0.1.0",
        description=(
            "Read S3 server access logs and CloudTrail data events from the "
            "logging bucket. Seal observations and findings. Do not copy raw logs."
        ),
        category="aws",
        scf_targets=(SCF_TARGET,),
        tools=(),
    )

    def collect(self, ctx: CollectContext) -> CollectResult:
        if not _target_allowed(ctx):
            return self._refused(ctx, "lake log collector seals IAC-02 only")
        force_fixture = bool(ctx.extra.get("force_fixture"))
        if ctx.live is True:
            force_fixture = False
        if force_fixture or ctx.live is False:
            return self._fixture_result(ctx, reason="forced_fixture")
        try:
            bucket = _logs_bucket()
        except ValueError as exc:
            return self._live_failed(ctx, str(exc))
        if not bucket:
            if ctx.live is True:
                return self._live_failed(ctx, "BEACON_LOGS_BUCKET is not set")
            return self._fixture_result(ctx, reason="no_logs_bucket")
        try:
            observations, access_truncated, trail_truncated = _ingest_live(boto3.client("s3"), bucket)
        except Exception as exc:
            return self._live_failed(ctx, _safe_error(exc))
        payload = _success_payload(
            mode="live",
            ctx=ctx,
            bucket=bucket,
            observations=observations,
            access_truncated=access_truncated,
            trail_truncated=trail_truncated,
            fixture_reason=None,
        )
        return CollectResult(ok=True, mode="live", payload=payload, scf_targets=_targets_for(ctx))

    def _fixture_result(self, ctx: CollectContext, reason: str) -> CollectResult:
        try:
            fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
            if not isinstance(fixture, dict):
                raise ValueError("fixture is not a JSON object")
            access_text = fixture.get("s3_access_log")
            trail = fixture.get("cloudtrail")
            if not isinstance(access_text, str) or not isinstance(trail, dict):
                raise ValueError("fixture is missing s3_access_log or cloudtrail")
            access_raw = access_text.encode("utf-8")
            trail_raw = json.dumps(trail).encode("utf-8")
            access_key = f"{S3_ACCESS_LOG_PREFIX}fixture"
            trail_key = f"{CLOUDTRAIL_PREFIX}fixture.json"
            observations = [
                _observation(
                    "s3_access_log",
                    "fixture",
                    access_key,
                    access_raw,
                    parse_s3_access_log(access_raw, access_key),
                ),
                _observation(
                    "cloudtrail_data_event",
                    "fixture",
                    trail_key,
                    trail_raw,
                    parse_cloudtrail_data_events(trail_raw, trail_key),
                ),
            ]
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            payload = _failure_payload(ctx, "fixture", str(exc), reason="fixture_unreadable")
            return CollectResult(
                ok=False,
                mode="fixture",
                payload=payload,
                error=str(exc),
                scf_targets=_targets_for(ctx),
            )
        payload = _success_payload(
            mode="fixture",
            ctx=ctx,
            bucket="fixture",
            observations=observations,
            access_truncated=False,
            trail_truncated=False,
            fixture_reason=reason,
        )
        return CollectResult(ok=True, mode="fixture", payload=payload, scf_targets=_targets_for(ctx))

    def _live_failed(self, ctx: CollectContext, error: str) -> CollectResult:
        payload = _failure_payload(ctx, "live_failed", error)
        return CollectResult(
            ok=False,
            mode="live_failed",
            payload=payload,
            error=error,
            scf_targets=_targets_for(ctx),
        )

    def _refused(self, ctx: CollectContext, error: str) -> CollectResult:
        mode = "live_failed" if ctx.live is True else "failed"
        payload = _failure_payload(ctx, mode, error, scf=None)
        return CollectResult(
            ok=False,
            mode=mode,
            payload=payload,
            error=error,
            scf_targets=(),
        )


PLUGIN = LakeLogPlugin()
