"""S3 evidence lake and DynamoDB artifact index.

Local seal always runs first. Remote write is a dual-write after the local
witness chain. This module does not upload ``.beacon/keys``, ``*.pem`` private keys, ``config.json``, or ``cache/``.

Raw observations stay under ``observations/``. Derived findings stay under
``evidence/``. Draft packs stay under ``exports/packs/``. The allowlisted
``public/trust-center/`` prefix never holds raw observations by default.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal, NoReturn
from urllib.parse import urlencode

try:
    import boto3
    from boto3.dynamodb.conditions import Key
    from botocore.exceptions import ClientError
except ImportError:  # pragma: no cover
    boto3 = None  # type: ignore[assignment]
    Key = None  # type: ignore[assignment]
    ClientError = Exception  # type: ignore[misc, assignment]

from beacon.canonical import dumps, sha256_bytes, sha256_obj
from beacon.config import (
    KMS_ALIAS_BEACON_EVIDENCE,
    PACK_TYPES,
    REPORT_FORMATS,
    Settings,
    ensure_layout,
    observation_expires_at,
    observation_is_expired,
)
from beacon.crypto.witness import (
    Checkpoint,
    Record,
    check_chain,
    iter_jsonl,
    load_checkpoints,
    load_records,
)
from beacon.locking import locked
from beacon.crypto.trust import read_trust, trust_path, local_head, advance_head
from beacon.errors import E_REMOTE, BeaconError, fail

ArtifactKind = Literal[
    "observation",
    "finding",
    "records",
    "checkpoints",
    "pack",
    "report",
    "import",
]

PRIVATE_NAMES = frozenset({"recorder.pem", "witness.pem", "tsa.pem"})
PRIVATE_SUFFIXES = frozenset({".sec", ".pem"})
LOCK_MODES = frozenset({"GOVERNANCE", "COMPLIANCE"})
TAG_SAFE = re.compile(r"[^0-9A-Za-z+\-.:/@_]")
PACK_NAME_RE = re.compile(r"^beacon-pack-(.+)\.json$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
TRUST_CENTER_KINDS = frozenset({"pack", "report"})
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_MARKDOWN = "text/markdown; charset=utf-8"
CONTENT_TYPE_ACTIVITY_LOG = "application/x-ndjson"


def _never(value: object) -> NoReturn:
    raise AssertionError(f"unhandled value: {value}")


def validate_scope_id(name: str, value: str) -> str:
    if not value or not SAFE_ID.match(value):
        fail(E_REMOTE, f"invalid {name}")
    if "#" in value or "/" in value or "\\" in value or ".." in value:
        fail(E_REMOTE, f"invalid {name}")
    return value


def validate_artifact_id(name: str, value: str) -> str:
    if not value or not SAFE_ID.match(value):
        fail(E_REMOTE, f"invalid {name} in index: {value!r}")
    if "/" in value or "\\" in value or ".." in value:
        fail(E_REMOTE, f"invalid {name} in index: {value!r}")
    return value


def validate_pack_type(pack_type: str) -> str:
    value = (pack_type or "").strip().lower()
    if value not in PACK_TYPES:
        fail(
            E_REMOTE,
            "BEACON_PACK_TYPE must be bundle, ongoing-certification-report, "
            "secure-configuration-guide, or security-decision-record",
        )
    return value


def validate_report_format(report_format: str) -> str:
    value = (report_format or "").strip().lower()
    if value not in REPORT_FORMATS:
        fail(E_REMOTE, "report_format must be bundle, json, markdown, or activity-log")
    return value


def checkpoint_id(checkpoint: Checkpoint) -> str:
    return f"{checkpoint.from_seq:08d}-{checkpoint.to_seq:08d}-{checkpoint.tsa_serial}"


def record_id(record: Record) -> str:
    return record.evidence_id


def _join_prefix(prefix: str, key: str) -> str:
    prefix = (prefix or "").strip().strip("/")
    if prefix:
        return f"{prefix}/{key}"
    return key


def observation_object_key(
    tenant_id: str,
    workspace_id: str,
    evidence_id: str,
    *,
    prefix: str = "",
) -> str:
    """Raw observation payload. Local file remains ``evidence/{uuid}.json``."""
    return _join_prefix(
        prefix, f"{tenant_id}/{workspace_id}/observations/{evidence_id}.json"
    )


def finding_object_key(
    tenant_id: str,
    workspace_id: str,
    evidence_id: str,
    *,
    prefix: str = "",
) -> str:
    """Derived finding/assertion: canonical sealed Record JSON."""
    return _join_prefix(prefix, f"{tenant_id}/{workspace_id}/evidence/{evidence_id}.json")


def evidence_object_key(
    tenant_id: str,
    workspace_id: str,
    evidence_id: str,
    *,
    prefix: str = "",
) -> str:
    """Finding object (derived Record). Use ``observation_object_key`` for raw payload."""
    return finding_object_key(tenant_id, workspace_id, evidence_id, prefix=prefix)


def import_object_key(
    tenant_id: str,
    workspace_id: str,
    import_id: str,
    *,
    prefix: str = "",
) -> str:
    return _join_prefix(prefix, f"{tenant_id}/{workspace_id}/imports/{import_id}.json")


def records_jsonl_key(tenant_id: str, workspace_id: str, *, prefix: str = "") -> str:
    """Match local ``chain/records.jsonl``."""
    return _join_prefix(prefix, f"{tenant_id}/{workspace_id}/chain/records.jsonl")


def checkpoints_jsonl_key(tenant_id: str, workspace_id: str, *, prefix: str = "") -> str:
    """Match local ``chain/checkpoints.jsonl``."""
    return _join_prefix(prefix, f"{tenant_id}/{workspace_id}/chain/checkpoints.jsonl")


def pack_object_key(
    tenant_id: str,
    workspace_id: str,
    stamp: str,
    *,
    prefix: str = "",
    pack_type: str = "bundle",
    version: str | None = None,
    filename: str = "beacon-pack.json",
) -> str:
    """Versioned pack under ``exports/packs/{pack_type}/{version}/``."""
    pack_type = validate_pack_type(pack_type)
    version = validate_artifact_id("pack_version", version or stamp)
    validate_artifact_id("pack_filename", filename.replace(".", "-"))
    if "/" in filename or "\\" in filename or ".." in filename:
        fail(E_REMOTE, "invalid pack filename")
    return _join_prefix(
        prefix,
        f"{tenant_id}/{workspace_id}/exports/packs/{pack_type}/{version}/{filename}",
    )


def activity_log_object_key(
    tenant_id: str,
    workspace_id: str,
    stamp: str,
    *,
    prefix: str = "",
) -> str:
    stamp = validate_artifact_id("activity_log_stamp", stamp)
    return _join_prefix(
        prefix, f"{tenant_id}/{workspace_id}/exports/activity-log/{stamp}.jsonl"
    )


def _relative_parts(relative: str) -> list[str]:
    parts: list[str] = []
    for part in relative.replace("\\", "/").split("/"):
        if part in {"", "."}:
            continue
        if part == ".." or part == "~":
            fail(E_REMOTE, "invalid trust-center relative key")
        parts.append(part)
    return parts


def trust_center_object_key(
    tenant_id: str,
    workspace_id: str,
    relative: str,
    *,
    prefix: str = "",
) -> str:
    parts = _relative_parts(relative.strip())
    if not parts:
        fail(E_REMOTE, "invalid trust-center relative key")
    if any(part.lower() == "observations" for part in parts):
        fail(E_REMOTE, "trust-center refuses observation paths")
    rel = "/".join(parts)
    return _join_prefix(
        prefix, f"{tenant_id}/{workspace_id}/public/trust-center/{rel}"
    )


def s3_uri(bucket: str, key: str) -> str:
    return f"s3://{bucket}/{key}"


def partition_key(tenant_id: str, workspace_id: str) -> str:
    return f"{tenant_id}#{workspace_id}"


def class_tag(kind: ArtifactKind) -> str:
    match kind:
        case "observation":
            return "observation"
        case "finding":
            return "finding"
        case "records":
            return "chain-record"
        case "checkpoints":
            return "checkpoint"
        case "pack":
            return "pack"
        case "report":
            return "report"
        case "import":
            return "import"
        case _:
            _never(kind)


def is_trust_center_key(
    key: str,
    *,
    prefix: str = "",
    tenant_id: str | None = None,
    workspace_id: str | None = None,
) -> bool:
    """True only for ``{prefix/}{tenant}/{workspace}/public/trust-center/``."""
    if not tenant_id or not workspace_id:
        return False
    root = _join_prefix(prefix, f"{tenant_id}/{workspace_id}/")
    if not key.startswith(root):
        return False
    rel = key[len(root) :]
    return rel == "public/trust-center" or rel.startswith("public/trust-center/")


def assert_key_kind_allowed(
    key: str,
    kind: ArtifactKind,
    *,
    prefix: str = "",
    tenant_id: str | None = None,
    workspace_id: str | None = None,
) -> None:
    """Raw observations never land in the public/trust-center prefix."""
    if is_trust_center_key(
        key, prefix=prefix, tenant_id=tenant_id, workspace_id=workspace_id
    ) and kind not in TRUST_CENTER_KINDS:
        fail(
            E_REMOTE,
            "public/trust-center may hold pack or report exports only; "
            f"refusing kind={kind}",
        )
    if kind == "observation" and "/observations/" not in f"/{key}":
        fail(E_REMOTE, f"observation objects must use observations/: {key}")
    if kind == "import" and "/imports/" not in f"/{key}":
        fail(E_REMOTE, f"import objects must use imports/: {key}")


def _reject_secret_bytes(body: bytes, *, name: str) -> None:
    markers = (
        b"BEGIN PRIVATE KEY",
        b"BEGIN RSA PRIVATE KEY",
        b"BEGIN EC PRIVATE KEY",
        b"BEGIN OPENSSH PRIVATE KEY",
    )
    if any(marker in body for marker in markers):
        fail(E_REMOTE, f"refusing to upload private key material: {name}")


def _public_pack_bytes(body: bytes) -> bytes:
    """Trust-center packs keep hashes and findings, never raw observation payloads."""
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(E_REMOTE, "trust-center pack must be JSON")
    if not isinstance(data, dict):
        fail(E_REMOTE, "trust-center pack must be a JSON object")
    _reject_secret_bytes(body, name="trust-center pack")
    public = dict(data)
    evidence_rows = []
    for row in public.get("evidence") or []:
        if not isinstance(row, dict):
            continue
        evidence_rows.append({"evidence_id": row.get("evidence_id")})
    public["evidence"] = evidence_rows
    public["trust_center"] = True
    return dumps(public)


def assert_upload_allowed(settings: Settings, path: Path) -> None:
    """Refuse keys, cache, config, and private key material.

    Never upload ``*.pem`` private keys, ``*.sec``, ``.beacon/keys``,
    ``config.json``, or ``cache/``.
    """
    resolved = path.resolve()
    home = settings.home.resolve()
    if resolved.is_relative_to(settings.keys_dir.resolve()):
        fail(E_REMOTE, f"refusing to upload private key material: {path}")
    if resolved.is_relative_to(settings.cache_dir.resolve()):
        fail(E_REMOTE, f"refusing to upload cache: {path}")
    if resolved == (home / "config.json"):
        fail(E_REMOTE, f"refusing to upload workspace config: {path}")
    if resolved.suffix.lower() in PRIVATE_SUFFIXES:
        fail(E_REMOTE, f"refusing to upload {path.name}")
    if resolved.name in PRIVATE_NAMES:
        fail(E_REMOTE, f"refusing to upload {path.name}")


def _meta_value(value: str) -> str:
    return str(value).replace("\n", " ").replace("\r", " ")[:1024]


def _tag_value(value: str) -> str:
    cleaned = TAG_SAFE.sub("-", value)
    return (cleaned or "none")[:256]


def _now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _stamp_from_pack_path(path: Path) -> str:
    match = PACK_NAME_RE.match(path.name)
    if match:
        return match.group(1)
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _boto_missing() -> None:
    fail(E_REMOTE, "boto3 is not installed; pip install boto3")


def remote_ready(settings: Settings, *, command: bool = False) -> ArtifactLake | None:
    """Return a lake when S3 is configured. Fail closed when remote is required."""
    if not settings.s3_bucket:
        if settings.require_remote or command:
            fail(E_REMOTE, "BEACON_S3_BUCKET is not set")
        return None
    if not settings.tenant_id or not settings.workspace_id:
        fail(
            E_REMOTE,
            "BEACON_TENANT_ID and BEACON_WORKSPACE_ID are required when S3 is configured",
        )
    validate_scope_id("BEACON_TENANT_ID", settings.tenant_id)
    validate_scope_id("BEACON_WORKSPACE_ID", settings.workspace_id)
    if settings.s3_prefix:
        for part in settings.s3_prefix.split("/"):
            if part:
                validate_scope_id("BEACON_S3_PREFIX", part)
    if not settings.ddb_table:
        fail(E_REMOTE, "BEACON_DDB_TABLE is required when S3 is configured")
    if not settings.kms_key_arn:
        fail(E_REMOTE, "BEACON_KMS_KEY_ARN is required; S3 SSE-KMS is mandatory")
    if settings.object_lock_mode not in LOCK_MODES:
        fail(E_REMOTE, "BEACON_OBJECT_LOCK_MODE must be GOVERNANCE or COMPLIANCE")
    if settings.pack_type:
        validate_pack_type(settings.pack_type)
    return ArtifactLake(settings)


class ArtifactLake:
    """S3 object writer plus DynamoDB ``beacon-artifact-index`` (name via env)."""

    def __init__(self, settings: Settings) -> None:
        if boto3 is None:
            _boto_missing()
        if not settings.s3_bucket or not settings.ddb_table:
            fail(E_REMOTE, "S3 bucket and DynamoDB table are required")
        if not settings.tenant_id or not settings.workspace_id:
            fail(E_REMOTE, "tenant_id and workspace_id are required")
        if not settings.kms_key_arn:
            fail(E_REMOTE, "BEACON_KMS_KEY_ARN is required; S3 SSE-KMS is mandatory")
        self.settings = settings
        self.bucket = settings.s3_bucket
        self.table_name = settings.ddb_table
        self.tenant_id = settings.tenant_id
        self.workspace_id = settings.workspace_id
        self.prefix = settings.s3_prefix
        self.object_versions: dict[str, str] = {}
        session = boto3.session.Session()
        self.s3 = session.client("s3")
        self.ddb = session.resource("dynamodb").Table(self.table_name)

    @property
    def pk(self) -> str:
        return partition_key(self.tenant_id, self.workspace_id)

    def _put_bytes(
        self,
        key: str,
        body: bytes,
        *,
        kind: ArtifactKind,
        metadata: dict[str, str],
        content_type: str = CONTENT_TYPE_JSON,
        extra_tags: dict[str, str] | None = None,
    ) -> str:
        assert_key_kind_allowed(
            key,
            kind,
            prefix=self.prefix,
            tenant_id=self.tenant_id,
            workspace_id=self.workspace_id,
        )
        kms_key = self.settings.kms_key_arn or KMS_ALIAS_BEACON_EVIDENCE
        merged_meta = {"kind": kind, **metadata}
        tags = {
            "beacon-class": class_tag(kind),
            "beacon-tenant": _tag_value(self.tenant_id),
            "beacon-workspace": _tag_value(self.workspace_id),
            "beacon-kind": kind,
        }
        if extra_tags:
            tags.update({k: _tag_value(v) for k, v in extra_tags.items() if v})
        extra: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": body,
            "ContentType": content_type,
            "Metadata": {k: _meta_value(v) for k, v in merged_meta.items() if v},
            "Tagging": urlencode(tags),
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": kms_key,
        }
        if self.settings.object_lock_days > 0:
            retain = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) + dt.timedelta(
                days=self.settings.object_lock_days
            )
            extra["ObjectLockMode"] = self.settings.object_lock_mode
            extra["ObjectLockRetainUntilDate"] = retain
        try:
            response = self.s3.put_object(**extra)
        except ClientError as exc:
            fail(E_REMOTE, f"S3 PutObject failed for {key}: {exc}")
        uri = s3_uri(self.bucket, key)
        if response.get("VersionId") and response["VersionId"] != "null":
            self.object_versions[uri] = response["VersionId"]
        return uri

    def _index_put(self, sk: str, fields: dict[str, Any]) -> None:
        item = {**fields, "pk": self.pk, "sk": sk}
        for field, value in fields.items():
            if field.endswith("s3_uri") and value in self.object_versions:
                item[field.removesuffix("uri") + "version_id"] = self.object_versions[value]
        condition = {}
        if sk.startswith(("EVIDENCE#", "CP#")) and fields.get("sha256"):
            condition = {"ConditionExpression": "attribute_not_exists(pk) OR #digest = :digest",
                         "ExpressionAttributeNames": {"#digest": "sha256"},
                         "ExpressionAttributeValues": {":digest": fields["sha256"]}}
        try:
            self.ddb.put_item(Item=item, **condition)
        except ClientError as exc:
            fail(E_REMOTE, f"DynamoDB PutItem failed for {sk}: {exc}")

    def _index_get(self, sk: str) -> dict[str, Any] | None:
        try:
            resp = self.ddb.get_item(Key={"pk": self.pk, "sk": sk}, ConsistentRead=True)
        except ClientError as exc:
            fail(E_REMOTE, f"DynamoDB GetItem failed for {sk}: {exc}")
        return resp.get("Item")

    def query_index(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(self.pk),
            "ConsistentRead": True,
        }
        try:
            while True:
                resp = self.ddb.query(**kwargs)
                items.extend(resp.get("Items") or [])
                last = resp.get("LastEvaluatedKey")
                if not last:
                    break
                kwargs["ExclusiveStartKey"] = last
        except ClientError as exc:
            fail(E_REMOTE, f"DynamoDB Query failed: {exc}")
        return items

    def query_freshness(self) -> list[dict[str, Any]]:
        """Return FRESH# index rows with expired flags from sealed_at / expires_at."""
        now = dt.datetime.now(dt.timezone.utc)
        raw_items: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {
            "IndexName": "freshness",
            "KeyConditionExpression": Key("pk").eq(self.pk),
        }
        try:
            while True:
                resp = self.ddb.query(**kwargs)
                raw_items.extend(resp.get("Items") or [])
                last = resp.get("LastEvaluatedKey")
                if not last:
                    break
                kwargs["ExclusiveStartKey"] = last
        except ClientError:
            raw_items = [
                item
                for item in self.query_index()
                if str(item.get("sk") or "").startswith("FRESH#")
            ]
        rows: list[dict[str, Any]] = []
        for item in raw_items:
            sk = str(item.get("sk") or "")
            if not sk.startswith("FRESH#"):
                continue
            sealed = str(item.get("sealed_at") or "")
            expires = str(item.get("expires_at") or "")
            expired = True
            if sealed:
                try:
                    expired = observation_is_expired(sealed, now=now)
                    if not expires:
                        expires = observation_expires_at(sealed)
                except ValueError:
                    expired = True
            rows.append(
                {
                    **item,
                    "expires_at": expires,
                    "expired": expired,
                }
            )
        return rows

    def put_records_jsonl(self) -> dict[str, Any]:
        path = self.settings.chain_path
        assert_upload_allowed(self.settings, path)
        body = path.read_bytes() if path.exists() else b""
        digest = sha256_bytes(body)
        key = records_jsonl_key(self.tenant_id, self.workspace_id, prefix=self.prefix)
        uri = self._put_bytes(
            key,
            body,
            kind="records",
            metadata={"sha256": digest, "sealed_at": _now(), "report_format": "json"},
        )
        return {"kind": "records", "s3_uri": uri, "sha256": digest}

    def put_checkpoints_jsonl(self) -> dict[str, Any]:
        path = self.settings.checkpoints_path
        assert_upload_allowed(self.settings, path)
        body = path.read_bytes() if path.exists() else b""
        digest = sha256_bytes(body)
        key = checkpoints_jsonl_key(self.tenant_id, self.workspace_id, prefix=self.prefix)
        uri = self._put_bytes(
            key,
            body,
            kind="checkpoints",
            metadata={"sha256": digest, "sealed_at": _now()},
        )
        return {"kind": "checkpoints", "s3_uri": uri, "sha256": digest}

    def put_record_and_evidence(
        self,
        record: Record,
        evidence_path: Path,
        *,
        merkle_root: str = "",
        pack_id: str = "",
        sync_jsonl: bool = True,
        verified: bool = False,
    ) -> list[dict[str, Any]]:
        assert_upload_allowed(self.settings, evidence_path)
        payload = evidence_path.read_bytes()
        _reject_secret_bytes(payload, name=str(evidence_path))
        digest = sha256_bytes(payload)
        if digest != record.payload_sha256:
            fail(E_REMOTE, f"local evidence hash mismatch for {record.evidence_id}")
        rec_id = record_id(record)
        finding_body = dumps(record.to_dict())
        rec_digest = sha256_bytes(finding_body)
        obs_key = observation_object_key(
            self.tenant_id, self.workspace_id, record.evidence_id, prefix=self.prefix
        )
        finding_key = finding_object_key(
            self.tenant_id, self.workspace_id, record.evidence_id, prefix=self.prefix
        )
        rec_uri = s3_uri(
            self.bucket,
            records_jsonl_key(self.tenant_id, self.workspace_id, prefix=self.prefix),
        )
        extras: list[dict[str, Any]] = []
        if sync_jsonl:
            jsonl = self.put_records_jsonl()
            rec_uri = jsonl["s3_uri"]
            extras.append(jsonl)
        expires_at = observation_expires_at(record.ts)
        verified_flag = "true" if verified else "false"
        meta_common = {
            "sha256": digest,
            "input_sha256": digest,
            "audit_sha256": rec_digest,
            "audit_seq": str(record.seq),
            "prev_sha256": record.prev_sha256,
            "scf_targets": ",".join(record.scf_targets),
            "plugin": record.plugin,
            "sealed_at": record.ts,
            "expires_at": expires_at,
            "record_id": rec_id,
            "verified": verified_flag,
        }
        existing = self._index_get(f"EVIDENCE#{record.evidence_id}")
        if (
            existing
            and existing.get("sha256") == digest
            and existing.get("input_sha256") == digest
            and existing.get("audit_sha256") == rec_digest
            and existing.get("record_sha256") == rec_digest
            and self._object_matches(existing.get("s3_uri") or existing.get("observation_s3_uri"), digest)
            and self._object_matches(existing.get("finding_s3_uri"), rec_digest)
        ):
            updates = {}
            if pack_id and existing.get("pack_id") != pack_id:
                updates["pack_id"] = pack_id
            if merkle_root and existing.get("merkle_root") != merkle_root:
                updates["merkle_root"] = merkle_root
            updates["record_s3_uri"] = rec_uri
            updates["expires_at"] = expires_at
            updates["verified"] = verified_flag
            if updates:
                merged = {k: v for k, v in existing.items() if k not in {"pk", "sk"}}
                merged.update(updates)
                self._index_put(f"EVIDENCE#{record.evidence_id}", merged)
                self._index_put(f"FRESH#{record.plugin}", dict(merged))
            return [
                {
                    "kind": "observation",
                    "s3_uri": existing.get("s3_uri"),
                    "sha256": digest,
                    "skipped": True,
                    "pack_id": pack_id or existing.get("pack_id"),
                },
                {
                    "kind": "finding",
                    "s3_uri": existing.get("finding_s3_uri"),
                    "sha256": rec_digest,
                    "skipped": True,
                },
                *extras,
            ]
        extra_tags = {"beacon-verified": verified_flag}
        obs_uri = self._put_bytes(
            obs_key,
            payload,
            kind="observation",
            metadata={**meta_common, "kind": "observation"},
            extra_tags=extra_tags,
        )
        finding_uri = self._put_bytes(
            finding_key,
            finding_body,
            kind="finding",
            metadata={
                **meta_common,
                "kind": "finding",
                "sha256": rec_digest,
                "input_sha256": digest,
            },
            extra_tags=extra_tags,
        )
        fields = {
            "s3_uri": obs_uri,
            "observation_s3_uri": obs_uri,
            "finding_s3_uri": finding_uri,
            "sha256": digest,
            "input_sha256": digest,
            "audit_sha256": rec_digest,
            "finding_sha256": rec_digest,
            "prev_sha256": record.prev_sha256,
            "audit_seq": record.seq,
            "sealed_at": record.ts,
            "expires_at": expires_at,
            "control_ids": list(record.scf_targets),
            "merkle_root": merkle_root,
            "pack_id": pack_id,
            "plugin": record.plugin,
            "record_id": rec_id,
            "record_s3_uri": rec_uri,
            "record_sha256": rec_digest,
            "seq": record.seq,
            "verified": verified_flag,
            "kind": "finding",
        }
        self._index_put(f"EVIDENCE#{record.evidence_id}", fields)
        self._index_put(f"FRESH#{record.plugin}", dict(fields))
        return [
            {"kind": "observation", "s3_uri": obs_uri, "sha256": digest},
            {"kind": "finding", "s3_uri": finding_uri, "sha256": rec_digest},
            *extras,
        ]

    def put_unverified_import(self, import_id: str, body: bytes) -> dict[str, Any]:
        """Store an import as unverified until a review seal."""
        import_id = validate_artifact_id("import_id", import_id)
        _reject_secret_bytes(body, name=import_id)
        digest = sha256_bytes(body)
        key = import_object_key(
            self.tenant_id, self.workspace_id, import_id, prefix=self.prefix
        )
        sealed_at = _now()
        uri = self._put_bytes(
            key,
            body,
            kind="import",
            metadata={
                "kind": "import",
                "sha256": digest,
                "input_sha256": digest,
                "sealed_at": sealed_at,
                "expires_at": observation_expires_at(sealed_at),
                "verified": "false",
            },
            extra_tags={"beacon-verified": "false"},
        )
        fields = {
            "s3_uri": uri,
            "sha256": digest,
            "input_sha256": digest,
            "sealed_at": sealed_at,
            "expires_at": observation_expires_at(sealed_at),
            "verified": "false",
            "kind": "import",
        }
        self._index_put(f"IMPORT#{import_id}", fields)
        return {"kind": "import", "s3_uri": uri, "sha256": digest, "verified": False}

    def _object_matches(self, uri: object, digest: str) -> bool:
        if not uri:
            return False
        try:
            return sha256_bytes(self._get_object(str(uri))) == digest
        except BeaconError:
            return False

    def _unchanged(self, sk: str, digest: str, field: str = "sha256") -> bool:
        item = self._index_get(sk)
        return bool(item) and item.get(field) == digest

    def put_checkpoint(self, checkpoint: Checkpoint, *, pack_id: str = "") -> dict[str, Any]:
        cp_id = checkpoint_id(checkpoint)
        digest = sha256_bytes(dumps(checkpoint.to_dict()))
        sk = f"CP#{cp_id}"
        jsonl = self.put_checkpoints_jsonl()
        if self._unchanged(sk, digest):
            existing = self._index_get(sk)
            if existing:
                merged = {k: v for k, v in existing.items() if k not in {"pk", "sk"}}
                merged["s3_uri"] = jsonl["s3_uri"]
                if pack_id:
                    merged["pack_id"] = pack_id
                self._index_put(sk, merged)
            return {
                "kind": "checkpoints",
                "s3_uri": jsonl["s3_uri"],
                "sha256": digest,
                "checkpoint_id": cp_id,
                "skipped": True,
            }
        self._index_put(
            sk,
            {
                "s3_uri": jsonl["s3_uri"],
                "sha256": digest,
                "sealed_at": checkpoint.created_at,
                "control_ids": [],
                "merkle_root": checkpoint.merkle_root,
                "pack_id": pack_id,
                "checkpoint_id": cp_id,
            },
        )
        return {
            "kind": "checkpoints",
            "s3_uri": jsonl["s3_uri"],
            "sha256": digest,
            "checkpoint_id": cp_id,
        }

    def _maybe_trust_center(
        self,
        *,
        relative: str,
        body: bytes,
        kind: ArtifactKind,
        metadata: dict[str, str],
        content_type: str,
    ) -> dict[str, Any] | None:
        if not self.settings.trust_center_export:
            return None
        if kind not in TRUST_CENTER_KINDS:
            fail(E_REMOTE, "trust-center export refuses raw observations")
        export_body = body
        export_meta = dict(metadata)
        if kind == "pack" and content_type.split(";", 1)[0].strip() == CONTENT_TYPE_JSON:
            export_body = _public_pack_bytes(body)
            export_meta["sha256"] = sha256_bytes(export_body)
            export_meta["public"] = "true"
        key = trust_center_object_key(
            self.tenant_id, self.workspace_id, relative, prefix=self.prefix
        )
        uri = self._put_bytes(
            key,
            export_body,
            kind=kind,
            metadata=export_meta,
            content_type=content_type,
        )
        return {"kind": kind, "s3_uri": uri, "relative": relative}

    def put_pack(
        self,
        path: Path,
        *,
        stamp: str | None = None,
        pack_type: str | None = None,
        draft: bool | None = None,
        markdown_path: Path | None = None,
        report_format: str = "json",
    ) -> dict[str, Any]:
        assert_upload_allowed(self.settings, path)
        stamp = stamp or _stamp_from_pack_path(path)
        pack_type = validate_pack_type(pack_type or self.settings.pack_type)
        report_format = validate_report_format(report_format)
        if draft is None:
            draft = pack_type != "bundle"
        body = path.read_bytes()
        digest = sha256_bytes(body)
        key = pack_object_key(
            self.tenant_id,
            self.workspace_id,
            stamp,
            prefix=self.prefix,
            pack_type=pack_type,
            version=stamp,
        )
        meta = {
            "sha256": digest,
            "sealed_at": _now(),
            "record_id": stamp,
            "pack_type": pack_type,
            "pack_version": stamp,
            "draft": "true" if draft else "false",
            "report_format": report_format,
            "verified": "true",
        }
        uri = self._put_bytes(
            key,
            body,
            kind="pack",
            metadata=meta,
            content_type=CONTENT_TYPE_JSON,
            extra_tags={"beacon-verified": "true"},
        )
        extras: list[dict[str, Any]] = []
        md_path = markdown_path
        if md_path is None:
            candidate = path.with_suffix(".md")
            if candidate.exists():
                md_path = candidate
        if md_path is not None:
            extras.append(
                self.put_markdown_report(
                    md_path, pack_type=pack_type, version=stamp, draft=draft
                )
            )
        extras.append(self.put_activity_log(stamp=stamp))
        trust = self._maybe_trust_center(
            relative=f"packs/{pack_type}/{stamp}/beacon-pack.json",
            body=body,
            kind="pack",
            metadata=meta,
            content_type=CONTENT_TYPE_JSON,
        )
        if trust:
            extras.append(trust)
        return {
            "kind": "pack",
            "s3_uri": uri,
            "sha256": digest,
            "pack_id": stamp,
            "pack_type": pack_type,
            "pack_version": stamp,
            "draft": draft,
            "report_format": report_format,
            "exports": extras,
        }

    def put_markdown_report(
        self,
        path: Path,
        *,
        pack_type: str,
        version: str,
        draft: bool = True,
    ) -> dict[str, Any]:
        assert_upload_allowed(self.settings, path)
        pack_type = validate_pack_type(pack_type)
        version = validate_artifact_id("pack_version", version)
        body = path.read_bytes()
        digest = sha256_bytes(body)
        key = pack_object_key(
            self.tenant_id,
            self.workspace_id,
            version,
            prefix=self.prefix,
            pack_type=pack_type,
            version=version,
            filename="report.md",
        )
        meta = {
            "sha256": digest,
            "sealed_at": _now(),
            "pack_type": pack_type,
            "pack_version": version,
            "draft": "true" if draft else "false",
            "report_format": "markdown",
            "verified": "true",
        }
        uri = self._put_bytes(
            key,
            body,
            kind="report",
            metadata=meta,
            content_type=CONTENT_TYPE_MARKDOWN,
            extra_tags={"beacon-verified": "true"},
        )
        trust = self._maybe_trust_center(
            relative=f"packs/{pack_type}/{version}/report.md",
            body=body,
            kind="report",
            metadata=meta,
            content_type=CONTENT_TYPE_MARKDOWN,
        )
        result = {
            "kind": "report",
            "s3_uri": uri,
            "sha256": digest,
            "report_format": "markdown",
            "content_type": CONTENT_TYPE_MARKDOWN,
        }
        if trust:
            result["trust_center"] = trust
        return result

    def put_activity_log(self, *, stamp: str) -> dict[str, Any]:
        path = self.settings.chain_path
        assert_upload_allowed(self.settings, path)
        body = path.read_bytes() if path.exists() else b""
        digest = sha256_bytes(body)
        stamp = validate_artifact_id("activity_log_stamp", stamp)
        key = activity_log_object_key(
            self.tenant_id, self.workspace_id, stamp, prefix=self.prefix
        )
        meta = {
            "sha256": digest,
            "sealed_at": _now(),
            "report_format": "activity-log",
            "pack_version": stamp,
            "verified": "true",
        }
        uri = self._put_bytes(
            key,
            body,
            kind="report",
            metadata=meta,
            content_type=CONTENT_TYPE_ACTIVITY_LOG,
            extra_tags={"beacon-verified": "true"},
        )
        trust = self._maybe_trust_center(
            relative=f"activity-log/{stamp}.jsonl",
            body=body,
            kind="report",
            metadata=meta,
            content_type=CONTENT_TYPE_ACTIVITY_LOG,
        )
        result = {
            "kind": "report",
            "s3_uri": uri,
            "sha256": digest,
            "report_format": "activity-log",
            "content_type": CONTENT_TYPE_ACTIVITY_LOG,
        }
        if trust:
            result["trust_center"] = trust
        return result

    def _workspace_prefix(self) -> str:
        return _join_prefix(self.prefix, f"{self.tenant_id}/{self.workspace_id}/")

    def _assert_lake_uri(self, uri: str) -> tuple[str, str]:
        bucket, key = _parse_s3_uri(uri)
        if bucket != self.bucket:
            fail(E_REMOTE, f"s3 uri bucket mismatch: {uri}")
        prefix = self._workspace_prefix()
        if not key.startswith(prefix):
            fail(E_REMOTE, f"s3 uri outside workspace prefix: {uri}")
        if ".." in key.split("/"):
            fail(E_REMOTE, f"s3 uri invalid: {uri}")
        return bucket, key

    def _get_object(self, uri: str, version_id: str | None = None) -> bytes:
        bucket, key = self._assert_lake_uri(uri)
        try:
            extra = {"VersionId": version_id} if version_id else {}
            resp = self.s3.get_object(Bucket=bucket, Key=key, **extra)
            return resp["Body"].read()
        except ClientError as exc:
            fail(E_REMOTE, f"S3 GetObject failed for {uri}: {exc}")

    def publish_records(
        self,
        records: list[Record],
        checkpoints: list[Checkpoint],
        *,
        merkle_root: str = "",
        pack_id: str = "",
    ) -> dict[str, Any]:
        objects: list[dict[str, Any]] = []
        for record in records:
            path = self.settings.evidence_dir / f"{record.evidence_id}.json"
            if not path.exists():
                fail(E_REMOTE, f"missing local evidence file for {record.evidence_id}")
            objects.extend(
                self.put_record_and_evidence(
                    record,
                    path,
                    merkle_root=merkle_root,
                    pack_id=pack_id,
                    sync_jsonl=False,
                    verified=True,
                )
            )
        if records or self.settings.chain_path.exists():
            objects.append(self.put_records_jsonl())
        for checkpoint in checkpoints:
            objects.append(self.put_checkpoint(checkpoint, pack_id=pack_id))
        return {
            "ok": True,
            "bucket": self.bucket,
            "objects": objects,
        }


def _parse_s3_uri(uri: str) -> tuple[str, str]:
    if not uri.startswith("s3://"):
        fail(E_REMOTE, f"invalid s3 uri: {uri}")
    rest = uri[len("s3://") :]
    bucket, _, key = rest.partition("/")
    if not bucket or not key:
        fail(E_REMOTE, f"invalid s3 uri: {uri}")
    return bucket, key


def _parse_jsonl(body: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in body.decode("utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def publish_sealed_record(settings: Settings, record: Record) -> dict[str, Any] | None:
    """Dual-write observation + finding and ``chain/records.jsonl`` after local seal."""
    lake = remote_ready(settings)
    if lake is None:
        return None
    path = settings.evidence_dir / f"{record.evidence_id}.json"
    objects = lake.put_record_and_evidence(record, path, sync_jsonl=True, verified=False)
    return {"ok": True, "objects": objects}


def publish_sealed_checkpoint(settings: Settings, checkpoint: Checkpoint) -> dict[str, Any] | None:
    """Dual-write ``chain/checkpoints.jsonl`` after local checkpoint."""
    lake = remote_ready(settings)
    if lake is None:
        return None
    return {"ok": True, **lake.put_checkpoint(checkpoint)}


def publish_unverified_import(
    settings: Settings, import_id: str, body: bytes
) -> dict[str, Any] | None:
    lake = remote_ready(settings)
    if lake is None:
        return None
    return {"ok": True, **lake.put_unverified_import(import_id, body)}


def publish_collect_run(
    settings: Settings,
    *,
    evidence_ids: list[str],
    checkpoint: Checkpoint | None,
    run_id: str | None = None,
) -> dict[str, Any] | None:
    lake = remote_ready(settings)
    if lake is None:
        return None
    if checkpoint is not None:
        from beacon.assurance.admission import verified_snapshot
        snapshot = verified_snapshot(settings)
        for record in snapshot.records:
            if record.evidence_id in evidence_ids:
                lake.put_record_and_evidence(record, settings.evidence_dir / f"{record.evidence_id}.json",
                    verified=True, merkle_root=checkpoint.merkle_root, sync_jsonl=False)
    objects: list[dict[str, Any]] = []
    for eid in evidence_ids:
        item = lake._index_get(f"EVIDENCE#{eid}")
        if item is None:
            fail(E_REMOTE, f"remote seal missing for evidence {eid}")
        objects.append(
            {
                "kind": "observation",
                "s3_uri": item.get("s3_uri"),
                "sha256": item.get("sha256"),
            }
        )
        if item.get("finding_s3_uri"):
            objects.append(
                {
                    "kind": "finding",
                    "s3_uri": item.get("finding_s3_uri"),
                    "sha256": item.get("audit_sha256") or item.get("finding_sha256"),
                }
            )
    objects.append(
        {
            "kind": "records",
            "s3_uri": s3_uri(
                lake.bucket,
                records_jsonl_key(lake.tenant_id, lake.workspace_id, prefix=lake.prefix),
            ),
        }
    )
    if checkpoint is not None:
        objects.append(
            {
                "kind": "checkpoints",
                "s3_uri": s3_uri(
                    lake.bucket,
                    checkpoints_jsonl_key(lake.tenant_id, lake.workspace_id, prefix=lake.prefix),
                ),
                "merkle_root": checkpoint.merkle_root,
            }
        )
    return {"ok": True, "bucket": lake.bucket, "objects": objects}


@locked
def publish_pack(
    settings: Settings,
    path: Path,
    *,
    stamp: str | None = None,
    markdown_path: Path | None = None,
    pack_type: str | None = None,
    draft: bool | None = None,
) -> dict[str, Any] | None:
    lake = remote_ready(settings)
    if lake is None:
        return None
    from beacon.assurance.admission import verified_snapshot
    verified_snapshot(settings, pack_path=path)
    uploaded = lake.put_pack(
        path,
        stamp=stamp,
        pack_type=pack_type,
        draft=draft,
        markdown_path=markdown_path,
    )
    records = load_records(settings)
    checkpoints = load_checkpoints(settings)
    merkle = checkpoints[-1].merkle_root if checkpoints else ""
    objects: list[dict[str, Any]] = [uploaded]
    for record in records:
        ev = settings.evidence_dir / f"{record.evidence_id}.json"
        if ev.exists():
            objects.extend(
                lake.put_record_and_evidence(
                    record,
                    ev,
                    merkle_root=merkle,
                    pack_id=uploaded["pack_id"],
                    sync_jsonl=False,
                    verified=True,
                )
            )
    if records:
        objects.append(lake.put_records_jsonl())
    for checkpoint in checkpoints:
        objects.append(lake.put_checkpoint(checkpoint, pack_id=uploaded["pack_id"]))
    return {
        "ok": True,
        "pack": uploaded,
        "objects": objects,
    }


@locked
def sync_workspace(settings: Settings) -> dict[str, Any]:
    from beacon.assurance.admission import verified_snapshot
    verified_snapshot(settings)
    lake = remote_ready(settings, command=True)
    assert lake is not None
    records = load_records(settings)
    checkpoints = load_checkpoints(settings)
    merkle = checkpoints[-1].merkle_root if checkpoints else ""
    result = lake.publish_records(records, checkpoints, merkle_root=merkle)
    packs = []
    for path in sorted(settings.export_dir.glob("beacon-pack-*.json")):
        assert_upload_allowed(settings, path)
        verified_snapshot(settings, pack_path=path)
        packs.append(lake.put_pack(path))
    result["packs"] = packs
    return result


@locked
def pull_workspace(settings: Settings) -> dict[str, Any]:
    lake = remote_ready(settings, command=True)
    assert lake is not None
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    settings.chain_path.parent.mkdir(parents=True, exist_ok=True)
    items = lake.query_index()
    pulled = 0
    verified = 0
    incoming_records: dict[int, dict[str, Any]] = {}
    incoming_checkpoints: dict[str, dict[str, Any]] = {}
    staged_evidence: dict[str, bytes] = {}
    jsonl_cache: dict[str, bytes] = {}

    def cached_get(uri: str) -> bytes:
        if uri not in jsonl_cache:
            jsonl_cache[uri] = lake._get_object(uri)
        return jsonl_cache[uri]

    evidence_items: list[dict[str, Any]] = []
    checkpoint_items: list[dict[str, Any]] = []
    for item in items:
        sk = str(item.get("sk") or "")
        if sk.startswith("FRESH#") or sk.startswith("IMPORT#"):
            continue
        if sk.startswith("EVIDENCE#"):
            validate_artifact_id("evidence_id", sk.split("#", 1)[1])
            evidence_items.append(item)
        elif sk.startswith("CP#"):
            raw_id = str(item.get("checkpoint_id") or sk.split("#", 1)[1])
            validate_artifact_id("checkpoint_id", raw_id)
            checkpoint_items.append(item)
        else:
            fail(E_REMOTE, f"unexpected index sort key {sk}")

    records_by_eid: dict[str, dict[str, Any]] = {}
    records_uri = ""
    for item in evidence_items:
        maybe = str(item.get("record_s3_uri") or "")
        if maybe:
            records_uri = maybe
            break
    if not records_uri and evidence_items:
        records_uri = s3_uri(
            lake.bucket,
            records_jsonl_key(lake.tenant_id, lake.workspace_id, prefix=lake.prefix),
        )
    if records_uri:
        for row in _parse_jsonl(cached_get(records_uri)):
            records_by_eid[str(row["evidence_id"])] = row
        pulled += 1
        verified += 1

    for item in evidence_items:
        sk = str(item.get("sk") or "")
        uri = str(item.get("s3_uri") or item.get("observation_s3_uri") or "")
        if not uri:
            fail(E_REMOTE, f"index item {sk} missing s3_uri")
        lake._assert_lake_uri(uri)
        finding_uri = str(item.get("finding_s3_uri") or "")
        if not finding_uri:
            fail(E_REMOTE, f"index item {sk} missing finding_s3_uri")
        lake._assert_lake_uri(finding_uri)
        expected = str(item.get("sha256") or "")
        input_expected = str(item.get("input_sha256") or "")
        rec_expected = str(item.get("record_sha256") or item.get("audit_sha256") or "")
        finding_expected = str(item.get("finding_sha256") or item.get("audit_sha256") or "")
        prev_expected = str(item.get("prev_sha256") or "")
        if not expected or not input_expected:
            fail(E_REMOTE, f"index item {sk} missing sha256 or input_sha256")
        if expected != input_expected:
            fail(E_REMOTE, f"index item {sk} sha256 does not match input_sha256")
        if not rec_expected or not finding_expected:
            fail(E_REMOTE, f"index item {sk} missing linked audit hash")
        if item.get("audit_seq") is None:
            fail(E_REMOTE, f"index item {sk} missing audit_seq")
        if not prev_expected:
            fail(E_REMOTE, f"index item {sk} missing prev_sha256")
        evidence_id = validate_artifact_id("evidence_id", sk.split("#", 1)[1])
        dest = (settings.evidence_dir / f"{evidence_id}.json").resolve()
        if not dest.is_relative_to(settings.evidence_dir.resolve()):
            fail(E_REMOTE, f"refusing evidence path outside evidence dir: {evidence_id}")
        body = lake._get_object(uri, item.get("s3_version_id") or item.get("observation_s3_version_id"))
        digest = sha256_bytes(body)
        if digest != expected:
            fail(E_REMOTE, f"altered artifact: sha256 mismatch for {uri}")
        if digest != input_expected:
            fail(E_REMOTE, f"altered artifact: input hash mismatch for {uri}")
        verified += 1
        if dest.exists() and sha256_bytes(dest.read_bytes()) != digest:
            fail(E_REMOTE, f"local evidence conflict for {evidence_id}")
        record = records_by_eid.get(evidence_id)
        if record is None:
            fail(E_REMOTE, f"records.jsonl missing evidence_id {evidence_id}")
        rec_digest = sha256_bytes(dumps(record))
        if rec_digest != rec_expected:
            fail(E_REMOTE, f"altered artifact: linked audit hash mismatch for {evidence_id}")
        if str(record.get("payload_sha256")) != digest:
            fail(E_REMOTE, f"evidence does not match record payload_sha256 for {evidence_id}")
        finding_body = lake._get_object(finding_uri, item.get("finding_s3_version_id"))
        finding_digest = sha256_bytes(finding_body)
        if finding_digest != finding_expected:
            fail(E_REMOTE, f"altered artifact: finding sha256 mismatch for {finding_uri}")
        if finding_digest != rec_digest:
            fail(E_REMOTE, f"altered artifact: finding does not match record for {evidence_id}")
        verified += 1
        seq = int(record["seq"])
        if int(item["audit_seq"]) != seq:
            fail(E_REMOTE, f"altered artifact: audit sequence mismatch for {evidence_id}")
        if str(record.get("prev_sha256")) != prev_expected:
            fail(E_REMOTE, f"altered artifact: prev hash mismatch for {evidence_id}")
        prior = incoming_records.get(seq)
        if prior and sha256_obj(prior) != sha256_obj(record):
            fail(E_REMOTE, f"record conflict at seq {seq}")
        incoming_records[seq] = record
        staged_evidence[evidence_id] = body
        pulled += 1

    checkpoints_by_id: dict[str, dict[str, Any]] = {}
    checkpoints_uri = ""
    for item in checkpoint_items:
        maybe = str(item.get("s3_uri") or "")
        if maybe:
            checkpoints_uri = maybe
            break
    if checkpoints_uri:
        for row in _parse_jsonl(cached_get(checkpoints_uri)):
            checkpoints_by_id[checkpoint_id(Checkpoint.from_dict(row))] = row
        pulled += 1
        verified += 1

    for item in checkpoint_items:
        sk = str(item.get("sk") or "")
        expected = str(item.get("sha256") or "")
        raw_id = str(item.get("checkpoint_id") or sk.split("#", 1)[1])
        cp_id = validate_artifact_id("checkpoint_id", raw_id)
        checkpoint = checkpoints_by_id.get(cp_id)
        if checkpoint is None:
            fail(E_REMOTE, f"checkpoints.jsonl missing {cp_id}")
        digest = sha256_bytes(dumps(checkpoint))
        if expected and digest != expected:
            fail(E_REMOTE, f"altered artifact: checkpoint sha256 mismatch for {cp_id}")
        verified += 1
        prior = incoming_checkpoints.get(cp_id)
        if prior and sha256_obj(prior) != sha256_obj(checkpoint):
            fail(E_REMOTE, f"checkpoint conflict for {cp_id}")
        incoming_checkpoints[cp_id] = checkpoint

    merged_records = _merged_record_rows(settings, incoming_records)
    merged_checkpoints = _merged_checkpoint_rows(settings, incoming_checkpoints)
    chain = _validate_staged_chain(
        settings,
        staged_evidence=staged_evidence,
        merged_records=merged_records,
        merged_checkpoints=merged_checkpoints,
    )
    _promote_pull(
        settings,
        staged_evidence=staged_evidence,
        merged_records=merged_records,
        merged_checkpoints=merged_checkpoints,
        incoming_records=incoming_records,
        incoming_checkpoints=incoming_checkpoints,
    )
    advance_head(settings, load_records(settings))
    return {
        "ok": True,
        "pulled": pulled,
        "verified": verified,
        "records": len(incoming_records),
        "checkpoints": len(incoming_checkpoints),
        "index_items": len(items),
        "chain": chain,
    }


def _merged_record_rows(
    settings: Settings, incoming: dict[int, dict[str, Any]]
) -> list[dict[str, Any]]:
    existing = {int(row["seq"]): row for row in iter_jsonl(settings.chain_path)}
    for seq, row in incoming.items():
        prior = existing.get(seq)
        if prior and sha256_obj(prior) != sha256_obj(row):
            fail(E_REMOTE, f"local record conflict at seq {seq}")
        existing[seq] = row
    return [existing[seq] for seq in sorted(existing)]


def _merged_checkpoint_rows(
    settings: Settings, incoming: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    existing_rows = list(iter_jsonl(settings.checkpoints_path))
    by_id: dict[str, dict[str, Any]] = {}
    for row in existing_rows:
        cp = Checkpoint.from_dict(row)
        by_id[checkpoint_id(cp)] = row
    for cp_id, row in incoming.items():
        prior = by_id.get(cp_id)
        if prior and sha256_obj(prior) != sha256_obj(row):
            fail(E_REMOTE, f"local checkpoint conflict for {cp_id}")
        by_id[cp_id] = row
    return sorted(by_id.values(), key=lambda row: int(row.get("tsa_serial") or 0))


def _jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    lines = [dumps(row).decode("utf-8") for row in rows]
    text = "\n".join(lines) + ("\n" if lines else "")
    return text.encode("utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_jsonl_bytes(rows))


def _install_files_atomically(replacements: list[tuple[Path, bytes]]) -> None:
    """Write every payload to a sibling temp file, then replace destinations.

    If any replace fails, restore every destination that this call already
    changed. Temp files live next to the destination so ``os.replace`` stays
    on the same filesystem.
    """
    if not replacements:
        return
    temps: list[Path] = []
    backups: list[tuple[Path, bytes | None]] = []
    try:
        for dest, body in replacements:
            dest.parent.mkdir(parents=True, exist_ok=True)
            backups.append((dest, dest.read_bytes() if dest.exists() else None))
            tmp = dest.with_name(f"{dest.name}.pulltmp")
            tmp.write_bytes(body)
            temps.append(tmp)
        for (dest, _body), tmp in zip(replacements, temps, strict=True):
            os.replace(tmp, dest)
    except BaseException:
        for dest, prev in reversed(backups):
            if prev is None:
                dest.unlink(missing_ok=True)
            else:
                dest.write_bytes(prev)
        raise
    finally:
        for tmp in temps:
            tmp.unlink(missing_ok=True)


def _validate_staged_chain(
    settings: Settings,
    *,
    staged_evidence: dict[str, bytes],
    merged_records: list[dict[str, Any]],
    merged_checkpoints: list[dict[str, Any]],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        staged_settings = replace(settings, home=Path(tmp) / ".beacon")
        ensure_layout(staged_settings)
        # Keep verifier-owned pins and retained history, never downloaded trust.
        (staged_settings.home / "trust.json").write_bytes(dumps(read_trust(settings)))
        (staged_settings.home / "retained-head.json").write_bytes(local_head(settings).read_bytes())
        if (settings.home / "scopes").exists():
            shutil.copytree(settings.home / "scopes", staged_settings.home / "scopes")
        if settings.keys_dir.exists():
            shutil.copytree(settings.keys_dir, staged_settings.keys_dir, dirs_exist_ok=True)
        for evidence_id, body in staged_evidence.items():
            dest = (staged_settings.evidence_dir / f"{evidence_id}.json").resolve()
            if not dest.is_relative_to(staged_settings.evidence_dir.resolve()):
                fail(E_REMOTE, f"refusing evidence path outside evidence dir: {evidence_id}")
            dest.write_bytes(body)
        for row in merged_records:
            evidence_id = str(row.get("evidence_id") or "")
            if not evidence_id:
                continue
            dest = staged_settings.evidence_dir / f"{evidence_id}.json"
            if dest.exists():
                continue
            src = settings.evidence_dir / f"{evidence_id}.json"
            if src.exists():
                dest.write_bytes(src.read_bytes())
        _write_jsonl(staged_settings.chain_path, merged_records)
        _write_jsonl(staged_settings.checkpoints_path, merged_checkpoints)
        return check_chain(staged_settings)


def _promote_pull(
    settings: Settings,
    *,
    staged_evidence: dict[str, bytes],
    merged_records: list[dict[str, Any]],
    merged_checkpoints: list[dict[str, Any]],
    incoming_records: dict[int, dict[str, Any]],
    incoming_checkpoints: dict[str, dict[str, Any]],
) -> None:
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    replacements: list[tuple[Path, bytes]] = []
    for evidence_id, body in staged_evidence.items():
        dest = (settings.evidence_dir / f"{evidence_id}.json").resolve()
        if not dest.is_relative_to(settings.evidence_dir.resolve()):
            fail(E_REMOTE, f"refusing evidence path outside evidence dir: {evidence_id}")
        replacements.append((dest, body))
    if incoming_records:
        replacements.append((settings.chain_path, _jsonl_bytes(merged_records)))
    if incoming_checkpoints:
        replacements.append((settings.checkpoints_path, _jsonl_bytes(merged_checkpoints)))
    try:
        _install_files_atomically(replacements)
    except OSError as exc:
        fail(E_REMOTE, f"failed to install pulled workspace: {exc}")
