"""S3 evidence lake and DynamoDB artifact index.

Local seal always runs first. Remote write is a dual-write after the local
witness chain. This module does not upload ``.beacon/keys``, ``*.pem`` private keys, ``config.json``, or ``cache/``.
"""

from __future__ import annotations

import datetime as dt
import json
import re
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
from beacon.config import KMS_ALIAS_BEACON_EVIDENCE, Settings
from beacon.crypto.witness import (
    Checkpoint,
    Record,
    check_chain,
    iter_jsonl,
    load_checkpoints,
    load_records,
)
from beacon.errors import E_REMOTE, fail

ArtifactKind = Literal["evidence", "records", "checkpoints", "pack"]

PRIVATE_NAMES = frozenset({"recorder.pem", "witness.pem", "tsa.pem"})
PRIVATE_SUFFIXES = frozenset({".sec", ".pem"})
LOCK_MODES = frozenset({"GOVERNANCE", "COMPLIANCE"})
TAG_SAFE = re.compile(r"[^0-9A-Za-z+\-.:/@_]")
PACK_NAME_RE = re.compile(r"^beacon-pack-(.+)\.json$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


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


def checkpoint_id(checkpoint: Checkpoint) -> str:
    return f"{checkpoint.from_seq:08d}-{checkpoint.to_seq:08d}-{checkpoint.tsa_serial}"


def record_id(record: Record) -> str:
    return record.evidence_id


def _join_prefix(prefix: str, key: str) -> str:
    prefix = (prefix or "").strip().strip("/")
    if prefix:
        return f"{prefix}/{key}"
    return key


def evidence_object_key(
    tenant_id: str,
    workspace_id: str,
    evidence_id: str,
    *,
    prefix: str = "",
) -> str:
    """Match local ``evidence/{uuid}.json``."""
    return _join_prefix(prefix, f"{tenant_id}/{workspace_id}/evidence/{evidence_id}.json")


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
) -> str:
    """Match local ``export/beacon-pack-{stamp}.json``."""
    return _join_prefix(
        prefix,
        f"{tenant_id}/{workspace_id}/export/beacon-pack-{stamp}.json",
    )


def s3_uri(bucket: str, key: str) -> str:
    return f"s3://{bucket}/{key}"


def partition_key(tenant_id: str, workspace_id: str) -> str:
    return f"{tenant_id}#{workspace_id}"


def class_tag(kind: ArtifactKind) -> str:
    match kind:
        case "evidence":
            return "evidence"
        case "records":
            return "chain-record"
        case "checkpoints":
            return "checkpoint"
        case "pack":
            return "pack"
        case _:
            _never(kind)


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
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    if settings.object_lock_mode not in LOCK_MODES:
        fail(E_REMOTE, "BEACON_OBJECT_LOCK_MODE must be GOVERNANCE or COMPLIANCE")
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
        self.settings = settings
        self.bucket = settings.s3_bucket
        self.table_name = settings.ddb_table
        self.tenant_id = settings.tenant_id
        self.workspace_id = settings.workspace_id
        self.prefix = settings.s3_prefix
        session = boto3.session.Session()
        self.s3 = session.client("s3")
        self.ddb = session.resource("dynamodb").Table(self.table_name)

    @property
    def pk(self) -> str:
        return partition_key(self.tenant_id, self.workspace_id)

    def _key(self, kind: ArtifactKind, **parts: str) -> str:
        match kind:
            case "evidence":
                return evidence_object_key(
                    self.tenant_id,
                    self.workspace_id,
                    parts["evidence_id"],
                    prefix=self.prefix,
                )
            case "records":
                return records_jsonl_key(
                    self.tenant_id, self.workspace_id, prefix=self.prefix
                )
            case "checkpoints":
                return checkpoints_jsonl_key(
                    self.tenant_id, self.workspace_id, prefix=self.prefix
                )
            case "pack":
                return pack_object_key(
                    self.tenant_id, self.workspace_id, parts["stamp"], prefix=self.prefix
                )
            case _:
                _never(kind)

    def _put_bytes(
        self,
        key: str,
        body: bytes,
        *,
        kind: ArtifactKind,
        metadata: dict[str, str],
    ) -> str:
        extra: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": body,
            "ContentType": "application/json",
            "Metadata": {k: _meta_value(v) for k, v in metadata.items() if v},
            "Tagging": urlencode(
                {
                    "beacon-class": class_tag(kind),
                    "beacon-tenant": _tag_value(self.tenant_id),
                    "beacon-workspace": _tag_value(self.workspace_id),
                }
            ),
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self.settings.kms_key_arn or KMS_ALIAS_BEACON_EVIDENCE,
        }
        if self.settings.object_lock_days > 0:
            retain = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) + dt.timedelta(
                days=self.settings.object_lock_days
            )
            extra["ObjectLockMode"] = self.settings.object_lock_mode
            extra["ObjectLockRetainUntilDate"] = retain
        try:
            self.s3.put_object(**extra)
        except ClientError as exc:
            fail(E_REMOTE, f"S3 PutObject failed for {key}: {exc}")
        return s3_uri(self.bucket, key)

    def _index_put(self, sk: str, fields: dict[str, Any]) -> None:
        item = {**fields, "pk": self.pk, "sk": sk}
        try:
            self.ddb.put_item(Item=item)
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

    def put_records_jsonl(self) -> dict[str, Any]:
        path = self.settings.chain_path
        assert_upload_allowed(self.settings, path)
        body = path.read_bytes() if path.exists() else b""
        digest = sha256_bytes(body)
        key = self._key("records")
        uri = self._put_bytes(
            key,
            body,
            kind="records",
            metadata={"sha256": digest, "sealed_at": _now()},
        )
        return {"kind": "records", "s3_uri": uri, "sha256": digest}

    def put_checkpoints_jsonl(self) -> dict[str, Any]:
        path = self.settings.checkpoints_path
        assert_upload_allowed(self.settings, path)
        body = path.read_bytes() if path.exists() else b""
        digest = sha256_bytes(body)
        key = self._key("checkpoints")
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
    ) -> list[dict[str, Any]]:
        assert_upload_allowed(self.settings, evidence_path)
        payload = evidence_path.read_bytes()
        digest = sha256_bytes(payload)
        if digest != record.payload_sha256:
            fail(E_REMOTE, f"local evidence hash mismatch for {record.evidence_id}")
        rec_id = record_id(record)
        rec_digest = sha256_bytes(dumps(record.to_dict()))
        ev_key = self._key("evidence", evidence_id=record.evidence_id)
        rec_uri = s3_uri(self.bucket, self._key("records"))
        extras: list[dict[str, Any]] = []
        if sync_jsonl:
            jsonl = self.put_records_jsonl()
            rec_uri = jsonl["s3_uri"]
            extras.append(jsonl)
        meta_common = {
            "sha256": digest,
            "scf_targets": ",".join(record.scf_targets),
            "plugin": record.plugin,
            "sealed_at": record.ts,
            "record_id": rec_id,
        }
        existing = self._index_get(f"EVIDENCE#{record.evidence_id}")
        if (
            existing
            and existing.get("sha256") == digest
            and existing.get("record_sha256") == rec_digest
        ):
            updates = {}
            if pack_id and existing.get("pack_id") != pack_id:
                updates["pack_id"] = pack_id
            if merkle_root and existing.get("merkle_root") != merkle_root:
                updates["merkle_root"] = merkle_root
            updates["record_s3_uri"] = rec_uri
            if updates:
                merged = {k: v for k, v in existing.items() if k not in {"pk", "sk"}}
                merged.update(updates)
                self._index_put(f"EVIDENCE#{record.evidence_id}", merged)
                self._index_put(f"FRESH#{record.plugin}", dict(merged))
            return [
                {
                    "kind": "evidence",
                    "s3_uri": existing.get("s3_uri"),
                    "sha256": digest,
                    "skipped": True,
                    "pack_id": pack_id or existing.get("pack_id"),
                },
                *extras,
            ]
        ev_uri = self._put_bytes(
            ev_key,
            payload,
            kind="evidence",
            metadata=meta_common,
        )
        fields = {
            "s3_uri": ev_uri,
            "sha256": digest,
            "sealed_at": record.ts,
            "control_ids": list(record.scf_targets),
            "merkle_root": merkle_root,
            "pack_id": pack_id,
            "plugin": record.plugin,
            "record_id": rec_id,
            "record_s3_uri": rec_uri,
            "record_sha256": rec_digest,
            "seq": record.seq,
        }
        self._index_put(f"EVIDENCE#{record.evidence_id}", fields)
        self._index_put(f"FRESH#{record.plugin}", dict(fields))
        return [
            {"kind": "evidence", "s3_uri": ev_uri, "sha256": digest},
            *extras,
        ]

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

    def put_pack(self, path: Path, *, stamp: str | None = None) -> dict[str, Any]:
        assert_upload_allowed(self.settings, path)
        stamp = stamp or _stamp_from_pack_path(path)
        body = path.read_bytes()
        digest = sha256_bytes(body)
        key = self._key("pack", stamp=stamp)
        uri = self._put_bytes(
            key,
            body,
            kind="pack",
            metadata={"sha256": digest, "sealed_at": _now(), "record_id": stamp},
        )
        return {"kind": "pack", "s3_uri": uri, "sha256": digest, "pack_id": stamp}

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

    def _get_object(self, uri: str) -> bytes:
        bucket, key = self._assert_lake_uri(uri)
        try:
            resp = self.s3.get_object(Bucket=bucket, Key=key)
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
    """Dual-write ``evidence/{uuid}.json`` and ``chain/records.jsonl`` after local seal."""
    lake = remote_ready(settings)
    if lake is None:
        return None
    path = settings.evidence_dir / f"{record.evidence_id}.json"
    objects = lake.put_record_and_evidence(record, path, sync_jsonl=True)
    return {"ok": True, "objects": objects}


def publish_sealed_checkpoint(settings: Settings, checkpoint: Checkpoint) -> dict[str, Any] | None:
    """Dual-write ``chain/checkpoints.jsonl`` after local checkpoint."""
    lake = remote_ready(settings)
    if lake is None:
        return None
    return {"ok": True, **lake.put_checkpoint(checkpoint)}


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
    objects: list[dict[str, Any]] = []
    for eid in evidence_ids:
        item = lake._index_get(f"EVIDENCE#{eid}")
        if item is None:
            fail(E_REMOTE, f"remote seal missing for evidence {eid}")
        objects.append(
            {
                "kind": "evidence",
                "s3_uri": item.get("s3_uri"),
                "sha256": item.get("sha256"),
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


def publish_pack(settings: Settings, path: Path, *, stamp: str | None = None) -> dict[str, Any] | None:
    lake = remote_ready(settings)
    if lake is None:
        return None
    uploaded = lake.put_pack(path, stamp=stamp)
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


def sync_workspace(settings: Settings) -> dict[str, Any]:
    lake = remote_ready(settings, command=True)
    assert lake is not None
    records = load_records(settings)
    checkpoints = load_checkpoints(settings)
    merkle = checkpoints[-1].merkle_root if checkpoints else ""
    result = lake.publish_records(records, checkpoints, merkle_root=merkle)
    packs = []
    for path in sorted(settings.export_dir.glob("beacon-pack-*.json")):
        assert_upload_allowed(settings, path)
        packs.append(lake.put_pack(path))
    result["packs"] = packs
    return result


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
    jsonl_cache: dict[str, bytes] = {}

    def cached_get(uri: str) -> bytes:
        if uri not in jsonl_cache:
            jsonl_cache[uri] = lake._get_object(uri)
        return jsonl_cache[uri]

    evidence_items: list[dict[str, Any]] = []
    checkpoint_items: list[dict[str, Any]] = []
    for item in items:
        sk = str(item.get("sk") or "")
        if sk.startswith("FRESH#"):
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
        uri = str(item.get("s3_uri") or "")
        expected = str(item.get("sha256") or "")
        if not uri or not expected:
            fail(E_REMOTE, f"index item {sk} missing s3_uri or sha256")
        evidence_id = validate_artifact_id("evidence_id", sk.split("#", 1)[1])
        dest = (settings.evidence_dir / f"{evidence_id}.json").resolve()
        if not dest.is_relative_to(settings.evidence_dir.resolve()):
            fail(E_REMOTE, f"refusing evidence path outside evidence dir: {evidence_id}")
        body = lake._get_object(uri)
        digest = sha256_bytes(body)
        if digest != expected:
            fail(E_REMOTE, f"sha256 mismatch for {uri}")
        verified += 1
        if dest.exists() and sha256_bytes(dest.read_bytes()) != digest:
            fail(E_REMOTE, f"local evidence conflict for {evidence_id}")
        record = records_by_eid.get(evidence_id)
        if record is None:
            fail(E_REMOTE, f"records.jsonl missing evidence_id {evidence_id}")
        rec_expected = str(item.get("record_sha256") or "")
        rec_digest = sha256_bytes(dumps(record))
        if rec_expected and rec_digest != rec_expected:
            fail(E_REMOTE, f"record sha256 mismatch for {evidence_id}")
        if str(record.get("payload_sha256")) != digest:
            fail(E_REMOTE, f"evidence does not match record payload_sha256 for {evidence_id}")
        seq = int(record["seq"])
        prior = incoming_records.get(seq)
        if prior and sha256_obj(prior) != sha256_obj(record):
            fail(E_REMOTE, f"record conflict at seq {seq}")
        incoming_records[seq] = record
        dest.write_bytes(body)
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
            fail(E_REMOTE, f"checkpoint sha256 mismatch for {cp_id}")
        verified += 1
        prior = incoming_checkpoints.get(cp_id)
        if prior and sha256_obj(prior) != sha256_obj(checkpoint):
            fail(E_REMOTE, f"checkpoint conflict for {cp_id}")
        incoming_checkpoints[cp_id] = checkpoint

    _merge_records(settings, incoming_records)
    _merge_checkpoints(settings, incoming_checkpoints)
    chain = None
    if (settings.keys_dir / "recorder.pem").exists():
        chain = check_chain(settings)
    return {
        "ok": True,
        "pulled": pulled,
        "verified": verified,
        "records": len(incoming_records),
        "checkpoints": len(incoming_checkpoints),
        "index_items": len(items),
        "chain": chain,
    }


def _merge_records(settings: Settings, incoming: dict[int, dict[str, Any]]) -> None:
    if not incoming:
        return
    existing = {int(row["seq"]): row for row in iter_jsonl(settings.chain_path)}
    for seq, row in incoming.items():
        prior = existing.get(seq)
        if prior and sha256_obj(prior) != sha256_obj(row):
            fail(E_REMOTE, f"local record conflict at seq {seq}")
        existing[seq] = row
    lines = [dumps(existing[seq]).decode("utf-8") for seq in sorted(existing)]
    settings.chain_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _merge_checkpoints(settings: Settings, incoming: dict[str, dict[str, Any]]) -> None:
    if not incoming:
        return
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
    ordered = sorted(by_id.values(), key=lambda row: int(row.get("tsa_serial") or 0))
    lines = [dumps(row).decode("utf-8") for row in ordered]
    settings.checkpoints_path.write_text(
        "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
    )
