"""Signed witness chain: recorder vs witness, Merkle checkpoints, TSA."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
from dataclasses import dataclass
from typing import Any, Iterator
from uuid import uuid4

from beacon.canonical import dumps, sha256_bytes, sha256_obj
from beacon.config import Settings
from beacon.crypto.keys import KeyPair, load_roles, verify
from beacon.crypto.merkle import merkle_root
from beacon.crypto.tsa import TimeStampToken, stamp, verify_token
from beacon.errors import (
    E_BAD_CHAIN,
    E_BAD_SIGNATURE,
    E_KEY_COLLISION,
    E_NO_CHECKPOINT,
    E_NOT_INITIALIZED,
    E_SCOPE,
    E_TSA,
    BeaconError,
    fail,
)
from beacon.scope.bind import verify_payload_scope
from beacon.scope.store import load_scope
from beacon.locking import locked
from beacon.crypto.trust import read_trust, assert_signers, assert_continuity, advance_head, atomic_write

CHAIN_VERSION = 1
GENESIS_PREV = "0" * 64


@dataclass
class Record:
    v: int
    seq: int
    ts: str
    evidence_id: str
    plugin: str
    mode: str
    scf_targets: list[str]
    payload_sha256: str
    prev_sha256: str
    recorder_pub: str
    witness_pub: str
    recorder_sig: str
    witness_sig: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "seq": self.seq,
            "ts": self.ts,
            "evidence_id": self.evidence_id,
            "plugin": self.plugin,
            "mode": self.mode,
            "scf_targets": self.scf_targets,
            "payload_sha256": self.payload_sha256,
            "prev_sha256": self.prev_sha256,
            "recorder_pub": self.recorder_pub,
            "witness_pub": self.witness_pub,
            "recorder_sig": self.recorder_sig,
            "witness_sig": self.witness_sig,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Record:
        return cls(
            v=int(data["v"]),
            seq=int(data["seq"]),
            ts=str(data["ts"]),
            evidence_id=str(data["evidence_id"]),
            plugin=str(data["plugin"]),
            mode=str(data["mode"]),
            scf_targets=list(data["scf_targets"]),
            payload_sha256=str(data["payload_sha256"]),
            prev_sha256=str(data["prev_sha256"]),
            recorder_pub=str(data["recorder_pub"]),
            witness_pub=str(data["witness_pub"]),
            recorder_sig=str(data["recorder_sig"]),
            witness_sig=str(data["witness_sig"]),
        )

    def unsigned_body(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "seq": self.seq,
            "ts": self.ts,
            "evidence_id": self.evidence_id,
            "plugin": self.plugin,
            "mode": self.mode,
            "scf_targets": self.scf_targets,
            "payload_sha256": self.payload_sha256,
            "prev_sha256": self.prev_sha256,
            "recorder_pub": self.recorder_pub,
            "witness_pub": self.witness_pub,
        }


@dataclass
class Checkpoint:
    v: int
    from_seq: int
    to_seq: int
    leaf_count: int
    merkle_root: str
    tsa_token_b64: str
    tsa_gen_time: str
    tsa_serial: int
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "leaf_count": self.leaf_count,
            "merkle_root": self.merkle_root,
            "tsa_token_b64": self.tsa_token_b64,
            "tsa_gen_time": self.tsa_gen_time,
            "tsa_serial": self.tsa_serial,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Checkpoint:
        return cls(
            v=int(data["v"]),
            from_seq=int(data["from_seq"]),
            to_seq=int(data["to_seq"]),
            leaf_count=int(data["leaf_count"]),
            merkle_root=str(data["merkle_root"]),
            tsa_token_b64=str(data["tsa_token_b64"]),
            tsa_gen_time=str(data["tsa_gen_time"]),
            tsa_serial=int(data["tsa_serial"]),
            created_at=str(data["created_at"]),
        )


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def load_records(settings: Settings) -> list[Record]:
    try:
        return [Record.from_dict(row) for row in iter_jsonl(settings.chain_path)]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        fail(E_BAD_CHAIN, f"malformed witness chain: {exc}")


def load_checkpoints(settings: Settings) -> list[Checkpoint]:
    try:
        return [Checkpoint.from_dict(row) for row in iter_jsonl(settings.checkpoints_path)]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        fail(E_BAD_CHAIN, f"malformed checkpoints: {exc}")


def _append_jsonl(path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(dumps(obj).decode("utf-8") + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _recorder_message(body: dict[str, Any]) -> bytes:
    return dumps({k: body[k] for k in body if k not in {"recorder_sig", "witness_sig"}})


def _witness_message(body: dict[str, Any], recorder_sig: str) -> bytes:
    return dumps({"body": body, "recorder_sig": recorder_sig})


@locked
def seal_payload(
    settings: Settings,
    *,
    plugin: str,
    mode: str,
    scf_targets: list[str],
    payload: dict[str, Any],
    recorder: KeyPair | None = None,
    witness: KeyPair | None = None,
) -> Record:
    if recorder is None or witness is None:
        recorder, witness = load_roles(settings.keys_dir)
    if recorder.public_raw() == witness.public_raw():
        fail(E_KEY_COLLISION, "recorder and witness public keys must be distinct")
    records = load_records(settings)
    trust = read_trust(settings)
    assert_continuity(settings, records, trust)
    if recorder.fingerprint() != trust["recorder"] or witness.fingerprint() != trust["witness"]:
        fail("E_UNTRUSTED_SIGNER", "signing keys do not match the registered identities")
    seq = (records[-1].seq + 1) if records else 1
    prev = sha256_obj(records[-1].to_dict()) if records else GENESIS_PREV
    evidence_id = str(uuid4())
    payload_sha = sha256_obj(payload)
    record = Record(
        v=CHAIN_VERSION,
        seq=seq,
        ts=_now(),
        evidence_id=evidence_id,
        plugin=plugin,
        mode=mode,
        scf_targets=list(scf_targets),
        payload_sha256=payload_sha,
        prev_sha256=prev,
        recorder_pub=recorder.fingerprint(),
        witness_pub=witness.fingerprint(),
        recorder_sig="",
        witness_sig="",
    )
    body = record.unsigned_body()
    record.recorder_sig = recorder.sign(_recorder_message(body))
    record.witness_sig = witness.sign(_witness_message(body, record.recorder_sig))
    evidence_path = settings.evidence_dir / f"{evidence_id}.json"
    atomic_write(evidence_path, dumps(payload))
    _append_jsonl(settings.chain_path, record.to_dict())
    advance_head(settings, [*records, record])
    _dual_write_seal(settings, record)
    return record


def _dual_write_seal(settings: Settings, record: Record) -> None:
    # Circular import: beacon.storage.s3 imports Record from this module.
    from beacon.storage.s3 import publish_sealed_record

    publish_sealed_record(settings, record)


@locked
def create_checkpoint(
    settings: Settings,
    *,
    from_seq: int | None = None,
    to_seq: int | None = None,
) -> Checkpoint:
    records = load_records(settings)
    assert_continuity(settings, records)
    if not records:
        fail(E_NO_CHECKPOINT, "no records to checkpoint")
    start = from_seq if from_seq is not None else 1
    end = to_seq if to_seq is not None else records[-1].seq
    window = [row for row in records if start <= row.seq <= end]
    if not window:
        fail(E_NO_CHECKPOINT, f"no records in seq [{start}, {end}]")
    leaves = [sha256_obj(row.to_dict()) for row in window]
    root = merkle_root(leaves)
    existing = load_checkpoints(settings)
    serial = (existing[-1].tsa_serial + 1) if existing else 1
    token: TimeStampToken = stamp(settings.keys_dir, root, serial, settings.tsa_url)
    checkpoint = Checkpoint(
        v=CHAIN_VERSION,
        from_seq=window[0].seq,
        to_seq=window[-1].seq,
        leaf_count=len(window),
        merkle_root=root,
        tsa_token_b64=token.b64(),
        tsa_gen_time=token.gen_time.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        tsa_serial=token.serial,
        created_at=_now(),
    )
    _append_jsonl(settings.checkpoints_path, checkpoint.to_dict())
    _dual_write_checkpoint(settings, checkpoint)
    return checkpoint


def _dual_write_checkpoint(settings: Settings, checkpoint: Checkpoint) -> None:
    # Circular import: beacon.storage.s3 imports Checkpoint from this module.
    from beacon.storage.s3 import publish_sealed_checkpoint

    publish_sealed_checkpoint(settings, checkpoint)


def _covered_seqs(checkpoints: list[Checkpoint]) -> set[int]:
    covered: set[int] = set()
    for item in checkpoints:
        if item.from_seq > item.to_seq:
            fail(E_NO_CHECKPOINT, f"checkpoint {item.tsa_serial} has from_seq > to_seq")
        covered.update(range(item.from_seq, item.to_seq + 1))
    return covered


def _covered_through(checkpoints: list[Checkpoint]) -> int:
    if not checkpoints:
        return 0
    return max(item.to_seq for item in checkpoints)


def verify_record(record: Record, prev_hash: str) -> None:
    if record.prev_sha256 != prev_hash:
        fail(E_BAD_CHAIN, f"seq {record.seq} prev hash mismatch")
    body = record.unsigned_body()
    if not verify(record.recorder_pub, _recorder_message(body), record.recorder_sig):
        fail(E_BAD_SIGNATURE, f"seq {record.seq} recorder signature invalid")
    if not verify(
        record.witness_pub, _witness_message(body, record.recorder_sig), record.witness_sig
    ):
        fail(E_BAD_SIGNATURE, f"seq {record.seq} witness signature invalid")
    if record.recorder_pub == record.witness_pub:
        fail(E_BAD_SIGNATURE, f"seq {record.seq} recorder and witness keys are not distinct")


@locked
def check_chain(settings: Settings, *, scope_id: str | None = None) -> dict[str, Any]:
    if not settings.keys_dir.exists():
        fail(E_NOT_INITIALIZED, "run `beacon init` first")
    if scope_id is None and settings.require_scope:
        fail(E_SCOPE, "BEACON_REQUIRE_SCOPE=1 requires --scope")
    requested = load_scope(settings, scope_id) if scope_id is not None else None
    records = load_records(settings)
    checkpoints = load_checkpoints(settings)
    trust = read_trust(settings)
    assert_continuity(settings, records, trust)
    prev = GENESIS_PREV
    expected_seq = 1
    for record in records:
        if record.v != CHAIN_VERSION:
            fail(E_BAD_CHAIN, "unsupported record version")
        assert_signers(record, trust)
        if record.seq != expected_seq:
            fail(E_BAD_CHAIN, f"expected seq {expected_seq}, found {record.seq}")
        verify_record(record, prev)
        evidence_path = (settings.evidence_dir / f"{record.evidence_id}.json").resolve()
        if evidence_path.parent != settings.evidence_dir.resolve():
            fail(E_BAD_CHAIN, "evidence path escapes workspace")
        if not evidence_path.exists():
            fail(E_BAD_CHAIN, f"seq {record.seq} missing evidence file")
        payload_bytes = evidence_path.read_bytes()
        if sha256_bytes(payload_bytes) != record.payload_sha256:
            fail(E_BAD_CHAIN, f"seq {record.seq} evidence hash mismatch")
        verify_payload_scope(settings, record.seq, payload_bytes, requested=requested)
        prev = sha256_obj(record.to_dict())
        expected_seq += 1
    if records and not checkpoints:
        fail(
            E_NO_CHECKPOINT,
            "records exist but no Merkle/TSA checkpoint covers the chain",
        )
    head = records[-1].seq if records else 0
    for checkpoint in checkpoints:
        if checkpoint.v != 1 or not 1 <= checkpoint.from_seq <= checkpoint.to_seq <= head:
            fail(E_BAD_CHAIN, "invalid checkpoint version or range")
    covered_seqs = _covered_seqs(checkpoints)
    required = set(range(1, head + 1))
    if records and covered_seqs != required:
        fail(
            E_NO_CHECKPOINT,
            f"checkpoint coverage {sorted(covered_seqs)} does not match seq 1..{head}",
        )
    tsa_cert = settings.keys_dir / "tsa.crt"
    if checkpoints and not tsa_cert.exists():
        fail(E_TSA, "missing TSA certificate; cannot verify checkpoints")
    cert_pem = tsa_cert.read_bytes() if tsa_cert.exists() else b""
    if cert_pem and sha256_bytes(cert_pem) != trust["tsa_sha256"]:
        fail(E_TSA, "TSA certificate differs from the trusted pin")
    for checkpoint in checkpoints:
        window = [row for row in records if checkpoint.from_seq <= row.seq <= checkpoint.to_seq]
        if checkpoint.leaf_count != len(window):
            fail(E_BAD_CHAIN, f"checkpoint {checkpoint.tsa_serial} leaf_count mismatch")
        leaves = [sha256_obj(row.to_dict()) for row in window]
        root = merkle_root(leaves) if leaves else ""
        if root != checkpoint.merkle_root:
            fail(E_BAD_CHAIN, f"checkpoint {checkpoint.tsa_serial} Merkle root mismatch")
        der = base64.b64decode(checkpoint.tsa_token_b64)
        verify_token(der, checkpoint.merkle_root, cert_pem)
    return {
        "ok": True,
        "records": len(records),
        "checkpoints": len(checkpoints),
        "covered_through": _covered_through(checkpoints),
        "head_seq": records[-1].seq if records else 0,
        "signers_registered": True,
        "continuity": "external_and_local" if settings.anchor_dir else "local_only",
    }


def checkpoint_status(settings: Settings) -> dict[str, Any]:
    records = load_records(settings)
    checkpoints = load_checkpoints(settings)
    covered = _covered_through(checkpoints)
    head = records[-1].seq if records else 0
    return {
        "records": len(records),
        "checkpoints": len(checkpoints),
        "covered_through": covered,
        "head_seq": head,
        "fail_closed": bool(records) and covered < head,
    }


def is_no_checkpoint(exc: BaseException) -> bool:
    return isinstance(exc, BeaconError) and exc.code == E_NO_CHECKPOINT
