"""Witness chain, Merkle checkpoints, RFC 3161 TSA, fail-closed check."""

from __future__ import annotations

import base64

import pytest

from beacon.canonical import sha256_obj
from beacon.config import load_settings
from beacon.crypto.keys import load_roles
from beacon.crypto.tsa import OID_TST_INFO, verify_token
from beacon.crypto.witness import (
    check_chain,
    create_checkpoint,
    load_checkpoints,
    load_records,
    seal_payload,
)
from beacon.errors import E_BAD_CHAIN, E_NO_CHECKPOINT, BeaconError


def test_init_creates_distinct_recorder_and_witness(initialized):
    recorder, witness = load_roles(load_settings().keys_dir)
    assert recorder.fingerprint() != witness.fingerprint()
    assert len(recorder.fingerprint()) == 64
    assert recorder.role == "recorder"
    assert witness.role == "witness"


def test_check_fails_closed_without_checkpoint(initialized):
    settings = load_settings()
    seal_payload(
        settings,
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["IAC-02"],
        payload={"n": 1},
    )
    with pytest.raises(BeaconError) as caught:
        check_chain(settings)
    assert caught.value.code == E_NO_CHECKPOINT
    assert "E_NO_CHECKPOINT" in str(caught.value)


def test_checkpoint_covers_chain_and_tsa_matches_merkle(initialized):
    settings = load_settings()
    seal_payload(
        settings,
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["CRY-07"],
        payload={"n": 1},
    )
    seal_payload(
        settings,
        plugin="azure.inspector",
        mode="fixture",
        scf_targets=["CRY-07"],
        payload={"n": 2},
    )
    checkpoint = create_checkpoint(settings)
    result = check_chain(settings)
    assert result["ok"] is True
    assert result["records"] == 2
    assert result["checkpoints"] == 1
    cert_pem = (settings.keys_dir / "tsa.crt").read_bytes()
    der = base64.b64decode(checkpoint.tsa_token_b64)
    token = verify_token(der, checkpoint.merkle_root, cert_pem)
    assert token.message_imprint == checkpoint.merkle_root
    assert OID_TST_INFO in der


def test_partial_checkpoint_still_fail_closed(initialized):
    settings = load_settings()
    seal_payload(
        settings,
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["IAC-02"],
        payload={"a": 1},
    )
    create_checkpoint(settings)
    seal_payload(
        settings,
        plugin="gcp.inspector",
        mode="fixture",
        scf_targets=["IAC-02"],
        payload={"a": 2},
    )
    with pytest.raises(BeaconError) as caught:
        check_chain(settings)
    assert caught.value.code == E_NO_CHECKPOINT


def test_hash_chain_links(initialized):
    settings = load_settings()
    first = seal_payload(
        settings,
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["IAC-02"],
        payload={"k": "a"},
    )
    second = seal_payload(
        settings,
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["IAC-02"],
        payload={"k": "b"},
    )
    assert second.prev_sha256 == sha256_obj(first.to_dict())
    assert first.seq == 1
    assert second.seq == 2
    create_checkpoint(settings)
    records = load_records(settings)
    assert len(records) == 2
    assert load_checkpoints(settings)[0].leaf_count == 2


def test_tampered_evidence_fails_check(initialized):
    settings = load_settings()
    record = seal_payload(
        settings,
        plugin="aws.inspector",
        mode="fixture",
        scf_targets=["IAC-02"],
        payload={"k": "clean"},
    )
    create_checkpoint(settings)
    path = settings.evidence_dir / f"{record.evidence_id}.json"
    path.write_text('{"secret":"TAMPERED"}', encoding="utf-8")
    with pytest.raises(BeaconError) as caught:
        check_chain(settings)
    assert caught.value.code == E_BAD_CHAIN


def test_checkpoint_gap_is_e_no_checkpoint(initialized):
    settings = load_settings()
    for i in range(3):
        seal_payload(
            settings,
            plugin="aws.inspector",
            mode="fixture",
            scf_targets=["IAC-02"],
            payload={"i": i},
        )
    create_checkpoint(settings, from_seq=3, to_seq=3)
    with pytest.raises(BeaconError) as caught:
        check_chain(settings)
    assert caught.value.code == E_NO_CHECKPOINT
