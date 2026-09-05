"""Recorder and witness Ed25519 keys. The two roles MUST be distinct."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from beacon.errors import E_KEY_COLLISION, E_NOT_INITIALIZED, fail

RECORDER_NAME = "recorder"
WITNESS_NAME = "witness"


@dataclass(frozen=True)
class KeyPair:
    role: str
    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    def public_raw(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def fingerprint(self) -> str:
        return self.public_raw().hex()

    def sign(self, data: bytes) -> str:
        return self.private.sign(data).hex()


def verify(public_raw_hex: str, data: bytes, signature_hex: str) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_raw_hex))
        public.verify(bytes.fromhex(signature_hex), data)
    except Exception:
        return False
    return True


def _write_private(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _write_public(path: Path, key: Ed25519PublicKey) -> None:
    path.write_bytes(
        key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _load_private(path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)  # type: ignore[return-value]


def generate_keypair(role: str) -> Ed25519PrivateKey:
    if role not in {RECORDER_NAME, WITNESS_NAME}:
        raise ValueError(f"unknown key role: {role}")
    return Ed25519PrivateKey.generate()


def persist_pair(keys_dir: Path, role: str, private: Ed25519PrivateKey) -> KeyPair:
    keys_dir.mkdir(parents=True, exist_ok=True)
    _write_private(keys_dir / f"{role}.pem", private)
    _write_public(keys_dir / f"{role}.pub", private.public_key())
    return KeyPair(role=role, private=private, public=private.public_key())


def load_pair(keys_dir: Path, role: str) -> KeyPair:
    pem = keys_dir / f"{role}.pem"
    if not pem.exists():
        fail(E_NOT_INITIALIZED, f"missing {role} key; run `beacon init`")
    private = _load_private(pem)
    return KeyPair(role=role, private=private, public=private.public_key())


def generate_distinct_roles(keys_dir: Path) -> tuple[KeyPair, KeyPair]:
    """Create recorder and witness keys. Refuse identical public keys."""
    recorder_priv = generate_keypair(RECORDER_NAME)
    witness_priv = generate_keypair(WITNESS_NAME)
    recorder = persist_pair(keys_dir, RECORDER_NAME, recorder_priv)
    witness = persist_pair(keys_dir, WITNESS_NAME, witness_priv)
    if recorder.public_raw() == witness.public_raw():
        fail(E_KEY_COLLISION, "recorder and witness public keys must be distinct")
    return recorder, witness


def load_roles(keys_dir: Path) -> tuple[KeyPair, KeyPair]:
    recorder = load_pair(keys_dir, RECORDER_NAME)
    witness = load_pair(keys_dir, WITNESS_NAME)
    if recorder.public_raw() == witness.public_raw():
        fail(E_KEY_COLLISION, "recorder and witness public keys must be distinct")
    return recorder, witness
