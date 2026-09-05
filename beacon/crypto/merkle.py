"""SHA-256 Merkle tree over hex leaf hashes."""

from __future__ import annotations

import hashlib


def _digest(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def merkle_root(leaf_hex: list[str]) -> str:
    """Return the hex Merkle root. Duplicate the last node when the level is odd."""
    if not leaf_hex:
        raise ValueError("merkle_root requires at least one leaf")
    level = [bytes.fromhex(item) for item in leaf_hex]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            nxt.append(_digest(level[i], level[i + 1]))
        level = nxt
    return level[0].hex()
