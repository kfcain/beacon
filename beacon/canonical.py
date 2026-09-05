"""Canonical JSON for hashing and signatures."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def dumps(obj: Any) -> bytes:
    """UTF-8 JSON with sorted keys and no extra whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_obj(obj: Any) -> str:
    return sha256_bytes(dumps(obj))
