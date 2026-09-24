"""Read framework ids from the vendored SCF 2026.3 pin. This module does not add ids."""

from __future__ import annotations

import json
from functools import lru_cache

from beacon.canonical import sha256_bytes
from beacon.scf.catalog_pin import (
    PINNED_COUNTS,
    PINNED_FILE_SHA256,
    PINNED_NOT_A_FRAMEWORK_IDS,
    PINNED_PILLAR_FRAMEWORK_IDS,
    VENDORED_CATALOG_DIR,
)

# Offline slice plus the catalog plugin target. 2026.3 legacy map:
# IAC-01 (IAM) -> IAC-02, CRY-05 (data at rest) -> CRY-07, GOV-01 (SCRP) -> GOV-02.
SEEDED_CONTROL_IDS: frozenset[str] = frozenset({"IAC-02", "CRY-07", "GOV-02"})


@lru_cache(maxsize=1)
def pinned_framework_ids() -> frozenset[str]:
    """Return crosswalk framework ids from the vendored summary. Fail closed on a bad pin file."""
    path = VENDORED_CATALOG_DIR / "summary.json"
    try:
        raw_bytes = path.read_bytes()
        data = json.loads(raw_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("pin summary cannot be read") from exc
    if sha256_bytes(raw_bytes) != PINNED_FILE_SHA256["summary.json"]:
        raise ValueError("pin summary hash does not match the pin")
    raw = data.get("crosswalk_frameworks") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        raise ValueError("pin summary has no crosswalk_frameworks list")
    ids: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("pin framework row is not an object")
        framework_id = item.get("framework_id")
        if not isinstance(framework_id, str) or framework_id != framework_id.strip() or not framework_id:
            raise ValueError("pin framework_id is blank")
        ids.append(framework_id)
    expected = PINNED_COUNTS["total_crosswalk_frameworks"]
    if len(ids) != expected or len(ids) != len(set(ids)):
        raise ValueError("pin framework id count does not match the pin")
    blocked = set(PINNED_NOT_A_FRAMEWORK_IDS)
    if blocked.intersection(ids):
        raise ValueError("pin framework list includes a blocked id")
    for pillar in PINNED_PILLAR_FRAMEWORK_IDS:
        if pillar not in ids:
            raise ValueError("pin framework list misses a pillar id")
    return frozenset(ids)


def framework_id_on_pin(framework_id: str) -> bool:
    """True when the id is on the pin and is not a documented non-framework id."""
    if framework_id in PINNED_NOT_A_FRAMEWORK_IDS:
        return False
    return framework_id in pinned_framework_ids()
