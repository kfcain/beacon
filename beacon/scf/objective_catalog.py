"""Verified, versioned SCF assessment objectives with original source provenance."""
import json
from pathlib import Path

from beacon.canonical import sha256_bytes
from beacon.errors import fail

CATALOG_SHA256 = "85bd32502899ff908bb55fee3b1c79f56864565702446bb77fbaf10875725162"
WORKBOOK_SHA256 = "5a89bf2d3c106a9a87d4b6e3d62dd3e147d0e960d4c07473045a10aa8a7df697"
CATALOG_PATH = Path(__file__).parent / "objectives" / "rows.json"


def objectives(control_ref: str | None = None) -> list[dict]:
    body = CATALOG_PATH.read_bytes()
    if sha256_bytes(body) != CATALOG_SHA256:
        fail("E_CATALOG", "assessment objective file differs from its reviewed digest")
    data = json.loads(body)
    if data["source_sha256"] != WORKBOOK_SHA256 or len(data["rows"]) != 6446:
        fail("E_CATALOG", "objective provenance or count mismatch")
    rows = data["rows"]
    if control_ref is None:
        return rows
    selected = [row for row in rows if row["control_ref"] == control_ref]
    if not selected:
        fail("E_CATALOG", "control has no objectives in the pinned source")
    return selected
