"""Reproduce the unmodified SCF AO field export from the pinned workbook.

Usage: python scripts/vendor_scf_objectives.py /path/to/scf-2026.3.xlsx
Requires the optional catalog extra. Does not fetch files or update the pin.
"""
import hashlib
import json
import sys
from pathlib import Path

import openpyxl

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA256 = "5a89bf2d3c106a9a87d4b6e3d62dd3e147d0e960d4c07473045a10aa8a7df697"


def main():
    source = Path(sys.argv[1])
    if hashlib.sha256(source.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise SystemExit("Workbook differs from the reviewed SCF 2026.3 source")
    workbook = openpyxl.load_workbook(source, data_only=True, read_only=True)
    sheet = workbook["Assessment Objectives 2026.3"]
    rows = []
    for row_number, row in enumerate(sheet.iter_rows(min_row=2, values_only=True), start=2):
        if not row[0] or not row[1] or not row[2]:
            raise ValueError(f"missing objective identity or statement at row {row_number}")
        rows.append({"control_ref": row[0], "ao_id": row[1], "statement": row[2],
                     "ppt": row[5], "recommended_parameters": row[4], "origins": row[7],
                     "nist_800_53a": row[11], "legacy_control_ref": row[9], "source_row": row_number})
    if len(rows) != 6446 or len({r["ao_id"] for r in rows}) != 6446:
        raise ValueError("unexpected objective count or duplicate IDs")
    document = {"schema_version": 1, "catalog_version": "2026.3", "source_sha256": SOURCE_SHA256,
                "source_sheet": sheet.title, "rows": rows}
    body = json.dumps(document, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    target = ROOT / "beacon" / "scf" / "objectives" / "rows.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(body)
    print(json.dumps({"rows": len(rows), "sha256": hashlib.sha256(body).hexdigest()}))


if __name__ == "__main__":
    main()
