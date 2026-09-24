# SCF catalog pin (2026.3, offline)

Beacon verifies Secure Controls Framework **2026.3** with a slim offline pin.
Live HackIDLE and GRC Engineering Club APIs stay at 2026.1.1 / 2026.1.
Those APIs are **not** the pin.

## What is vendored

Path: `beacon/scf/catalog/` (verifier: `beacon/scf/catalog_pin.py`)

| File | Role |
| --- | --- |
| `PIN.json` | Version, workbook SHA-256, counts, SHA-256 of the JSON files |
| `summary.json` | `scf_version`, counts, 34 families (includes `QTS`), 270 mapped crosswalk framework ids |
| `families.json` | Family codes, names, control counts |
| `index-meta.json` | Workbook metadata, family codes, stale live-host note |

This pin does **not** vendor `controls.json` (about 15 MB).
It does not copy licensed control prose.
It does not vendor the official `.xlsx` workbook. Air-gap collect uses the JSON pin only.
If the workbook file is present next to the pin, the collector hashes it and fails closed on mismatch.
Crosswalk entries in `summary.json` are `framework_id` values from catalog truth. They are not control ids and not hop maps.

Workbook SHA-256 (official SCF 2026.3 xlsx):

`5a89bf2d3c106a9a87d4b6e3d62dd3e147d0e960d4c07473045a10aa8a7df697`

Pinned counts: 1591 controls, 34 families, 270 mapped crosswalks, 422 ERLs, 6446 assessment objectives. Compensating controls in the summary: 1397. QTS control count: 31.

## Collect

Builtin plugin id: `scf.catalog.offline`.

```bash
BEACON_SCF_OFFLINE=1 beacon collect --plugin scf.catalog.offline --fixture
beacon check
```

Optional catalog root:

```bash
export BEACON_SCF_CATALOG_PATH=/path/to/scf-catalog-pin
BEACON_SCF_OFFLINE=1 beacon collect --plugin scf.catalog.offline --fixture
```

`BEACON_SCF_CATALOG_PATH` must point at a directory that contains `PIN.json`, `summary.json`, `families.json`, and `index-meta.json`.
The collector fails closed when:

- `scf_version` is not `2026.3`
- a required file is missing
- a declared SHA-256 does not match
- a pinned count does not match
- `summary.json` `crosswalk_frameworks` is missing, empty, duplicated, or includes a documented non-framework id (`usa-federal-gsa-fedramp-20x-ksi`)

`--live` does **not** fetch HackIDLE. It seals `live_failed`.

The plugin declares drop-in target `GOV-02`. Workbook Legacy SCF # maps 2026.2 `GOV-01` (SCRP) to 2026.3 `GOV-02`. 2026.3 `GOV-01` is a new governance policy control. `examples/echo_platform.py` uses `GOV-02`.
Do not invent SCF control IDs.
`beacon collect --target GOV-02` still needs that control in the offline control slice. Use `--plugin scf.catalog.offline` for this pack.
Do not combine `--plugin scf.catalog.offline` with a different `--target` (for example `IAC-02`). The collector refuses that mix so the seal does not bind the catalog pin to the wrong control.

## Sealed evidence

The hashed payload includes:

- `catalog_pin` / `pin`: path provenance (`vendored` or `env`), workbook SHA-256, file hashes, counts
- `scf_binding`: `scf_version`, `scf_id` (`GOV-02`), `scf_family` (`GOV`), empty `erl_ids` and `framework_hops`, `pinned`, `provenance: scf-catalog`

`framework_hops` stay empty on this pack. This collector does not map one control to pillar FDIs.
Open draft PR #5 stamps control-level `scf_binding` hops (`provenance: scf-crosswalk`) from the offline control slice.

## Limits

Air-gap operation is supported.
The live SCF API is not authoritative for 2026.3.
See [LIMITS.md](../LIMITS.md).
