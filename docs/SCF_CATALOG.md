# SCF catalog pin (2026.2, offline)

Beacon verifies Secure Controls Framework **2026.2** with a slim offline pin.
Live HackIDLE and GRC Engineering Club APIs stay at 2026.1.1 / 2026.1.
Those APIs are **not** the pin.

## What is vendored

Path: `beacon/scf/catalog/` (verifier: `beacon/scf/catalog_pin.py`)

| File | Role |
| --- | --- |
| `PIN.json` | Version, workbook SHA-256, counts, SHA-256 of the JSON files |
| `summary.json` | `scf_version`, counts, 34 families (includes `QTS`) |
| `families.json` | Family codes, names, control counts |
| `index-meta.json` | Workbook metadata, family codes, stale live-host note |

This pin does **not** vendor `controls.json` (about 15 MB).
It does not copy licensed control prose.

Workbook SHA-256 (official SCF 2026.2 xlsx):

`9e0a4df4993726c95e636f04b3028d8b5edeba2bda45d16ed6722b13540e6835`

Pinned counts: 1534 controls, 34 families, 249 mapped crosswalks, 316 ERLs, 5956 assessment objectives.

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

- `scf_version` is not `2026.2`
- a required file is missing
- a declared SHA-256 does not match
- a pinned count does not match

`--live` does **not** fetch HackIDLE. It seals `live_failed`.

The plugin declares drop-in target `GOV-01` (already used by `examples/echo_platform.py`).
Do not invent SCF control IDs.
`beacon collect --target GOV-01` still needs that control in the offline control slice. Use `--plugin scf.catalog.offline` for this pack.

## Sealed evidence

The hashed payload includes:

- `catalog_pin` / `pin`: path provenance (`vendored` or `env`), workbook SHA-256, file hashes, counts
- `scf_binding`: `scf_version`, `scf_id` (`GOV-01`), `scf_family` (`GOV`), empty `erl_ids` and `framework_hops`, `pinned`, `provenance: scf-catalog`

`framework_hops` stay empty on this pack. This collector does not map one control to pillar FDIs.
Open draft PR #5 stamps control-level `scf_binding` hops (`provenance: scf-crosswalk`) from the offline control slice.

## Limits

Air-gap operation is supported.
The live SCF API is not authoritative for 2026.2.
See [LIMITS.md](../LIMITS.md).
