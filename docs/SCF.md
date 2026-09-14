# SCF pin (2026.2)

Beacon pins Secure Controls Framework (SCF) **2026.2**.
The pin is the offline bundle under `beacon/scf/offline/`.
Live HackIDLE and GRC Engineering Club APIs stay at 2026.1.x. Those APIs are not the pin.

## Catalog pin

| Field | Value |
| --- | --- |
| SCF version | `2026.2` |
| Controls | 1534 |
| Families | 34 (includes Quantum Security `QTS`) |
| Evidence Request List (ERL) | 316 (was 303 in 2026.1.x) |
| Crosswalk frameworks with mappings | 249 |
| Workbook | `secure-controls-framework-scf-2026-2.xlsx` |
| SHA-256 | `9e0a4df4993726c95e636f04b3028d8b5edeba2bda45d16ed6722b13540e6835` |
| License | CC BY-ND |

`/workspace/scf-catalog/raw/api/` was not present on this host.
Beacon parsed the official SCF 2026.2 workbook and stored slices in the offline bundle.
See `beacon/scf/offline/PIN.json` and `beacon/scf/offline/summary.json`.

## Offline fixtures

Bundled control JSON:

- `IAC-01`
- `CRY-05`
- Quantum Security `QTS-01` through `QTS-08` and their child IDs (`QTS-01.1` … `QTS-06.10`)
- ERL slice `E-QTS-01` … `E-QTS-13` under `beacon/scf/offline/erl/`

The bundle does **not** vendor all 1534 controls.
`BEACON_SCF_OFFLINE=1` fails closed when the control file is absent.

## Sealed evidence metadata

Collect and seal add `scf_binding` on the evidence payload (the bytes that the witness chain hashes):

| Field | Rule |
| --- | --- |
| `scf_version` | `"2026.2"` |
| `scf_id` | SCF control id |
| `scf_family` | Family code (`IAC`, `CRY`, `QTS`, …) |
| `erl_ids[]` | `evidence_requests` from the catalog |
| `framework_hops[]` | Pillar maps only. Each hop is `{framework_id, framework_control_ids[], provenance: "scf-crosswalk"}` |
| `overlay_unmapped` | Empty lists. No guessed maps. |

Pillar `framework_id` values (SCF FDI slugs):

- `usa-federal-gsa-fedramp-5-high`
- `general-nist-800-53-r5-2`
- `usa-federal-dow-cmmc-2-level-2`
- `general-aicpa-tsc-2017`

Do not invent `usa-federal-gsa-fedramp-20x-ksi`.
If a pillar has no catalog map, omit that hop.

Overlay IDs stay unmapped (empty lists):

- `KSI-CNA-OFA`
- `KSI-PIY-RES`
- `SA-09(07)`
- `SC-12(06)`

## Client use

```bash
BEACON_SCF_OFFLINE=1 beacon collect --target IAC-01
BEACON_SCF_OFFLINE=1 beacon collect --target QTS-01
```

`beacon_scf_lookup` reads the same pin.
The witness chain still fails closed with `E_NO_CHECKPOINT` when a checkpoint is missing.

Remaining catalog work (standing): finish evidence binding and framework crosswalk alignment against `/workspace/scf-catalog/raw/api/` when that tree is present. This bundle is a slice. It does not vendor all 1534 controls. QTS pillar hops stay empty when the catalog has no map. Do not invent IDs or hops.
