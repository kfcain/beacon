---
name: beacon-scf-pin
description: Use the offline SCF 2026.3 pin, the legacy id map, and the objective rows. Do not invent control ids.
---

# SCF pin

Use this skill when you cite an SCF control, an assessment objective, a legacy id, or a framework hop.

## Pin

The pin directory is `beacon/scf/catalog/`. The verifier is `beacon/scf/catalog_pin.py`.

`beacon/scf/catalog/PIN.json` says version `2026.3`. Pinned counts: 1591 controls, 34 families, 270 mapped crosswalks, 422 evidence requests, 6446 assessment objectives.

Workbook SHA-256:

`5a89bf2d3c106a9a87d4b6e3d62dd3e147d0e960d4c07473045a10aa8a7df697`

The pin does not vendor `controls.json` or licensed control prose. The objective rows are `beacon/scf/objectives/rows.json`. `NOTICE.md` in that folder names the sheet and the same workbook hash.

The live hosts `https://hackidle.github.io/scf-api/` and the GRC Engineering Club host are not the 2026.3 pin. Their max is 2026.1.1. Set `BEACON_SCF_OFFLINE=1` for the offline path. `BEACON_SCF_CATALOG_PATH` points at another pin directory.

## Legacy map

Cite the 2026.3 id. The legacy number is a pointer from the 2026.2 workbook.

| 2026.2 legacy id | Meaning | 2026.3 id |
| --- | --- | --- |
| IAC-01 | IAM | IAC-02 |
| CRY-05 | Data at rest | CRY-07 |
| GOV-01 | SCRP | GOV-02 |

The 2026.3 ids IAC-01, CRY-05, and GOV-01 name different controls. `control:IAC-01` fails closed for the IAM path.

Offline control JSON exists for IAC-02 and CRY-07 only (`beacon/scf/offline/`). `--target` uses that slice. The catalog plugin seals GOV-02 and leaves `framework_hops` empty.

## Hops and objectives

Copy a framework hop only from `beacon/scf/offline/<scf_id>.json` crosswalks. A framework id in `PIN.json` `pillar_framework_ids` is a catalog id. It is not a hop list.

`usa-federal-gsa-fedramp-20x-ksi` is in `not_a_framework_id`. It is not a framework id and it is not an SCF control id.

```bash
BEACON_SCF_OFFLINE=1 beacon collect --plugin scf.catalog.offline --fixture
beacon objectives --control CRY-07
beacon rules --control CRY-07
```

`beacon objectives --control CRY-07` prints rows from the vendored sheet. Read the `statement` before you map a check to an `ao_id`.

## Success

The id you write is a `control_ref` or `ao_id` in `rows.json`, or a control file under `beacon/scf/offline/`. The legacy column matches that row.

## Stop

Stop when the id is not in those files. Omit it. Do not invent an id, a hop, or a statement.

Stop when you attach a hop to IAC-25, MON-04, CFG-17.2, or any control with no offline JSON.

Stop when you treat the live SCF host as the 2026.3 pin.
