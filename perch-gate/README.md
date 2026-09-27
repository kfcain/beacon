# Perch Gate v0

Perch Gate checks Terraform before merge. Beacon seals a gate receipt later. A receipt in this pack has `claim_status` `unverified` and `sealed` false.

The charter summary is [docs/architecture/perch-gate.md](../docs/architecture/perch-gate.md).

## Preventive gate and custody

| Step | Owner | Result |
| --- | --- | --- |
| Rule pack and `perch scan` | Perch Gate in the delivery repo | CI exit and a receipt JSON file |
| Witness seal of that receipt | Beacon | A sealed record |
| Runtime collectors | Beacon | Evidence after deploy |

A passing scan is a preventive result. It is not a seal. It is not a statement that a control is met. Use the status word unverified until a sealed receipt is in the same view.

## What is in this repo

| Path | Role |
| --- | --- |
| `skills/beacon-perch-gate/SKILL.md` | Install, author, CI, receipt, claim words |
| `.perch/rules/terraform-v0.yaml` | Four Terraform rules Perch can parse |
| `perch-gate/maps/terraform-v0.json` | SCF and AO map for those rules |
| `perch.yaml` | `scan_types: [lint]` for this pack |
| `perch-gate/schema/gate-receipt.schema.json` | Receipt schema |
| `.github/workflows/perch-gate.yml` | Opt-in GitHub Action |
| `beacon/perch_gate.py` | Receipt builder. It does not seal. |

Perch rejects unknown YAML keys. SCF ids are in `# beacon.*` comments and in the JSON map. The builder fails when those two copies differ, and when an `ao_id` is missing from `beacon/scf/objectives/rows.json`.

## SCF map

Ids below are rows in the vendored SCF 2026.3 objective sheet. Framework hops are copied only where `beacon/scf/offline/<id>.json` exists.

| Rule | SCF id | AO id | Legacy id on the row | Offline JSON |
| --- | --- | --- | --- | --- |
| `tf-encryption-at-rest` | CRY-07 | CRY-07_A02 | CRY-05 | `beacon/scf/offline/CRY-07.json` |
| `tf-no-public-acl` | IAC-25 | IAC-25_A06 | IAC-20 | none |
| `tf-required-logging` | MON-04 | MON-04_A02 | MON-01.4 | none |
| `tf-no-plaintext-secrets` | CFG-17.2 | CFG-17.2_A04 | CFG-09.2 | none |

IAC-02 is the offline IAM control. Its objectives describe the IAM program. The public-ACL rule uses IAC-25_A06 ("system access is limited to authorized users"). `aws.lake.logs` still seals IAC-02. That collector target is a different path.

CRY-07_A07, IAC-25_A01, and IAC-53_A03 are real rows. They are not `ao_id` values on these rules. The gap text in the JSON map says when to add them.

A rule with no matching objective omits `ao_id`. Do not invent an id.

## Run locally

The mock path does not call Perch and does not need `PERCH_API_KEY`.

```bash
PYTHONPATH=. python3 -m beacon.perch_gate --mock
beacon perch-receipt --mock
```

A live scan needs a key in the environment. This repository does not store one.

```bash
export PERCH_API_KEY
npx --yes @lakeday/perch@0.3.5 scan deploy/aws --json > perch-scan.json
```

Write the receipt with the same exit code the scan returned. Pass `--live-api` only after that command ran.

```bash
PYTHONPATH=. python3 -m beacon.perch_gate \
  --scan perch-scan.json \
  --exit-code 0 \
  --repo owner/name \
  --commit "$(git rev-parse HEAD)" \
  --perch-version 0.3.5 \
  --live-api
```

`perch-gate/examples/deliberate-miss/bucket.tf` is a sample miss. Scan that directory when you want the gate to fail. The sample strings are examples. The default CI target is `deploy/aws`.

## CI

The workflow file is `.github/workflows/perch-gate.yml`.

- Secret: `PERCH_API_KEY`
- Pull requests run the job only when the repository variable `PERCH_GATE_ON` is `true`
- `workflow_dispatch` runs the job without that variable
- The job uploads `perch-gate-receipt.json`
- An empty secret writes `live_api: false` and fails the job
- The workflow is not part of the required checks in `.github/workflows/ci.yml`

This pack does not record a live Perch API run.
