# Perch Gate

Status: v0 in this repo. Date: 2026-09-27. Owner: Beacon (GRC) / Kyle.

This note is the charter for the preventive gate. The custody path stays in [How Beacon works](../HOW_IT_WORKS.md).

## Problem

Collectors show what is already true in a cloud account. A miss can land on the default branch first. Delivery teams need a stop before merge. Custody still needs a receipt of that stop.

## What the gate owns

1. A rule pack under `.perch/rules/` and `perch.yaml`, mapped to SCF assessment objectives.
2. A CI job that runs `perch scan` and fails when a gated rule breaks.
3. An AO map. Each rule carries `scf_id`. It carries `ao_id` when `beacon/scf/objectives/rows.json` has that row. It carries framework hops only when `beacon/scf/offline/<scf_id>.json` lists them.
4. A gate receipt JSON file for a later Beacon seal.
5. The same skill on any delivery repo. Beacon remains the custody engine.

## What the gate leaves to Beacon

- The witness chain, the lake, and the offline SCF pin.
- Live cloud collectors.
- The objective if-then runtime.
- A seal command. v0 writes the receipt and does not append a witness record.

The gate does not merge code, change production, or publish a trust center.

## Locked decisions (2026-09-27)

1. Ship a skill. Do not add a new bot.
2. Keep rule packs in this Beacon repo.
3. The CI secret name is `PERCH_API_KEY`. The key stays in the TypeSafe console and in Actions secrets.

## Receipt

Minimum fields:

| Field | Meaning |
| --- | --- |
| `kind` | `perch_gate` |
| `repo` | `owner/name` |
| `commit_sha` | Git commit that was scanned |
| `ruleset_sha256` | Hash of `perch.yaml`, the rule files, and the AO map |
| `perch_version` | CLI version, or `not-run` when no CLI ran |
| `exit_code` | Process exit |
| `problem_count` | Issues in the scan JSON |
| `failing` | True when `exit_code` is not 0 |
| `ao_hits` | `scf_id`, optional `ao_id`, and `issue_ids` |
| `scope_id` | Scope id, or null |
| `scope_sha256` | Scope hash, or null |

v0 also sets `schema_version` 0, `claim_status` `unverified`, `sealed` false, and `live_api` true only after a Perch process ran. The schema file is `perch-gate/schema/gate-receipt.schema.json`.

`scope_id` and `scope_sha256` are both present or both null. The builder copies a pair. It does not check the scope file and it does not seal.

## Loop

1. A pull request or a local scan loads the AO-mapped rule pack.
2. `perch scan` or `perch check` reads the Terraform.
3. CI fails when the exit code is not 0.
4. The job writes a gate receipt and uploads it.
5. A later Beacon command seals that file.
6. Collectors still run after deploy.

## v0 Terraform rules

| Rule | Check | SCF id | AO id |
| --- | --- | --- | --- |
| `tf-encryption-at-rest` | Encryption at rest on storage | CRY-07 | CRY-07_A02 |
| `tf-no-public-acl` | Public ACL and public access block | IAC-25 | IAC-25_A06 |
| `tf-required-logging` | A logging resource beside a bucket | MON-04 | MON-04_A02 |
| `tf-no-plaintext-secrets` | No plaintext or encoded secret in `.tf` | CFG-17.2 | CFG-17.2_A04 |

CRY-07 is in the offline control slice. IAC-25, MON-04, and CFG-17.2 are `control_ref` values on vendored objective rows. They have no offline control JSON in this pin, so those three rules have no framework hops.

## Claim words

Use the status word unverified while `sealed` is false. A green exit code is still unverified. A later seal of this JSON is still not a compliance claim. The words compliant, evidenced, and proven need `decide_claim` permitted and a linked `receipt_id` in the same view. v0 does not seal and does not call `decide_claim`. Runtime collectors remain part of the control story.
