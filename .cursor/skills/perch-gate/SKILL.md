---
name: perch-gate
description: Install Perch, author Terraform rules mapped to pinned SCF objectives, wire the opt-in CI gate, and emit an unverified gate receipt for a later Beacon seal.
---

# Perch Gate

Perch Gate stops a Terraform miss before merge. Beacon keeps custody of a sealed receipt. A gate run is not a seal. A seal is not a statement that a control is met.

Use the status word **unverified** until a sealed receipt id is in the same view. A claim word needs that sealed receipt. The v0 receipt schema sets `claim_status` to `unverified` and `sealed` to false.

## Install Perch

1. Create a key in the TypeSafe console.
2. Store it as the Actions secret `PERCH_API_KEY`. Keep the key out of the repo, the chat, and the workflow file.
3. Install the CLI when a human will run a scan: `npm install -g @lakeday/perch`.
4. `perch setup cursor` writes `.cursor/rules/perch.mdc`. That file is the upstream Perch helper. This skill is the Beacon gate.

`perch doctor` checks the key. `perch scan` and `perch check` call the API. `perch rules list` does not.

## Author rules

Put rules in `.perch/rules/*.yaml` or in `perch.yaml`. Perch rejects a key that is not in its grammar. Put SCF ids in `# beacon.*` comments above the rule name. Copy the same fields into `perch-gate/maps/terraform-v0.json`.

Each mapped `ao_id` must be a row in `beacon/scf/objectives/rows.json`. The `scf_id` must equal that row's `control_ref`. Copy `legacy_control_ref`, `ppt`, and `origins` from that row. When the row has no `ao_id` for the check, omit `ao_id`. When `legacy_control_ref` is `NONE`, omit it.

Copy `framework_hops` only from `beacon/scf/offline/<scf_id>.json`. The v0 offline slice has control JSON for IAC-02 and CRY-07. Leave hops off a rule that has no offline JSON.

v0 rules use `where: "**/*.tf"`, `each: file`, `min: 70`, and `gate: true`. Say what breaks the rule in `ensure`.

Run `PYTHONPATH=. python3 -m beacon.perch_gate --mock` after an edit. The command checks the map against the objective rows. It writes a mock receipt. `live_api` is false.

## Wire CI

Use `.github/workflows/perch-gate.yml`. The job reads `secrets.PERCH_API_KEY`. A pull request runs the job only when the repository variable `PERCH_GATE_ON` is `true`. `workflow_dispatch` runs it without that variable. The workflow is not a required check.

The pinned CLI in that file is `@lakeday/perch@0.3.5`. The scan target defaults to `deploy/aws`. A human can pass another relative directory on `workflow_dispatch`.

An empty `PERCH_API_KEY` writes a receipt with `live_api` false and exit code 1. The job then fails. No request is sent.

## Emit a receipt

The receipt schema is `perch-gate/schema/gate-receipt.schema.json`. Required charter fields are `kind`, `repo`, `commit_sha`, `ruleset_sha256`, `perch_version`, `exit_code`, `problem_count`, `failing`, `ao_hits`, `scope_id`, and `scope_sha256`.

```bash
PYTHONPATH=. python3 -m beacon.perch_gate --mock --out perch-gate-receipt.json
beacon perch-receipt --mock
```

A scan receipt needs the scan JSON, the process exit code, the repo, the commit, and the Perch version:

```bash
PYTHONPATH=. python3 -m beacon.perch_gate \
  --scan perch-scan.json \
  --exit-code 0 \
  --repo owner/name \
  --commit "$GIT_SHA" \
  --perch-version 0.3.5 \
  --live-api \
  --out perch-gate-receipt.json
```

`--live-api` means this process called Perch. It does not mean the receipt is sealed.

`beacon perch-receipt` does not append a witness record. A later seal command can read this JSON. That command is not in v0.

## Claim words

Say **unverified** when `sealed` is false. Say **unverified** when `live_api` is false. A green `exit_code` is still unverified. A collector that runs later is still required for runtime proof. The preventive gate and the custody seal are both required before a control story is strong.
