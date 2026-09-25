# AO rules and the Foreman-shaped Jev adapter

> Historical design note. The implemented contract and migration path are in
> [the verified workflow](../VERIFIED_WORKFLOW.md). Version-1 claim receipts are
> non-authoritative; version-2 evaluations cover supporting assertions only.
> Objective source taxonomy also includes Data and Facility. The SDK returns a
> numeric Noul probability and rubric-indexed Score, not the former stub enums.


Status: design accepted. This change adds this note only.
Date: 2026-09-24.

This note extends [assessment-scope-and-jev.md](assessment-scope-and-jev.md). It does not change `beacon/scope/document.py`. It does not change `decide_claim`. It does not change `JudgmentReceipt`. It does not change `beacon/scf/catalog/PIN.json`. It does not vendor `controls.json`. It does not vendor assessment-objective rows. It does not invent SCF control ids. Example ids stay IAC-02, CRY-07, and GOV-02.

SCF 2026.3 has an assessment-objectives sheet. The pin records `total_assessment_objectives` as 6446. The pin files do not store those rows. The offline slice `beacon/scf/offline/IAC-02.json` and `beacon/scf/offline/CRY-07.json` do not store assessment objectives. This note does not copy assessment-objective statements.

## Problem

The parent note judges one control. A control has many assessment objectives. Each objective has a People, Process, or Technology tag on the assessment-objectives sheet. A cloud inspector can speak only to a Technology objective. A green AWS result does not satisfy a Process objective or a People objective. A control claim from AWS alone overclaims.

Phase 4 still needs a Jev adapter. Jev must score. Python must decide.

## Decision

Beacon validates each in-scope assessment objective. Beacon does not validate the control as one boolean. A control is met only when every in-scope objective outcome is `satisfied`. Any other outcome blocks the control. The roll-up returns machine reasons. It does not print a claim word.

`decide_claim` stays the claim gate in `beacon/scope/document.py`. A later phase adds a roll-up caller. That caller runs the ordered gate below, then calls `decide_claim` once for each linked `JudgmentReceipt`. The current function signature stays until that phase. Claim words stay behind `decide_claim` permitted and a visible `receipt_id`.

## Assessment objectives

The first build step after this note vendors assessment-objective rows into the offline pin. The source is the SCF 2026.3 assessment-objectives sheet. Where that sheet names a NIST SP 800-53A objective, the vendor step copies that label as provenance. This note does not invent those labels.

The offline control slice for IAC-02 maps `general-nist-800-53-r5-2` to the control ids `AC-01` and `IA-01`. That map is not an assessment-objective list. It is not 800-53A provenance.

The approved example for IAC-02 is objective ids `IAC-02_A01` through `IAC-02_A06`. Those rows carry People, Process, and Technology tags. This note does not quote the objective statements. The engine reads the statement and the tag from the vendored row. A missing row fails closed.

An in-scope objective is a row on that control. This note does not add an objective exclusion field to `ScopeDocument`.

## Rule file

Each objective has one versioned rule file. The file is canonical JSON-equivalent TOML. Beacon hashes the file the same way it hashes a scope document. The hash covers the file body. The file does not store its own hash.

The file lists the evidence kinds that may satisfy the objective. It requires live mode. It requires the evidence principal to sit inside the scope boundary and outside exclusions. It sets `max_age` to the control `conformity_cadence` from the catalog row. The IAC-02 offline slice label is `Annual`. This note does not convert that label into a day count.

Asserts read organization-defined parameters from the scope. `ScopeDocument` schema version 1 has no parameter field. A later phase adds that field. A missing parameter fails closed. This note does not invent parameter ids.

Rule outcomes:

| Outcome | Meaning |
| --- | --- |
| `satisfied` | Every gate for this objective passed. |
| `not_satisfied` | A require, an assert, or a Jev threshold failed. |
| `no_evidence` | No evidence of an allowed kind is present. |
| `needs_judgment` | Deterministic gates passed and the rule sends the excerpt to Jev. |

`needs_judgment` is not a final outcome. The arbiter calls Jev and then writes `satisfied` or `not_satisfied`.

Evidence kind limits:

| Tag on the objective | Evidence that may satisfy it |
| --- | --- |
| Technology | `cloud_inspector`, and other kinds the rule lists |
| Process | `policy`, `attestation`, or `inbox` |
| People | `policy`, `attestation`, or `inbox` |

`ScopeDocument` schema version 1 allows `cloud_inspector`, `lake_log_extract`, `catalog_pin`, and `drop_in`. `policy`, `attestation`, and `inbox` are later kinds. A rule that names a kind the scope does not allow fails closed. This note does not add kinds to the schema.

`beacon policy hash` addresses a JSON policy. The custody tag is `evidence:policy`. That hash is not a witness seal of a git tip. `beacon inbox intake` writes a candidate from a local JSON file. It does not open a mailbox. This repository has no attestation collector. A candidate file is not evidence until a later phase seals it. An unsealed candidate does not satisfy an objective.

A sealed payload `mode` must be `live`. `fixture`, `live_failed`, and `failed` fail the mode require. They do not satisfy. They do not reach Jev.

## Foreman-shaped adapter

The pattern comes from [thruwire/foreman](https://github.com/thruwire/foreman) (`docs/why-jev.md`). Beacon does not vendor that repository. Beacon does not copy its code.

Jev is TypeSafe System One. The adapter calls `system_one` through `typesafe-sdk`. Jev returns Choice, Score, and Noul. Jev does not permit a claim. Python owns `decide_claim` and the objective roll-up.

| Judgment | Use in Beacon | Jev does not |
| --- | --- | --- |
| Choice | Candidate router only: `pick` or `no_match` | Pick an objective or a control id |
| Score | `coverage` from 0 through 1 | Receive `min_threshold` or return permitted |
| Noul | `sufficient`, `insufficient`, or `abstain` | Emit a claim word |

The parent note already defines those three results. `DEFAULT_SCORE_MIN` stays `1.0`. The rule file stores `min_threshold` for Beacon. The adapter does not send `min_threshold` to Jev. A threshold outside 0 through 1 makes the rule file invalid.

The adapter runs only after the ordered gate reaches `needs_judgment`. The rule file names the checks and each `min_threshold`.

The state sent to Jev is compact:

| Part | Bound |
| --- | --- |
| Evidence excerpt | A sealed excerpt with a maximum size the adapter enforces |
| Objective text | The vendored statement for that objective id |
| Scope parameters | The organization-defined parameters the asserts name |

The state does not include the repository tree. The state does not include the policy tree. A payload that exceeds the excerpt bound fails closed. The adapter does not truncate in secret and then call Jev.

A deterministic fail overrides a Jev pass. The ordered gate does not call Jev after a require or assert fail. Fixture evidence, stale evidence, and out-of-scope evidence never reach Jev and never satisfy.

A malformed Jev body, a timeout, a score below `min_threshold`, Noul `insufficient`, and Noul `abstain` fail closed. The reason is a machine reason. The adapter writes a `JudgmentReceipt` only for a response that passes Beacon checks. A failed call does not write a passing receipt.

The receipt schema stays version 1: `receipt_id`, `scope_id`, `scope_sha256`, `evidence_sha256`, `control_ref`, `choice`, `score`, and `noul`. A later phase may add `ao_id`. This note does not add that field. The parent link rules stay. The roll-up keeps one receipt for each objective that called Jev.

## Ordered gate

The arbiter applies these steps in order. It stops at the first failure.

1. A deterministic require or assert fails. The outcome is `not_satisfied`. Jev is not called.
2. Evidence of an allowed kind is missing. The outcome is `no_evidence`. Jev is not called.
3. The rule sets `needs_judgment`. The adapter calls Jev. A score below `min_threshold`, Noul `insufficient`, or Noul `abstain` sets `not_satisfied` and records the reason. A malformed body or a timeout sets `not_satisfied` and records the reason.
4. Every in-scope objective is `satisfied`, and each Jev path has a linked receipt that `decide_claim` permits. Only then may a control claim use `decide_claim`.

Step 4 does not print `compliant`, `evidenced`, or `proven`. Those words appear only when `decide_claim` returns `permitted` true and the same view shows `receipt_id`.

Machine reasons for this gate include `require_mode_failed`, `principal_out_of_boundary`, `evidence_stale`, `evidence_kind_rejected`, `assert_failed`, `missing_odp`, `no_evidence`, `jev_malformed`, and `jev_timeout`. Score and Noul failures keep the parent reasons `score_below_min`, `noul_insufficient`, and `noul_abstain`. The reason list has no claim word.

## Rule sketch

This sketch is not loaded. It uses `IAC-02_A03` as a Process example. The vendored row supplies the statement and the tag. This sketch does not contain that statement. If the vendored tag is not Process, the rule file fails closed.

```toml
schema_version = 1
ao_id = "IAC-02_A03"
control_ref = "IAC-02"
ppt = "Process"

[deterministic]
require_mode = "live"
require_principal_in_boundary = true
max_age = "conformity_cadence"
allowed_evidence_kinds = ["policy", "attestation", "inbox"]

[[deterministic.asserts]]
odp = "operator_review_frequency"
present = true

[jev]
when = "needs_judgment"

[jev.checks.procedure_matches_ao]
kind = "noul"
min_threshold = 1.0

[jev.checks.coverage]
kind = "score"
min_threshold = 1.0
```

`operator_review_frequency` is an operator parameter name in the sketch. It is not an SCF id. `when = "needs_judgment"` fires only after the deterministic section passes and evidence of an allowed kind is present. Choice stays on the candidate router. This sketch does not put Choice on the objective.

A Technology objective that a live cloud inspector can close does not set `when = "needs_judgment"`. The same ordered gate still rejects fixture, stale, and out-of-scope evidence.

## Phased build plan

This work stays inside phases 3 and 4 of [assessment-scope-and-jev.md](assessment-scope-and-jev.md). Those phase numbers do not change. Do the steps in this order:

| Step | Work | Phase | Done in this change |
| --- | --- | --- | --- |
| 1 | Vendor assessment objectives into the offline pin. Copy 800-53A provenance where the sheet has it. Fail closed when a cited objective id has no row. | 3 | No |
| 2 | Deterministic rule engine and per-objective roll-up. The roll-up calls `decide_claim` for each linked receipt. | 3 | No |
| 3 | Jev adapter. Tests use a local fake judge. No network. A later step uses live `typesafe-sdk`. | 4 | No |

Freeze-aware timing is optional. This note does not define a fleet freeze policy.

## Non-goals

This design leaves the following work out:

- Vendoring Foreman or copying its code
- Container or microVM isolation for collectors
- A live Jev network client in this change
- A change to the SCF catalog pin in this change
- New SCF control ids, new objective ids, or copied objective statements
- A change to `decide_claim` or `JudgmentReceipt` in this change
