# Improvement log

## 2026-09-14 — Cycle 1

PR: https://github.com/kfcain/beacon/pull/5

### Why

The SCF agent pinned SCF **2026.2** as the source of truth.
Live HackIDLE and club APIs max at 2026.1.1 / 2026.1. Those APIs are not the pin.
`/workspace/scf-catalog` was not mounted on this VM.
Beacon now vendors 2026.2 slices from the official workbook (SHA-256 `9e0a4df4993726c95e636f04b3028d8b5edeba2bda45d16ed6722b13540e6835`).
Collect and seal write `scf_binding` on hashed evidence.
The witness chain still fails closed.

Catalog counts from the parse (match the pin): 1534 controls, 34 families, 316 ERLs, 249 mapped crosswalk frameworks.

### Next 3 items

1. Standing: finish SCF 2026.2 catalog alignment for evidence binding and framework crosswalks when `/workspace/scf-catalog` is mounted. Keep the pin at 2026.2. Sealed evidence already stores `scf_id` plus pillar `framework_hops` (`provenance: scf-crosswalk`). Remaining work: vendor remaining controls and hops from the catalog. Do not invent control IDs. Do not guess overlay maps (`KSI-CNA-OFA`, `KSI-PIY-RES`, `SA-09(07)`, `SC-12(06)`). Do not invent `usa-federal-gsa-fedramp-20x-ksi`. Live HackIDLE / club APIs stay at 2026.1.x and are not the pin.
2. Finish open PR #4: bind Conftest to the evidence bucket policy and reject IAM action wildcards (Greptile P1).
3. Close the lake gap: S3 access logging and CloudTrail data events for the evidence bucket; seal those logs as lake evidence.

### Blockers

- `/workspace/scf-catalog/raw/api/` is not in this environment. Re-parse if that catalog tree is later mounted.
- Live HackIDLE / GRCEngClub APIs remain 2026.1.x. Do not treat them as 2026.2.
- The offline bundle is a slice (IAC-01, CRY-05, QTS-*, E-QTS-*). It is not the full 1534-control workbook.
- Repo stays private. No production AWS apply in this cycle.

## 2026-09-16 — Cycle 2

PR: https://github.com/kfcain/beacon/pull/6

### Why

PR #4 added Conftest for the AWS evidence lake but left Greptile P1 gaps: the suite accepted a bucket policy on the wrong bucket, and IAM Allow checks used exact strings so `s3:Delete*`, `kms:*`, and `dynamodb:*` passed. Cycle 2 ports those rules onto a new branch from `main`, binds `aws_s3_bucket_policy` to `aws_s3_bucket.evidence` plus `data.aws_iam_policy_document.bucket`, and rejects IAM Allow wildcards with glob matching. The same PR adds a dedicated logging bucket (same KMS / Block Public Access / BucketOwnerEnforced posture, no Object Lock) for S3 server access logs and a module-scoped CloudTrail that records object-level read and write on the evidence bucket. Those AWS files are raw observations. Seal them to findings before they are lake evidence. Do not mix them into evidence-bucket `observations/` or `evidence/` from Terraform. The witness chain still fails closed. FedRAMP 20x wants CloudTrail-class telemetry in a tamper-resistant lake; this change supplies that raw material. EU CRA Article 14 early-warning work stays next: KEV is a signal, not automatic product exploitation.

### Next 3 items

1. CRA Article 14 early-warning packer. Obligations are in force since 2026-09-11. Treat KEV as a signal. Do not treat severity or KEV as product exploitation.
2. Standing: mount the full SCF 2026.2 catalog from `/workspace/scf-catalog` when that tree is available. Keep the pin at 2026.2. Do not invent control IDs. Do not treat live HackIDLE / GRCEngClub APIs as 2026.2. Open PR #5 still holds the offline slice.
3. Add a collector that ingests S3 access logs and CloudTrail data-event files as observations, then seals findings. Keep observation vs finding separation. Optional later: MFA Delete, VPC endpoints, explicit bucket Deny for `s3:BypassGovernanceRetention`.

### Blockers

- Greptile review credits were exhausted on PR #4 / PR #5. Human review still required.
- No production AWS apply in this cycle. `terraform validate` is local only.
- Open PR #4 (`cursor/evidence-lake-architecture-opa-14c3`) is superseded for Conftest; do not force-push that branch.
- Open PR #5 (SCF 2026.2 pin) is still draft. This cycle does not widen it.
- `/workspace/scf-catalog` is not mounted.
- Repo stays private. No secrets.

## 2026-09-17 — Cycle 3

PR: https://github.com/kfcain/beacon/pull/7

### Why

Cycle 2 PR #6 merged to `main` (fail-closed Conftest lake policy, evidence-bucket S3 access logging, module-scoped CloudTrail data events). Cycle 2 next-item #1 is CRA Article 14 early-warning packing. Reporting obligations have been in force since 2026-09-11. This cycle adds a drop-in packer (`cra.art14.early_warning`) that ingests KEV as an optional signal, records product/component identity and observation time, and seals observations separately from findings. KEV listing and severity never set `exploitation_status=confirmed` or a notification duty. Those fields stay `undetermined` / `not_evaluated` unless a human or separate policy input sets them. Live KEV fetch is opt-in HTTPS; a live failure is `live_failed` and is never rewritten as a fixture. The witness chain still fails closed. This is evidence packing, not legal advice, and not ENISA filing.

### Next 3 items

1. Standing: mount the full SCF 2026.2 catalog from `/workspace/scf-catalog` when that tree is available. Keep the pin at 2026.2. Do not invent control IDs. Do not treat live HackIDLE / GRCEngClub APIs as 2026.2. Open draft PR #5 still holds the offline slice.
2. Add a collector that ingests S3 access logs and CloudTrail data-event files as observations, then seals findings. Keep observation vs finding separation.
3. Optional later lake hardening: MFA Delete, VPC endpoints, explicit bucket Deny for `s3:BypassGovernanceRetention`.

### Blockers

- Open PR #5 (`cursor/scf-2026-2-pin-e292`) is still draft. This cycle does not widen, rebase-force, or close it.
- Open PR #4 (`cursor/evidence-lake-architecture-opa-14c3`) is superseded for Conftest. Leave that branch untouched.
- Greptile review credits may be exhausted. Human review still required.
- No production AWS apply in this cycle.
- `/workspace/scf-catalog` is not mounted.
- Repo stays private. No secrets.

## 2026-09-17 — Cycle 4

PR: https://github.com/kfcain/beacon/pull/7

### What

PR #7 hardening — loopback alias block, KEV schema gate, relative fixture URI resolve.

### Why

Codex P2 review on the CRA Art 14 packer. Alternate numeric hosts such as `127.1`, `2130706433`, and `0177.0.0.1` bypassed `ipaddress` and could resolve to loopback. Object-shaped errors such as `{"error":"unavailable"}` sealed as live success with empty matches. Relative fixture paths crashed in `Path.as_uri()`. Live failures stay `mode=live_failed` / `ok=false` and are not rewritten as a fixture. The witness chain still fails closed (`E_NO_CHECKPOINT`).

### Next 3 items

1. Standing: SCF 2026.2 catalog alignment. Keep the pin at 2026.2. Open draft PR #5 still holds the offline slice. Do not invent control IDs.
2. Add a collector that ingests S3 access logs and CloudTrail data-event files as observations, then seals findings.
3. Optional later lake hardening: MFA Delete, VPC endpoints, explicit bucket Deny for `s3:BypassGovernanceRetention`.

### Blockers

- Open PR #5 (`cursor/scf-2026-2-pin-e292`) is still draft and dirty. This cycle does not widen, rebase-force, or close it.
- Open PR #4 (`cursor/evidence-lake-architecture-opa-14c3`) is superseded for Conftest. Leave that branch untouched.
- No production AWS apply in this cycle.
- Repo stays private. No secrets.

## 2026-09-18 — Cycle 5

PR: https://github.com/kfcain/beacon/pull/8

### Why

PR #5 vendors the 2026.2 control slice and seal-time `scf_binding`. It does not ship a standing catalog freshness collector.
PR #6 already added lake access logging / CloudTrail for the evidence bucket.
This cycle adds builtin plugin `scf.catalog.offline`. The plugin verifies a slim offline SCF **2026.2** pin (summary, families, index-meta, workbook SHA-256 `9e0a4df4993726c95e636f04b3028d8b5edeba2bda45d16ed6722b13540e6835`). It fails closed on version, missing files, SHA-256, or count mismatch. It does not vendor `controls.json`. It does not treat live HackIDLE as the pin. Sealed evidence stores `catalog_pin` plus `scf_binding` with `provenance: scf-catalog` and documented drop-in id `GOV-01`. The witness chain still fails closed (`E_NO_CHECKPOINT`).

### Next 3 items

1. Merge open PR #7 (CRA Article 14 early-warning packer). Manufacturer reporting obligations are in force. Lake CloudTrail / access-log raw material already landed in #6.
2. Merge draft PR #5 (SCF 2026.2 control slice + seal-time `scf_binding`) after this catalog collector. Do not invent overlay maps.
3. When `/workspace/scf-catalog` is mounted, point `BEACON_SCF_CATALOG_PATH` at that tree and refresh file hashes. Do not vendor the full 15 MB `controls.json`. Do not invent SCF IDs.

### Blockers

- `/workspace/scf-catalog` is not mounted on this host.
- Draft PR #5 is still open. Engine `SCF_VERSION` on `main` stays 2026.1.1 until that PR merges. This collector independently proves the 2026.2 catalog pin.
- Open PR #7 should merge next. This cycle does not rebase it.
- Greptile review credits were exhausted earlier. Human review still required.
- Repo stays private. No secrets. No production AWS apply.

## 2026-09-21 — Cycle 6

PR: https://github.com/kfcain/beacon/pull/8

### Why

PR #8 was mergeable. Codex P1 (workbook SHA + complete `file_sha256`) and P2 (GOV-01 target bind) were already on HEAD. GitHub had no pytest workflow; CodeRabbit was the only check and it passed (rate-limited). This cycle stays on the same branch. It re-verifies the slim SCF **2026.2** pin against attached catalog truth (`summary`, `families`, 249 crosswalk framework ids). Counts still match: 1534 controls, 34 families, 249 mapped frameworks, 316 ERLs, 5956 AOs. `summary.json` now hashes the 249 `framework_id` values from that truth. Vendored file SHA-256 values are compiled into `catalog_pin.py` so PIN.json cannot rewrite the in-repo pin. The verifier always rejects `usa-federal-gsa-fedramp-20x-ksi` and requires the four pillar framework ids. It does not vendor `controls.json`, display names, hop maps, or the `.xlsx` workbook. LIMITS.md now states the air-gap path: JSON pin only; workbook optional; engine offline slice remains IAC-01 and CRY-05. The witness chain still fails closed (`E_NO_CHECKPOINT`). Drop-in target remains `GOV-01`. No new SCF control ids.

### Next 3 items

1. Merge open PR #7 (CRA Article 14 early-warning packer). Manufacturer 24h reporting is already in force.
2. After #8 merges: add a collector that seals S3 access logs and CloudTrail data-event files as lake evidence. Keep observation vs finding separation.
3. Merge draft PR #5 (SCF 2026.2 control slice + seal-time `scf_binding`) after this catalog collector. Do not invent overlay maps. Optional later: add GitHub Actions pytest so PR checks are more than CodeRabbit.

### Blockers

- `/workspace/scf-catalog` is not mounted. Cycle 6 used attached catalog JSON (summary/families/crosswalks), not the official `.xlsx` bytes, to refresh hashes.
- Draft PR #5 is still open. Engine `SCF_VERSION` on `main` stays 2026.1.1 until that PR merges.
- Open PR #7 should merge next. This cycle does not rebase it.
- This repository has no GitHub Actions pytest workflow. Human review still required.
- Repo stays private. No secrets. No production AWS apply.

## 2026-09-21 — Cycle 7

PR: https://github.com/kfcain/beacon/pull/9

### Why

PR #8 (offline SCF 2026.2 catalog) is mergeable. CodeRabbit is green. It waits on a human merge.
PR #7 (CRA Article 14 early-warning packer) is mergeable. CodeRabbit is green. Host, catalog, and fixture checks are already on that branch. It waits on a human merge.
PR #5 stays a conflicting draft. This cycle does not rebase it.
The next gap on main is the logging bucket. Terraform already writes S3 access logs and CloudTrail data events there. Those files were raw observations. No collector sealed them.

`aws.lake.logs` reads `s3-access-logs/` and `cloudtrail/` from `BEACON_LOGS_BUCKET`.
It seals a bounded extract and the object SHA-256 as an observation, then the witness record as a finding.
Raw AWS objects stay in the logging bucket.
A live read with no bucket, no objects, a bad log, or an S3 error stays `live_failed`.
The witness chain still fails closed (`E_NO_CHECKPOINT`).
The seal target is IAC-01 only. That is the offline control this repo already uses for AWS CloudTrail evidence.
A different target is refused and is not sealed as IAC-01.
The finding does not assert that IAC-01, FedRAMP High, NIST 800-53, CMMC L2, or SOC 2 TSC is met.
`BeaconWriter` may list and get only those two prefixes. It must not put or delete log objects.
The auditor still has no access to the logging bucket.

### Next 3 items

1. Human merge of PR #8, then PR #7. Do not redo those branches while they stay green.
2. Standing: keep SCF 2026.2 on the offline catalog pin. Do not use live HackIDLE as the pin. Do not invent control ids. PR #5 stays draft until that pin is the base.
3. Optional lake follow-ups: MFA Delete, VPC endpoints, and an explicit bucket Deny for `s3:BypassGovernanceRetention`.

### Blockers

- No production AWS apply in this cycle.
- `/workspace/scf-catalog` is not mounted. The MON family exists on the PR #8 pin. This cycle does not invent an MON control id.
- Repo stays private. No secrets.

## 2026-09-22 — Cycle 8

PR: https://github.com/kfcain/beacon/pull/9

### Why

PR #8 (offline SCF 2026.2 catalog) is on `main`.
PR #7 (CRA Article 14 early-warning packer) merged to `main`.
This cycle merges `main` into PR #9.
Conflicts were in `beacon/plugins/loader.py`, `docs/IMPROVEMENT_LOG.md`, and `docs/PLUGINS.md`.
Both builtins stay registered: `scf.catalog.offline` and `aws.lake.logs`.

ListObjectsV2 returns keys in ascending order.
CloudTrail digest keys (`CloudTrail-Digest/`) sort before data-event keys (`CloudTrail/`).
The old scan cap counted digest keys, so a live read could stop with no data-event key.
The same ascending order sealed the oldest logs when the list was truncated.
The collector now skips the digest prefix and seals the newest matching keys.
The seal target stays IAC-01.
The finding still does not assert that the control is met.
The witness chain still fails closed (`E_NO_CHECKPOINT`).

### Next 3 items

1. Human review and merge of PR #9. Do not merge it in this cycle.
2. Standing: keep SCF 2026.2 on the offline catalog pin. PR #5 stays draft.
3. Optional lake follow-ups: MFA Delete, VPC endpoints, and an explicit bucket Deny for `s3:BypassGovernanceRetention`.

### Blockers

- No production AWS apply in this cycle.
- PR #9 waits on human review. This cycle does not merge it.
- Repo stays private. No secrets.

## 2026-09-24 — Cycle 9

### Why

Official SCF 2026.3 (published 2026-09-21) replaces the slim offline pin.
Workbook SHA-256 is `5a89bf2d3c106a9a87d4b6e3d62dd3e147d0e960d4c07473045a10aa8a7df697`.
Parser counts: 1591 controls, 34 families, 270 mapped crosswalks, 6446 assessment objectives, 422 evidence requests, 1397 compensating controls. QTS stays at 31 controls.
The same control id often names a different control. Seeds follow workbook Legacy SCF #: IAC-01 (IAM) to IAC-02, CRY-05 (data at rest) to CRY-07, GOV-01 (SCRP) to GOV-02.
2026.3 IAC-01, CRY-05, and GOV-01 are different controls. Seals use the remapped ids.
The collector still fails closed on version, SHA-256, and count mismatch. It does not vendor `controls.json` or the workbook.

### Next 3 items

1. Human review of the 2026.3 pin. Do not treat live HackIDLE as the pin.
2. Do not invent control ids. Keep using Legacy SCF # when a seed id moves.
3. Optional lake follow-ups stay out of this pin bump.

### Blockers

- Assessment-scope design is out of scope.
- Live HackIDLE remains 2026.1.x.
- Repo stays private. No secrets.

## 2026-09-24 — Cycle 10

PR: https://github.com/kfcain/beacon/pull/11

### Why

PR #10 merged to main. The slim SCF pin is 2026.3.
Workbook SHA-256 is `5a89bf2d3c106a9a87d4b6e3d62dd3e147d0e960d4c07473045a10aa8a7df697` (1591 controls, 34 families, 270 crosswalks).
This cycle hardens open PR #11 for that pin.
It merges main into the assessment-scope branch.
Example and test control ids follow the 2026.3 Legacy SCF # map: IAC-01 (IAM) to IAC-02, CRY-05 (Encrypting Data At Rest) to CRY-07, GOV-01 (SCRP) to GOV-02.
`catalog_pin_version` examples are `2026.3`.
The lake collector on main seals IAC-02.
The ADR no longer says the pin bump is pending.
This pull request does not re-vendor `controls.json` and does not invent control ids.
Scope stays a design and a schema stub. There is no collect wiring, no live Jev client, and no `Record.v` bump.
Codex P1 and P2 on the claim gate are fixed here. `decide_claim` requires the sealed receipt id. Coverage rejects a boolean and a string. Scope collections are tuples, so a caller cannot append after the hash.

### Next 3 items

1. Human review and merge of PR #11.
2. After that merge, add the phase-1 scope CLI (`beacon scope init`, `show`, and `hash`).
3. Do not revive draft PR #5 (obsolete 2026.2 pin) or superseded PR #4. Do not start lake MFA, VPC, or BypassGovernanceRetention work.

### Blockers

- PR #11 waits on human review.
- No production AWS apply in this cycle.
- Repo stays private. No secrets.

## 2026-09-24 — Cycle 11

### Why

PR #11 merged to main (merge commit `4de2c37340b7b00807571a34fdfab2e363e00e55`).
The assessment scope ADR and the schema stub are on main.
PR #12 merged to main (merge commit `91bbb6539948b4dfb677ba5a473ce78c3ae1f4c6`).
The offline SCF summary is a 2026.3 seed index. That pull request does not change the catalog pin.
PR #13 merged to main (merge commit `3b3e6acdc1a3f90cdfff94245fe020b015ea5124`).
The Beacon TUI shows a first-run walkthrough.
`decide_claim` stays fail-closed. `DEFAULT_SCORE_MIN` stays `1.0`.
This cycle adds phase 1 only: `beacon scope init`, `beacon scope show`, and `beacon scope hash`.
`init` writes `.beacon/scopes/{scope_id}.json` as schema version 1.
The catalog pin label on that file is `2026.3`. The command does not read or write `PIN.json`.
The starter framework id is the pillar id `general-nist-800-53-r5-2`.
The starter boundary system is `workspace`. The file has no credential.
An unsafe id, a missing file, a second init, or a scope id that does not match the file fails closed.
`hash` prints `ScopeDocument.content_sha256()`.
This cycle does not bind collect or check, does not build candidates, does not call Jev, and does not add lake index fields.
Conftest on current OPA rejects the field name `default` as a keyword. Policy rules now read `item.values["default"]`. The rule text is the same.
Draft PR #5 and draft PR #2 stay untouched.

### Next 3 items

1. Human review of the phase-1 scope CLI.
2. After that merge, phase 2 can bind `scope_id` and `scope_sha256` on collect and check. A missing file still fails closed.
3. Do not revive draft PR #5 (obsolete 2026.2 pin) or superseded drafts. Do not start lake index fields or a Jev network client in the bind phase.

### Blockers

- No production AWS apply in this cycle.
- Repo stays private. No secrets.

## 2026-09-24 — Cycle 12

### Why

Phase 1 scope CLI is on main (PR #14).
This cycle locks the assurance stack Kyle asked to proceed through.
The design is `docs/architecture/beacon-assurance-stack.md`.
It sequences five slices after the assessment-scope phases: workshop, tags, and framework context (phase 7); then existing phase 2 scope bind; then the ledger and KSI counters (phase 8); pack compilers (phase 9); the git policy bridge (phase 10); and trust center, SCN, and the security inbox (phase 11).
Class C needs at least 2 automated methods per KSI. That figure is CR26 guide rule FRC-CSX-VVK.
Class D needs at least 4. The attached guide is Class C only. This cycle does not invent a Class D rule id.
The code sketches are a version 2 scope draft, a tag registry, `ksi_method_report`, and `compile_pack_draft`.
`ScopeDocument` version 1 still round-trips. `load_scope` rejects a version 2 file.
A method count is a package gap. `decide_claim` still gates claim words.
This cycle does not fetch a FedRAMP schema, does not change `beacon push`, and does not send mail.
Draft PR #5 and draft PR #2 stay untouched.

### Next 3 items

1. Human review of the assurance-stack ADR.
2. After that review, phase 2 can bind `scope_id` and `scope_sha256` on collect and check. Phase 7 file writes for `.beacon/scopes/drafts/` stay behind that bind.
3. Do not revive draft PR #5 or draft PR #2. Do not invent SCF control ids or a 20x crosswalk id.

### Blockers

- No production AWS apply in this cycle.
- The 46 KSI ids are not in this repository. The ledger does not invent them.
- Repo stays private. No secrets.
