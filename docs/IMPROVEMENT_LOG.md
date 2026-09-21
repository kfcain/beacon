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

## 2026-09-21 — Cycle 7

PR: pending

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
