# AWS evidence lake

Beacon can dual-write sealed evidence, witness-chain records, checkpoints, and packs to an S3 evidence lake. A DynamoDB table indexes the objects. Local seal still runs first. The witness chain still fails closed with `E_NO_CHECKPOINT` when coverage is missing.

Remote storage does **not** prove that evidence content is true. See [LIMITS.md](../LIMITS.md). Hash mismatch checks detect altered artifacts. They do not prove the original observation is true.

## Regions

Supported deploy targets:

- `us-east-1` — commercial AWS
- `us-gov-west-1` — AWS GovCloud

Terraform takes `var.aws_region`. Do not hard-code the region. GovCloud uses partition `aws-us-gov` through `data.aws_partition.current`.

## Object keys

Optional prefix: `BEACON_S3_PREFIX` (no leading or trailing slash). Raw observations stay separate from derived findings.

```
{prefix/}{tenant_id}/{workspace_id}/observations/{uuid}.json
{prefix/}{tenant_id}/{workspace_id}/evidence/{uuid}.json
{prefix/}{tenant_id}/{workspace_id}/chain/records.jsonl
{prefix/}{tenant_id}/{workspace_id}/chain/checkpoints.jsonl
{prefix/}{tenant_id}/{workspace_id}/exports/packs/{pack_type}/{version}/beacon-pack.json
{prefix/}{tenant_id}/{workspace_id}/exports/packs/{pack_type}/{version}/report.md
{prefix/}{tenant_id}/{workspace_id}/exports/activity-log/{version}.jsonl
{prefix/}{tenant_id}/{workspace_id}/imports/{id}.json
{prefix/}{tenant_id}/{workspace_id}/public/trust-center/   # allowlisted exports only
```

| Local path | Writer | Remote object | `kind` metadata |
| --- | --- | --- | --- |
| `evidence/{uuid}.json` | `seal_payload` | `.../observations/{uuid}.json` | `observation` |
| sealed Record JSON | `seal_payload` | `.../evidence/{uuid}.json` | `finding` |
| `chain/records.jsonl` | `seal_payload` | `.../chain/records.jsonl` | `records` |
| `chain/checkpoints.jsonl` | `create_checkpoint` | `.../chain/checkpoints.jsonl` | `checkpoints` |
| `export/beacon-pack-{stamp}.json` | `beacon push` | `.../exports/packs/{pack_type}/{stamp}/beacon-pack.json` | `pack` |
| `export/beacon-pack-{stamp}.md` | `beacon push` | `.../exports/packs/{pack_type}/{stamp}/report.md` | `report` |
| (derived) | `beacon push` | `.../exports/activity-log/{stamp}.jsonl` | `report` (`report_format=activity-log`) |
| import bytes | review pending | `.../imports/{id}.json` | `import` (`verified=false`) |

`pack_type` is one of:

- `bundle` — evidence bundle (default)
- `ongoing-certification-report` — Ongoing Certification Report
- `secure-configuration-guide` — Secure Configuration Guide
- `security-decision-record` — Security Decision Record

Draft named packs store version metadata (`pack_type`, `pack_version`, `draft`). Set `BEACON_PACK_TYPE` to select the named document type.

Beacon does **not** upload `config.json`, `keys/` (`*.pem`, `*.pub`, `tsa.crt`), or `cache/scf/`. Packs include public keys as JSON fields only. Never upload private keys.

Restricted workspace prefixes hold raw observations and findings. The allowlisted `public/trust-center/` prefix never holds raw observations by default. Set `BEACON_TRUST_CENTER_EXPORT=1` to copy pack and report objects only (JSON, Markdown, activity-log). The writer refuses observation, finding, import, and chain objects on that prefix. The bucket policy also denies those classes there.

Object metadata (when present): `kind`, `sha256`, `input_sha256`, `audit_sha256`, `audit_seq`, `prev_sha256`, `scf_targets`, `plugin`, `sealed_at`, `expires_at`, `record_id`, `verified`, `report_format`, `pack_type`, `pack_version`, `draft`.

Object tags: `beacon-class` (`observation` | `finding` | `chain-record` | `checkpoint` | `pack` | `report` | `import`), `beacon-kind`, `beacon-tenant`, `beacon-workspace`, `beacon-verified`. Lifecycle moves `observation`, `finding`, `pack`, and `report` to STANDARD_IA at 90 days and GLACIER at 365 days. `chain/records.jsonl` and `chain/checkpoints.jsonl` stay in STANDARD.

Export `Content-Type`:

- evidence bundle / JSON report: `application/json` (`report_format=json`; `pack_type` names the document)
- Markdown report: `text/markdown; charset=utf-8` (`report_format=markdown`)
- activity-log: `application/x-ndjson` (`report_format=activity-log`)

## Evidence vault hashes

Each sealed row stores:

- `sha256` / `input_sha256` — SHA-256 of the raw observation
- `audit_sha256` / `finding_sha256` / `record_sha256` — SHA-256 of the linked finding (canonical Record)
- `prev_sha256` — previous audit hash
- `audit_seq` — audit sequence (`Record.seq`)

`beacon pull` fails closed on altered artifacts (hash mismatch, input hash mismatch, linked audit hash mismatch, finding mismatch, audit sequence mismatch, invalid signatures, and missing TSA material). Pull verifies the staged chain before it installs files. Private keys are not required for that check. The local TSA certificate (`tsa.crt`) is required when checkpoints exist.

## Freshness

Key checks and infrastructure observations expire 24 hours after `sealed_at`. DynamoDB stores `sealed_at` and `expires_at` on `EVIDENCE#` and `FRESH#` items. The `freshness` GSI uses `pk` + `expires_at` so expiry queries work. `beacon freshness` also returns `expires_at` and `expired` from the local chain.

## Encryption (S3 SSE-KMS)

S3 server-side encryption with a customer managed KMS key is mandatory.

- Bucket default encryption is SSE-KMS (`aws:kms`) with a bucket key.
- Every `PutObject` sets `ServerSideEncryption=aws:kms` and `SSEKMSKeyId` (`BEACON_KMS_KEY_ARN`, or `alias/beacon-evidence` when a bucket is set).
- The bucket policy denies `PutObject` that is not SSE-KMS.

### KMS key governance

- Create one customer CMK per lake (`alias/beacon-evidence`). Enable automatic annual rotation (`enable_key_rotation = true`).
- The key policy grants account root key administration so IAM can delegate use. It allows the S3 and DynamoDB service principals to encrypt and decrypt in the same account.
- **BeaconWriter** may `Encrypt`, `Decrypt`, `GenerateDataKey`, and `DescribeKey`. **BeaconAuditor** may `Decrypt` and `DescribeKey` only.
- Separate key administrators (IAM / key policy) from evidence prefix writers. Do not put key-admin actions on BeaconWriter.
- Prefer CMK ARN in `BEACON_KMS_KEY_ARN` after apply. Aliases are a fallback.
- GovCloud uses the same governance in `us-gov-west-1` with partition `aws-us-gov`.

## Object Lock

Default mode is **GOVERNANCE** with configurable retain days (`BEACON_OBJECT_LOCK_DAYS`, Terraform `object_lock_days`, default 365). The product does not publish a fixed long-retention period.

**COMPLIANCE** mode is opt-in after you fix retain days. Set `object_lock_mode = "COMPLIANCE"` / `BEACON_OBJECT_LOCK_MODE=COMPLIANCE` only when legal hold needs are stable. BeaconWriter has no `s3:BypassGovernanceRetention`.

## Imports

Imports are unverified until a review seal. Stored imports use `kind=import` and `verified=false`. A local `seal_payload` dual-write sets `verified=true` on the observation and finding.

## DynamoDB index

Table name: `BEACON_DDB_TABLE` (default `beacon-artifact-index`). Encryption uses the same CMK.

| Attribute | Value |
| --- | --- |
| PK | `{tenant_id}#{workspace_id}` |
| SK | `EVIDENCE#{evidence_id}` / `CP#{checkpoint_id}` / `FRESH#{plugin}` / `IMPORT#{import_id}` |
| GSI `freshness` | PK `pk`, SK `expires_at` |
| fields | `s3_uri`, `observation_s3_uri`, `finding_s3_uri`, `sha256`, `input_sha256`, `audit_sha256`, `finding_sha256`, `prev_sha256`, `audit_seq`, `sealed_at`, `expires_at`, `verified`, `control_ids`, `merkle_root`, `pack_id` |

## Environment

| Variable | Role |
| --- | --- |
| `BEACON_S3_BUCKET` | Bucket name. Empty disables remote write. |
| `BEACON_S3_PREFIX` | Optional key prefix. |
| `BEACON_KMS_KEY_ARN` | Customer CMK ARN. When a bucket is set and this is empty, Beacon uses `alias/beacon-evidence`. SSE-KMS is mandatory. |
| `BEACON_DDB_TABLE` | Index table. Defaults to `beacon-artifact-index` when a bucket is set. |
| `BEACON_OBJECT_LOCK_MODE` | `GOVERNANCE` (default) or `COMPLIANCE` (opt-in). |
| `BEACON_OBJECT_LOCK_DAYS` | Retain days on PutObject. Default 365. `0` omits lock headers. |
| `BEACON_TENANT_ID` | Required when a bucket is set. |
| `BEACON_WORKSPACE_ID` | Required when a bucket is set. |
| `BEACON_REQUIRE_REMOTE` | If true, fail closed (`E_REMOTE`) when the remote seal is missing. |
| `BEACON_PACK_TYPE` | `bundle` (default), `ongoing-certification-report`, `secure-configuration-guide`, or `security-decision-record`. |
| `BEACON_TRUST_CENTER_EXPORT` | If true, copy pack/report exports to `public/trust-center/`. Never copies raw observations. |

Credentials use the default AWS chain (STS assumed role, instance profile, env). Do not put long-lived keys in Beacon-specific variables. Never upload `*.sec` or files under `.beacon/keys`.

## IAM

- **BeaconWriter** — `s3:PutObject`, `PutObjectRetention`, `GetObject`, `ListBucket` on `{prefix/}{tenant}/{workspace}/*` only; KMS `Encrypt`, `Decrypt`, `GenerateDataKey`; DynamoDB index write with `dynamodb:LeadingKeys` = `{tenant}#{workspace}`. No `s3:DeleteObject`. No `s3:BypassGovernanceRetention`.
- **BeaconAuditor** — the same S3 prefix and DynamoDB partition, read-only Get/List, KMS Decrypt, DynamoDB Query.

Set Terraform `tenant_id` and `workspace_id` to the bound namespace. Those values must match `BEACON_TENANT_ID` and `BEACON_WORKSPACE_ID`.

Prefer `aws sts assume-role`. See [deploy/aws](../deploy/aws/README.md).

Architecture (collectors → seal/witness → S3 + DynamoDB + KMS + IAM): [docs/architecture/beacon-evidence-lake.md](architecture/beacon-evidence-lake.md). Draw.io: [docs/architecture/beacon-evidence-lake.drawio](architecture/beacon-evidence-lake.drawio). Terraform control map: [docs/architecture/terraform-compliance.md](architecture/terraform-compliance.md).

## OPA / Conftest

Policies under `policy/terraform` check the controls that `deploy/aws` encodes (SSE-KMS, Block Public Access, BucketOwnerEnforced, Object Lock, versioning, lifecycle, writer no delete / no BypassGovernanceRetention, auditor read-only, IAM Allow wildcards, evidence bucket-policy attachment, KMS rotation, DynamoDB CMK + freshness GSI, trust-center prefix deny, S3 access logging, CloudTrail data events). They do not invent missing Terraform.

```bash
make policy
conftest verify -p policy/terraform
conftest test --combine --parser hcl2 -p policy/terraform deploy/aws/*.tf
```

Install Conftest from https://github.com/open-policy-agent/conftest/releases. Warn results list known gaps. They do not fail the default run.

## Access logs and CloudTrail data events

Terraform creates a **dedicated logging bucket** next to the evidence lake. That bucket uses the same customer CMK, Block Public Access, BucketOwnerEnforced, versioning, and TLS deny. It does **not** use Object Lock.

| AWS log | Prefix on logging bucket | Beacon class after seal |
| --- | --- | --- |
| S3 server access logs | `s3-access-logs/` | Raw **observation**. Seal to a **finding** (`beacon-class=finding`) before it is lake evidence. |
| CloudTrail S3 object-level data events (read and write) | `cloudtrail/` | Raw **observation**. Seal to a **finding** the same way. |

AWS writes those files. They are not sealed Beacon records.

Do **not**:

- Write those logs into the evidence bucket `observations/` or `evidence/` prefixes from Terraform.
- Mix raw logs with sealed findings.
- Copy raw logs to `public/trust-center/`.

`aws.lake.logs` seals them as lake evidence:

1. Read log objects from the logging bucket (`BEACON_LOGS_BUCKET`).
2. Store a bounded extract and the object SHA-256 as an **observation** (local `evidence/{uuid}.json` / remote `.../observations/{uuid}.json`, `beacon-class=observation`).
3. After `seal_payload`, dual-write the derived record as a **finding** (`.../evidence/{uuid}.json`, `beacon-class=finding`).
4. Keep the witness chain fail-closed (`E_NO_CHECKPOINT`).

```bash
beacon collect --plugin aws.lake.logs
beacon collect --plugin aws.lake.logs --live
```

`--live` fails closed when the bucket is unset, unreadable, empty, or not a valid access log / CloudTrail data-event file. The fixture is used only when live collection is not requested and `BEACON_LOGS_BUCKET` is unset. Raw AWS objects are not copied into the evidence bucket. The seal target is IAC-02. The finding does not assert that the control is met.

FedRAMP 20x asks for machine-readable and human-readable reconciled evidence from CloudTrail (and Config, Security Hub, Inspector) in a tamper-resistant lake. This logging path supplies the CloudTrail and S3 access raw material. Seal and pack remain Beacon jobs.

Variables (default **true**):

- `enable_s3_access_logging`
- `enable_cloudtrail_data_events`

The CloudTrail is module-scoped. `include_management_events` is false. It does not create an account-level management trail.

## Commands

After local seal:

- `beacon collect` / `beacon seed` — after local seal, dual-write observation + finding and `records.jsonl`; after checkpoint, dual-write `checkpoints.jsonl`.
- `beacon push` — write a local pack (public keys only) plus Markdown, then dual-write `exports/packs/...` with JSON, Markdown, and activity-log.
- `beacon sync` — upload the writer classes from the local workspace.
- `beacon pull` — download observation objects listed in the index, verify SHA-256 / input / audit hashes and the staged witness chain, then restore local `evidence/{uuid}.json` only after that check.
- `beacon freshness` — local freshness with 24-hour `expires_at`.

Offline tests and local collect still run with no AWS configuration.
