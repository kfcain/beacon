# AWS evidence lake

Beacon can dual-write sealed evidence, witness-chain records, checkpoints, and packs to an S3 evidence lake. A DynamoDB table indexes the objects. Local seal still runs first. The witness chain still fails closed with `E_NO_CHECKPOINT` when coverage is missing.

Remote storage does **not** prove that evidence content is true. See [LIMITS.md](../LIMITS.md).

## Object keys

Optional prefix: `BEACON_S3_PREFIX` (no leading or trailing slash).

```
{prefix/}{tenant_id}/{workspace_id}/evidence/{uuid}.json
{prefix/}{tenant_id}/{workspace_id}/chain/records.jsonl
{prefix/}{tenant_id}/{workspace_id}/chain/checkpoints.jsonl
{prefix/}{tenant_id}/{workspace_id}/export/beacon-pack-{YYYYMMDDTHHMMSSZ}.json
```

These keys match the local `.beacon/` writers on main:

| Local path | Writer | Remote object |
| --- | --- | --- |
| `evidence/{uuid}.json` | `seal_payload` | `.../evidence/{uuid}.json` |
| `chain/records.jsonl` | `seal_payload` | `.../chain/records.jsonl` |
| `chain/checkpoints.jsonl` | `create_checkpoint` | `.../chain/checkpoints.jsonl` |
| `export/beacon-pack-{stamp}.json` | `beacon push` | `.../export/beacon-pack-{stamp}.json` |

Beacon does **not** upload `config.json`, `keys/` (`*.pem`, `*.pub`, `tsa.crt`), or `cache/scf/`. Packs include public keys as JSON fields only.

Object metadata (when present): `sha256`, `scf_targets`, `plugin`, `sealed_at`, `record_id`.

Object tags: `beacon-class` (`evidence` | `chain-record` | `checkpoint` | `pack`), `beacon-tenant`, `beacon-workspace`. Lifecycle moves `evidence` and `pack` to STANDARD_IA at 90 days and GLACIER at 365 days. `chain/records.jsonl` and `chain/checkpoints.jsonl` stay in STANDARD.

## DynamoDB index

Table name: `BEACON_DDB_TABLE` (default `beacon-artifact-index`).

| Attribute | Value |
| --- | --- |
| PK | `{tenant_id}#{workspace_id}` |
| SK | `EVIDENCE#{evidence_id}` / `CP#{checkpoint_id}` / `FRESH#{plugin}` |
| fields | `s3_uri`, `sha256`, `sealed_at`, `control_ids`, `merkle_root`, `pack_id` |

## Environment

| Variable | Role |
| --- | --- |
| `BEACON_S3_BUCKET` | Bucket name. Empty disables remote write. |
| `BEACON_S3_PREFIX` | Optional key prefix. |
| `BEACON_KMS_KEY_ARN` | Customer CMK ARN. When a bucket is set and this is empty, Beacon uses `alias/beacon-evidence`. |
| `BEACON_DDB_TABLE` | Index table. Defaults to `beacon-artifact-index` when a bucket is set. |
| `BEACON_OBJECT_LOCK_MODE` | `GOVERNANCE` (default) or `COMPLIANCE`. |
| `BEACON_OBJECT_LOCK_DAYS` | Retain days on PutObject. Default 365. `0` omits lock headers. |
| `BEACON_TENANT_ID` | Required when a bucket is set. |
| `BEACON_WORKSPACE_ID` | Required when a bucket is set. |
| `BEACON_REQUIRE_REMOTE` | If true, fail closed (`E_REMOTE`) when the remote seal is missing. |

Credentials use the default AWS chain (STS assumed role, instance profile, env). Do not put long-lived keys in Beacon-specific variables. Never upload `*.sec` or files under `.beacon/keys`.

## IAM

- **BeaconWriter** — `s3:PutObject`, `GetObject`, `ListBucket`; KMS `Encrypt`, `Decrypt`, `GenerateDataKey`; DynamoDB index write. No `s3:DeleteObject`. No `s3:BypassGovernanceRetention`.
- **BeaconAuditor** — read-only Get/List, KMS Decrypt, DynamoDB Query.

Prefer `aws sts assume-role`. See [deploy/aws](../deploy/aws/README.md).

## Commands

After local seal:

- `beacon collect` / `beacon seed` — after local seal, dual-write evidence and `records.jsonl`; after checkpoint, dual-write `checkpoints.jsonl`.
- `beacon push` — write a local pack (public keys only), then dual-write `export/beacon-pack-{stamp}.json`.
- `beacon sync` — upload the three writer classes from the local workspace.
- `beacon pull` — download objects listed in the index and verify SHA-256 against the index.

Offline tests and local collect still run with no AWS configuration.
