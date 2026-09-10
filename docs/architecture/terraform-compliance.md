# Terraform compliance map

This file maps each control in `deploy/aws` to a Beacon / Mock SaaS evidence-lake requirement.
The map matches the Terraform on `main` after the AWS evidence lake merge (`e6fd354`).
Rego in `policy/terraform` checks the same controls.
The Rego does not invent a control that Terraform does not implement.

## Scope

| Item | Value |
| --- | --- |
| Module | `deploy/aws` |
| Application writer | `beacon/storage/s3.py` |
| Supported regions | `us-east-1` (commercial), `us-gov-west-1` (GovCloud) |
| Object Lock default | `GOVERNANCE`, `object_lock_days = 365` |
| Roles | `BeaconWriter` (Put/Get/List, no delete), `BeaconAuditor` (read-only) |

## Control map

| Requirement | Terraform | Beacon / Mock SaaS need | Rego |
| --- | --- | --- | --- |
| SSE-KMS on the lake | `aws_s3_bucket_server_side_encryption_configuration.evidence` uses `sse_algorithm = "aws:kms"` and `kms_master_key_id = aws_kms_key.evidence.arn`. `bucket_key_enabled = true`. | Every object uses S3 SSE-KMS. The app sets `ServerSideEncryption=aws:kms` and `SSEKMSKeyId`. | Deny if default encryption is missing or is not `aws:kms` with a CMK. |
| Deny uploads that are not SSE-KMS | Bucket policy SID `DenyUnencryptedObjectUploads` denies `s3:PutObject` when `s3:x-amz-server-side-encryption` is not `aws:kms`. | Fail closed if a client omits SSE-KMS. | Deny if the SID is missing or does not require `aws:kms`. |
| Block Public Access | `aws_s3_bucket_public_access_block.evidence` sets all four flags to `true`. | The lake is not a public bucket. | Deny unless all four flags are true. |
| No public ACL | `aws_s3_bucket_ownership_controls.evidence` sets `object_ownership = "BucketOwnerEnforced"`. There is no `aws_s3_bucket_acl`. | ACLs are off. Bucket owner owns every object. | Deny if ownership is not `BucketOwnerEnforced`, or if a public ACL resource exists. |
| Versioning | `aws_s3_bucket_versioning.evidence` status `Enabled`. | Object Lock needs versioning. Pull can read object versions. | Deny if versioning is not `Enabled`. |
| Object Lock GOVERNANCE | `object_lock_enabled = true` on the bucket. `aws_s3_bucket_object_lock_configuration.evidence` uses `var.object_lock_mode` (default `GOVERNANCE`) and `var.object_lock_days` (default 365). COMPLIANCE is opt-in. | Retain sealed artifacts. The product does not publish a fixed long retain period. | Deny if Object Lock is off, or if the default mode is not GOVERNANCE / COMPLIANCE / `var.object_lock_mode`. Deny if the variable default is not GOVERNANCE. |
| Writer has no DeleteObject | Writer IAM allow list has Put/Get/List and `PutObjectRetention` only. Bucket policy SID `DenyDeleteObject` denies `s3:DeleteObject` and `s3:DeleteObjectVersion` for all principals. | Collectors cannot remove evidence. | Deny if writer allows delete, or if `DenyDeleteObject` is missing. |
| Writer has no BypassGovernanceRetention | Writer IAM does not include `s3:BypassGovernanceRetention`. The allow list is default-deny. | GOVERNANCE retain must hold for the writer role. | Deny if writer (or auditor) allows `s3:BypassGovernanceRetention`. |
| Auditor is read-only | `data.aws_iam_policy_document.auditor` allows Get/List, `kms:Decrypt`, and DynamoDB Get/Query. It does not allow Put, delete, or KMS encrypt. | Review and `beacon pull` only. | Deny if auditor allows Put/Delete/encrypt/write. |
| Prefix and partition bind | Writer and auditor S3 object ARNs use `${local.workspace_prefix}/*`. DynamoDB uses `dynamodb:LeadingKeys` = `${local.ddb_pk}` (`{tenant}#{workspace}`). | IAM matches `BEACON_TENANT_ID` / `BEACON_WORKSPACE_ID`. | Deny if writer object ARNs are not prefix-scoped, or if LeadingKeys is missing. |
| KMS rotation | `aws_kms_key.evidence` sets `enable_key_rotation = true`. Alias default `alias/beacon-evidence`. | Annual CMK rotation. Writer may encrypt. Auditor may decrypt only. | Deny if `enable_key_rotation` is not true. |
| DynamoDB encryption | `aws_dynamodb_table.index` `server_side_encryption` enabled with `kms_key_arn = aws_kms_key.evidence.arn`. | Index hashes and pointers use the same CMK. | Deny if table SSE is off or has no CMK. |
| Freshness GSI | GSI `freshness` on `pk` + `expires_at`. | Key checks and observations expire 24 hours after `sealed_at`. `beacon freshness` queries expiry. | Deny if GSI `freshness` is missing or uses other keys. |
| Lifecycle IA / Glacier | Lifecycle rules for `local.cold_classes` go to `STANDARD_IA` at 90 days and `GLACIER` at 365 days. | Cold storage for observation, finding, pack, and report classes. Chain JSONL stays in STANDARD. | Deny if those transitions are missing. |
| Trust-center prefix deny | SID `DenyRawInTrustCenterByClass` denies PutObject when `s3:RequestObjectTag/beacon-class` is observation, finding, chain-record, checkpoint, or import under `*/public/trust-center/*`. SID `DenyObservationsUnderTrustCenterPrefix` denies observation key paths. | Trust center may hold pack/report copies only. App `assert_key_kind_allowed` also refuses raw kinds. | Deny if those SIDs or class tags are missing. |
| TLS in transit | SID `DenyInsecureTransport` denies `s3:*` when `aws:SecureTransport` is false. | HTTPS only. | Covered by required SID set. |
| Regions | Provider `region = var.aws_region`. Default `us-east-1`. Docs name `us-gov-west-1` for GovCloud. Partition comes from `data.aws_partition.current`. | Commercial and GovCloud deploy targets. Do not hard-code the region on resources. | Deny if the provider region is hard-coded to a value outside the allow list, or if the variable default is not an allowed region. |
| Point-in-time recovery | DynamoDB `point_in_time_recovery { enabled = true }`. | Extra index recovery. Not a Mock SaaS must-have. | Not a deny rule. Present in Terraform. |

## Data path that the controls protect

1. Inspectors collect on the Beacon host.
2. `seal_payload` writes the local chain first.
3. The process assumes `BeaconWriter` with STS.
4. `ArtifactLake._put_bytes` calls `PutObject` with SSE-KMS, object tags, and Object Lock headers.
5. The same CMK encrypts DynamoDB index items (`EVIDENCE#`, `CP#`, `FRESH#`, `IMPORT#`).
6. `BeaconAuditor` reads the same prefix and partition for `beacon pull`. Pull verifies hashes before it installs files.

See [beacon-evidence-lake.md](beacon-evidence-lake.md) and [STORAGE.md](../STORAGE.md).

## Gaps / recommended Rego

These items are **not** encoded as Terraform resources today. Do not treat them as implemented.

| Gap | What Terraform does today | Recommended follow-up |
| --- | --- | --- |
| Region allow list at apply time | `var.aws_region` has no `validation` block. Default is `us-east-1`. An operator can still pass any region. | Add `validation { condition = contains(["us-east-1", "us-gov-west-1"], var.aws_region) }`. Plan-time Rego can deny other resolved regions when you pass `terraform show -json`. |
| Explicit Deny `s3:BypassGovernanceRetention` | The action is absent from the writer allow list (default deny). The bucket policy does not deny the action. | Optional bucket-policy Deny for `s3:BypassGovernanceRetention`. Current Rego already fails if the writer allow list includes it. |
| Lifecycle class `evidence` | `locals.cold_classes` includes `evidence`. The writer tags derived records as `beacon-class=finding`. | Remove `evidence` from `cold_classes`, or tag findings as `evidence` if that is the intended class. Conftest emits a **warn** only. |
| Deny missing KMS key id on PutObject | `DenyUnencryptedObjectUploads` checks the SSE algorithm header only. | Optional extra Deny when `s3:x-amz-server-side-encryption-aws-kms-key-id` is empty or is not the lake CMK. |
| S3 access logging / CloudTrail data events | Not in `deploy/aws`. | Add logging if an audit program requires it. |
| MFA Delete | Not set. | Optional after you fix account MFA and versioning governance. |
| Private-only access (VPC endpoint) | The lake is a regional API. There is no VPC in this module. | Add gateway endpoints only if the collector must stay off the public S3 endpoint. |
| COMPLIANCE mode guard | Terraform allows COMPLIANCE through the variable after you fix retain days. | Keep COMPLIANCE opt-in. Do not force it in Rego. |

## How to run the checks

```bash
make policy
# same commands:
conftest verify -p policy/terraform
conftest test --combine --parser hcl2 -p policy/terraform deploy/aws/*.tf
```

`make policy` must see zero **deny** results on the current module.
Warn results document gaps. They do not fail the default Conftest run.
