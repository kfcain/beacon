# Beacon AWS evidence lake

Terraform creates the S3 evidence lake, KMS CMK (S3 SSE-KMS), DynamoDB index, and IAM roles.

Supported deploy targets: **us-east-1** (commercial) and **us-gov-west-1** (GovCloud). Set `aws_region`. Do not hard-code the region.

BeaconWriter has Put/Get/List and PutObjectRetention on `{prefix/}{tenant_id}/{workspace_id}/*` only, plus KMS encrypt/decrypt/GenerateDataKey. DynamoDB writes use `dynamodb:LeadingKeys` for `{tenant}#{workspace}`. It does not have DeleteObject. BeaconAuditor is the same prefix, read-only. Prefer STS assume-role. Do not upload private keys (`*.sec`, `.beacon/keys`).

Set `tenant_id` and `workspace_id` in Terraform. Those values bind the IAM roles. They must match `BEACON_TENANT_ID` and `BEACON_WORKSPACE_ID`.

Object Lock default is GOVERNANCE with configurable days. COMPLIANCE mode is opt-in after retain days are fixed.

The bucket policy denies raw `observation` objects under `public/trust-center/`.

## Apply

```bash
cd deploy/aws
cp terraform.tfvars.example terraform.tfvars
# set bucket_name, aws_region, trusted_principal_arns, tenant_id, workspace_id
terraform init
terraform apply
terraform output -raw beacon_env
```

Set tenant and workspace ids, then assume BeaconWriter:

```bash
eval "$(terraform output -raw beacon_env)"
export BEACON_TENANT_ID=acme
export BEACON_WORKSPACE_ID=prod
aws sts assume-role --role-arn "$(terraform output -raw writer_role_arn)" --role-session-name beacon-writer
```

Copy AccessKeyId, SecretAccessKey, and SessionToken from STS into the process environment. Then:

```bash
beacon collect --target IAC-01
beacon push
beacon sync
beacon pull
```

Set `BEACON_REQUIRE_REMOTE=1` to fail closed when the remote seal is missing.

Optional:

- `BEACON_S3_PREFIX`
- `BEACON_PACK_TYPE` (`bundle`, `ongoing-certification-report`, `secure-configuration-guide`, `security-decision-record`)
- `BEACON_TRUST_CENTER_EXPORT=1` (pack/report copies only; never raw observations)

See [docs/STORAGE.md](../../docs/STORAGE.md). Architecture: [docs/architecture/beacon-evidence-lake.md](../../docs/architecture/beacon-evidence-lake.md). Control map: [docs/architecture/terraform-compliance.md](../../docs/architecture/terraform-compliance.md).

OPA/Conftest (`make policy`) checks the controls in this module. See `policy/terraform`.

S3 server access logs and CloudTrail object-level data events default to **on**. They write to a dedicated logging bucket (`beacon-evidence-logs-<account>-<region>` by default) with the same SSE-KMS, Block Public Access, and BucketOwnerEnforced posture. Object Lock is off on that bucket because S3 cannot deliver access logs to an Object Lock destination. Set `enable_s3_access_logging = false` or `enable_cloudtrail_data_events = false` only when you already cover those events. This module does not create an account-level management-event trail.

`BeaconWriter` can list and get `s3-access-logs/` and `cloudtrail/` on that bucket. It cannot put or delete those objects. `aws.lake.logs` uses `BEACON_LOGS_BUCKET` (Terraform output `logging_bucket`) to read them and seal observations and findings into the evidence bucket. Raw AWS log objects stay in the logging bucket.
