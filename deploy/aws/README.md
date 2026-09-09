# Beacon AWS evidence lake

Terraform creates the S3 evidence lake, KMS CMK (S3 SSE-KMS), DynamoDB index, and IAM roles.

Supported deploy targets: **us-east-1** (commercial) and **us-gov-west-1** (GovCloud). Set `aws_region`. Do not hard-code the region.

BeaconWriter has Put/Get/List and KMS encrypt/decrypt/GenerateDataKey. It does not have DeleteObject. BeaconAuditor is read-only. Prefer STS assume-role. Do not upload private keys (`*.sec`, `.beacon/keys`).

Object Lock default is GOVERNANCE with configurable days. COMPLIANCE mode is opt-in after retain days are fixed.

The bucket policy denies raw `observation` objects under `public/trust-center/`.

## Apply

```bash
cd deploy/aws
cp terraform.tfvars.example terraform.tfvars
# set bucket_name, aws_region, and trusted_principal_arns
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

See [docs/STORAGE.md](../../docs/STORAGE.md).
