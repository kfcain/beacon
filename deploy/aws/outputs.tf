output "s3_bucket" {
  value       = aws_s3_bucket.evidence.bucket
  description = "BEACON_S3_BUCKET"
}

output "s3_bucket_arn" {
  value = aws_s3_bucket.evidence.arn
}

output "kms_key_arn" {
  value       = aws_kms_key.evidence.arn
  description = "BEACON_KMS_KEY_ARN"
}

output "kms_alias" {
  value = aws_kms_alias.evidence.name
}

output "ddb_table" {
  value       = aws_dynamodb_table.index.name
  description = "BEACON_DDB_TABLE"
}

output "writer_role_arn" {
  value       = aws_iam_role.writer.arn
  description = "Assume this role with STS for collect, sync, and push."
}

output "auditor_role_arn" {
  value       = aws_iam_role.auditor.arn
  description = "Assume this role with STS for pull and read-only review."
}

output "object_lock_mode" {
  value = var.object_lock_mode
}

output "object_lock_days" {
  value = var.object_lock_days
}

output "aws_region" {
  value       = var.aws_region
  description = "Deploy region. Supported targets: us-east-1 (commercial), us-gov-west-1 (GovCloud)."
}

output "beacon_env" {
  description = "Shell exports for Beacon after terraform apply."
  value       = <<-EOT
    export BEACON_S3_BUCKET=${aws_s3_bucket.evidence.bucket}
    export BEACON_KMS_KEY_ARN=${aws_kms_key.evidence.arn}
    export BEACON_DDB_TABLE=${aws_dynamodb_table.index.name}
    export BEACON_OBJECT_LOCK_MODE=${var.object_lock_mode}
    export BEACON_OBJECT_LOCK_DAYS=${var.object_lock_days}
    export BEACON_TENANT_ID=${var.tenant_id}
    export BEACON_WORKSPACE_ID=${var.workspace_id}
    export BEACON_S3_PREFIX=${var.s3_key_prefix}
    # Prefer STS. Do not put long-lived keys in Beacon env.
    # aws sts assume-role --role-arn ${aws_iam_role.writer.arn} --role-session-name beacon-writer
  EOT
}
