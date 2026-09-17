terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  bucket_name = var.bucket_name != "" ? var.bucket_name : "beacon-evidence-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  table_name  = var.ddb_table_name
  kms_alias   = startswith(var.kms_alias, "alias/") ? var.kms_alias : "alias/${var.kms_alias}"
  trusted_principals = length(var.trusted_principal_arns) > 0 ? var.trusted_principal_arns : [
    "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
  ]
  writer_name      = var.writer_role_name
  auditor_name     = var.auditor_role_name
  cold_classes     = ["observation", "finding", "evidence", "pack", "report"]
  key_prefix       = trim(var.s3_key_prefix, "/")
  workspace_prefix = local.key_prefix != "" ? "${local.key_prefix}/${var.tenant_id}/${var.workspace_id}" : "${var.tenant_id}/${var.workspace_id}"
  ddb_pk           = "${var.tenant_id}#${var.workspace_id}"

  enable_log_bucket    = var.enable_s3_access_logging || var.enable_cloudtrail_data_events
  logs_bucket_name     = var.logging_bucket_name != "" ? var.logging_bucket_name : "beacon-evidence-logs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  trail_name           = var.cloudtrail_name
  cloudtrail_arn       = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"
  s3_access_log_prefix = "s3-access-logs/"
  cloudtrail_s3_prefix = "cloudtrail/"
}
