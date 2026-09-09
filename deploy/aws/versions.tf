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

locals {
  bucket_name = var.bucket_name != "" ? var.bucket_name : "beacon-evidence-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  table_name  = var.ddb_table_name
  kms_alias   = startswith(var.kms_alias, "alias/") ? var.kms_alias : "alias/${var.kms_alias}"
  trusted_principals = length(var.trusted_principal_arns) > 0 ? var.trusted_principal_arns : [
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
  ]
  writer_name  = var.writer_role_name
  auditor_name = var.auditor_role_name
}
