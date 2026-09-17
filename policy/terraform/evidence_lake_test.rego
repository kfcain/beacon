package main

import rego.v1

as_input(cfg) := [{"path": "fixture.tf", "contents": cfg}]

test_ensure_array_unwraps_object if {
	ensure_array({"a": 1}) == [{"a": 1}]
}

test_deny_sse_aes256 if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_s3_bucket" "evidence" { object_lock_enabled = true }`,
		`resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {`,
		`  bucket = aws_s3_bucket.evidence.id`,
		`  rule {`,
		`    apply_server_side_encryption_by_default {`,
		`      sse_algorithm = "AES256"`,
		`    }`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "default encryption must be SSE-KMS")}) > 0 with input as as_input(cfg)
}

test_allow_sse_kms if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_s3_bucket" "evidence" { object_lock_enabled = true }`,
		`resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {`,
		`  bucket = aws_s3_bucket.evidence.id`,
		`  rule {`,
		`    apply_server_side_encryption_by_default {`,
		`      sse_algorithm     = "aws:kms"`,
		`      kms_master_key_id = aws_kms_key.evidence.arn`,
		`    }`,
		`    bucket_key_enabled = true`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "default encryption must be SSE-KMS")}) == 0 with input as as_input(cfg)
}

test_deny_bpa_incomplete if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_s3_bucket" "evidence" { object_lock_enabled = true }`,
		`resource "aws_s3_bucket_public_access_block" "evidence" {`,
		`  bucket                  = aws_s3_bucket.evidence.id`,
		`  block_public_acls       = true`,
		`  block_public_policy     = true`,
		`  ignore_public_acls      = false`,
		`  restrict_public_buckets = true`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "Block Public Access")}) > 0 with input as as_input(cfg)
}

test_deny_ownership_not_enforced if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_s3_bucket" "evidence" { object_lock_enabled = true }`,
		`resource "aws_s3_bucket_ownership_controls" "evidence" {`,
		`  bucket = aws_s3_bucket.evidence.id`,
		`  rule { object_ownership = "ObjectWriter" }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "BucketOwnerEnforced")}) > 0 with input as as_input(cfg)
}

test_deny_public_acl if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_s3_bucket" "evidence" { object_lock_enabled = true }`,
		`resource "aws_s3_bucket_acl" "evidence" {`,
		`  bucket = aws_s3_bucket.evidence.id`,
		`  acl    = "public-read"`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "public ACLs")}) > 0 with input as as_input(cfg)
}

test_deny_object_lock_disabled if {
	cfg := parse_config("hcl2", `resource "aws_s3_bucket" "evidence" { object_lock_enabled = false }`)
	count({m | some m in deny; contains(m, "object_lock_enabled")}) > 0 with input as as_input(cfg)
}

test_deny_versioning_suspended if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_s3_bucket" "evidence" { object_lock_enabled = true }`,
		`resource "aws_s3_bucket_versioning" "evidence" {`,
		`  bucket = aws_s3_bucket.evidence.id`,
		`  versioning_configuration { status = "Suspended" }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "versioning")}) > 0 with input as as_input(cfg)
}

test_deny_writer_delete_object if {
	cfg := parse_config("hcl2", concat("\n", [
		`data "aws_iam_policy_document" "writer" {`,
		`  statement {`,
		`    sid     = "S3PutGetNoDelete"`,
		`    effect  = "Allow"`,
		`    actions = ["s3:PutObject", "s3:DeleteObject"]`,
		`    resources = ["${aws_s3_bucket.evidence.arn}/${local.workspace_prefix}/*"]`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "s3:DeleteObject")}) > 0 with input as as_input(cfg)
}

test_deny_writer_bypass_governance if {
	cfg := parse_config("hcl2", concat("\n", [
		`data "aws_iam_policy_document" "writer" {`,
		`  statement {`,
		`    sid     = "S3PutGetNoDelete"`,
		`    effect  = "Allow"`,
		`    actions = ["s3:PutObject", "s3:BypassGovernanceRetention"]`,
		`    resources = ["${aws_s3_bucket.evidence.arn}/${local.workspace_prefix}/*"]`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "BypassGovernanceRetention")}) > 0 with input as as_input(cfg)
}

test_deny_auditor_wildcard if {
	cfg := parse_config("hcl2", concat("\n", [
		`data "aws_iam_policy_document" "auditor" {`,
		`  statement {`,
		`    sid     = "S3ReadObjects"`,
		`    effect  = "Allow"`,
		`    actions = ["s3:*"]`,
		`    resources = ["${aws_s3_bucket.evidence.arn}/${local.workspace_prefix}/*"]`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "s3:*")}) > 0 with input as as_input(cfg)
}

test_deny_writer_partial_delete_wildcard if {
	cfg := parse_config("hcl2", concat("\n", [
		`data "aws_iam_policy_document" "writer" {`,
		`  statement {`,
		`    sid     = "S3PutGetNoDelete"`,
		`    effect  = "Allow"`,
		`    actions = ["s3:PutObject", "s3:Delete*"]`,
		`    resources = ["${aws_s3_bucket.evidence.arn}/${local.workspace_prefix}/*"]`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "s3:Delete*")}) > 0 with input as as_input(cfg)
}

test_deny_auditor_kms_service_wildcard if {
	cfg := parse_config("hcl2", concat("\n", [
		`data "aws_iam_policy_document" "auditor" {`,
		`  statement {`,
		`    sid     = "KmsDecrypt"`,
		`    effect  = "Allow"`,
		`    actions = ["kms:*"]`,
		`    resources = [aws_kms_key.evidence.arn]`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "kms:*")}) > 0 with input as as_input(cfg)
}

test_deny_auditor_dynamodb_delete_wildcard if {
	cfg := parse_config("hcl2", concat("\n", [
		`data "aws_iam_policy_document" "auditor" {`,
		`  statement {`,
		`    sid     = "DynamoIndexRead"`,
		`    effect  = "Allow"`,
		`    actions = ["dynamodb:GetItem", "dynamodb:Delete*"]`,
		`    resources = [aws_dynamodb_table.index.arn]`,
		`    condition {`,
		`      test     = "ForAllValues:StringEquals"`,
		`      variable = "dynamodb:LeadingKeys"`,
		`      values   = [local.ddb_pk]`,
		`    }`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "dynamodb:Delete*")}) > 0 with input as as_input(cfg)
}

test_deny_writer_global_wildcard if {
	cfg := parse_config("hcl2", concat("\n", [
		`data "aws_iam_policy_document" "writer" {`,
		`  statement {`,
		`    sid     = "TooBroad"`,
		`    effect  = "Allow"`,
		`    actions = ["*"]`,
		`    resources = ["*"]`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "wildcard")}) > 0 with input as as_input(cfg)
}

test_deny_mismatched_bucket_policy_attachment if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_s3_bucket" "evidence" { object_lock_enabled = true }`,
		`resource "aws_s3_bucket" "unprotected" { bucket = "other" }`,
		`data "aws_iam_policy_document" "bucket" {`,
		`  statement {`,
		`    sid     = "DenyInsecureTransport"`,
		`    effect  = "Deny"`,
		`    actions = ["s3:*"]`,
		`    principals {`,
		`      type        = "*"`,
		`      identifiers = ["*"]`,
		`    }`,
		`    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]`,
		`    condition {`,
		`      test     = "Bool"`,
		`      variable = "aws:SecureTransport"`,
		`      values   = ["false"]`,
		`    }`,
		`  }`,
		`}`,
		`resource "aws_s3_bucket_policy" "wrong" {`,
		`  bucket = aws_s3_bucket.unprotected.id`,
		`  policy = "{}"`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "aws_s3_bucket_policy must attach")}) > 0 with input as as_input(cfg)
}

test_deny_bucket_policy_wrong_document if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_s3_bucket" "evidence" { object_lock_enabled = true }`,
		`data "aws_iam_policy_document" "bucket" {`,
		`  statement {`,
		`    sid    = "DenyInsecureTransport"`,
		`    effect = "Deny"`,
		`  }`,
		`}`,
		`resource "aws_s3_bucket_policy" "evidence" {`,
		`  bucket = aws_s3_bucket.evidence.id`,
		`  policy = "{}"`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "aws_s3_bucket_policy must attach")}) > 0 with input as as_input(cfg)
}

test_deny_without_combine_shape if {
	cfg := parse_config("hcl2", `resource "aws_s3_bucket" "evidence" { object_lock_enabled = true }`)
	count({m | some m in deny; contains(m, "--combine")}) > 0 with input as cfg
}

test_deny_auditor_put_object if {
	cfg := parse_config("hcl2", concat("\n", [
		`data "aws_iam_policy_document" "auditor" {`,
		`  statement {`,
		`    sid     = "S3ReadObjects"`,
		`    effect  = "Allow"`,
		`    actions = ["s3:GetObject", "s3:PutObject"]`,
		`    resources = ["${aws_s3_bucket.evidence.arn}/${local.workspace_prefix}/*"]`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "BeaconAuditor")}) > 0 with input as as_input(cfg)
}

test_deny_kms_rotation_off if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_kms_key" "evidence" {`,
		`  enable_key_rotation = false`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "enable_key_rotation")}) > 0 with input as as_input(cfg)
}

test_deny_ddb_without_cmk if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_dynamodb_table" "index" {`,
		`  name     = "beacon-artifact-index"`,
		`  hash_key = "pk"`,
		`  attribute {`,
		`    name = "pk"`,
		`    type = "S"`,
		`  }`,
		`  server_side_encryption { enabled = true }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "SSE with the evidence CMK")}) > 0 with input as as_input(cfg)
}

test_deny_missing_freshness_gsi if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_dynamodb_table" "index" {`,
		`  name     = "beacon-artifact-index"`,
		`  hash_key = "pk"`,
		`  attribute {`,
		`    name = "pk"`,
		`    type = "S"`,
		`  }`,
		`  server_side_encryption {`,
		`    enabled     = true`,
		`    kms_key_arn = aws_kms_key.evidence.arn`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "freshness")}) > 0 with input as as_input(cfg)
}

test_deny_hardcoded_disallowed_region if {
	cfg := parse_config("hcl2", concat("\n", [
		`provider "aws" { region = "us-west-2" }`,
	]))
	count({m | some m in deny; contains(m, "region")}) > 0 with input as as_input(cfg)
}

test_deny_region_default_not_allowed if {
	cfg := parse_config("hcl2", concat("\n", [
		`variable "aws_region" {`,
		`  type    = string`,
		`  default = "eu-west-1"`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "var.aws_region default")}) > 0 with input as as_input(cfg)
}

test_deny_trust_center_missing_classes if {
	cfg := parse_config("hcl2", concat("\n", [
		`resource "aws_s3_bucket" "evidence" { object_lock_enabled = true }`,
		`data "aws_iam_policy_document" "bucket" {`,
		`  statement {`,
		`    sid     = "DenyRawInTrustCenterByClass"`,
		`    effect  = "Deny"`,
		`    actions = ["s3:PutObject"]`,
		`    resources = ["${aws_s3_bucket.evidence.arn}/*/public/trust-center/*"]`,
		`    condition {`,
		`      test     = "StringEquals"`,
		`      variable = "s3:RequestObjectTag/beacon-class"`,
		`      values   = ["observation"]`,
		`    }`,
		`  }`,
		`}`,
	]))
	count({m | some m in deny; contains(m, "DenyRawInTrustCenterByClass")}) > 0 with input as as_input(cfg)
}

# Paths are relative to policy/terraform (conftest verify load dir).
_live_files := [
	"../../deploy/aws/s3.tf",
	"../../deploy/aws/iam.tf",
	"../../deploy/aws/kms.tf",
	"../../deploy/aws/dynamodb.tf",
	"../../deploy/aws/logging.tf",
	"../../deploy/aws/variables.tf",
	"../../deploy/aws/versions.tf",
	"../../deploy/aws/outputs.tf",
]

test_live_module_has_no_deny if {
	cfg := parse_combined_config_files(_live_files)
	count(deny) == 0 with input as cfg
}

test_live_module_warns_on_known_gaps if {
	cfg := parse_combined_config_files(_live_files)
	count({m | some m in warn; contains(m, "var.aws_region")}) == 1 with input as cfg
	count({m | some m in warn; contains(m, "cold_classes")}) == 1 with input as cfg
}
