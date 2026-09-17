# Dedicated logging bucket for S3 server access logs and CloudTrail data events.
# Same KMS CMK, Block Public Access, and BucketOwnerEnforced posture as the evidence bucket.
# Object Lock is off: S3 server access logging cannot deliver to an Object Lock destination.
# AWS writes these objects. They are raw observations. They are not sealed findings.
# Do not mix them into evidence-bucket observations/ or evidence/ prefixes.

resource "aws_s3_bucket" "logs" {
  count  = local.enable_log_bucket ? 1 : 0
  bucket = local.logs_bucket_name
}

resource "aws_s3_bucket_versioning" "logs" {
  count  = local.enable_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = local.enable_log_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  count  = local.enable_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = local.enable_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  count  = local.enable_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  depends_on = [aws_s3_bucket_versioning.logs]

  rule {
    id     = "s3-access-logs-to-cold"
    status = "Enabled"

    filter {
      prefix = local.s3_access_log_prefix
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }
  }

  rule {
    id     = "cloudtrail-to-cold"
    status = "Enabled"

    filter {
      prefix = local.cloudtrail_s3_prefix
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }
  }
}

data "aws_iam_policy_document" "logs" {
  count = local.enable_log_bucket ? 1 : 0

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_s3_bucket.logs[0].arn,
      "${aws_s3_bucket.logs[0].arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid     = "DenyDeleteObject"
    effect  = "Deny"
    actions = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = ["${aws_s3_bucket.logs[0].arn}/*"]
  }

  dynamic "statement" {
    for_each = var.enable_s3_access_logging && local.enable_log_bucket ? [1] : []
    content {
      sid     = "AllowS3ServerAccessLogs"
      effect  = "Allow"
      actions = ["s3:PutObject"]
      principals {
        type        = "Service"
        identifiers = ["logging.s3.amazonaws.com"]
      }
      resources = ["${aws_s3_bucket.logs[0].arn}/${local.s3_access_log_prefix}*"]
      condition {
        test     = "ArnLike"
        variable = "aws:SourceArn"
        values   = [aws_s3_bucket.evidence.arn]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [data.aws_caller_identity.current.account_id]
      }
    }
  }

  dynamic "statement" {
    for_each = var.enable_cloudtrail_data_events && local.enable_log_bucket ? [1] : []
    content {
      sid     = "AWSCloudTrailAclCheck"
      effect  = "Allow"
      actions = ["s3:GetBucketAcl", "s3:GetBucketLocation"]
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      resources = [aws_s3_bucket.logs[0].arn]
      condition {
        test     = "StringEquals"
        variable = "aws:SourceArn"
        values   = [local.cloudtrail_arn]
      }
    }
  }

  dynamic "statement" {
    for_each = var.enable_cloudtrail_data_events && local.enable_log_bucket ? [1] : []
    content {
      sid     = "AWSCloudTrailWrite"
      effect  = "Allow"
      actions = ["s3:PutObject"]
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      resources = ["${aws_s3_bucket.logs[0].arn}/${local.cloudtrail_s3_prefix}AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
      condition {
        test     = "StringEquals"
        variable = "aws:SourceArn"
        values   = [local.cloudtrail_arn]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  count  = local.enable_log_bucket ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  policy = data.aws_iam_policy_document.logs[0].json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

resource "aws_s3_bucket_logging" "evidence" {
  count         = var.enable_s3_access_logging && local.enable_log_bucket ? 1 : 0
  bucket        = aws_s3_bucket.evidence.id
  target_bucket = aws_s3_bucket.logs[0].id
  target_prefix = local.s3_access_log_prefix

  depends_on = [aws_s3_bucket_policy.logs]
}

# Module-scoped data-event trail only. include_management_events is false so this
# does not invent an account-level management trail.
resource "aws_cloudtrail" "evidence" {
  count                         = var.enable_cloudtrail_data_events && local.enable_log_bucket ? 1 : 0
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.logs[0].id
  s3_key_prefix                 = trimsuffix(local.cloudtrail_s3_prefix, "/")
  kms_key_id                    = aws_kms_key.evidence.arn
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = false

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.evidence.arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.logs]
}
