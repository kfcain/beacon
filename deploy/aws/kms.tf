data "aws_iam_policy_document" "kms" {
  statement {
    sid     = "EnableRootAccount"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  statement {
    sid    = "AllowS3AndDynamoDB"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant",
    ]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com", "dynamodb.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "AllowS3AccessLogsEncrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
    ]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "AllowCloudTrailEncryptLogs"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
    ]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.cloudtrail_arn]
    }
  }
}

resource "aws_kms_key" "evidence" {
  description             = "Beacon evidence lake customer CMK for S3 server-side encryption (SSE-KMS) and DynamoDB encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "evidence" {
  name          = local.kms_alias
  target_key_id = aws_kms_key.evidence.key_id
}
