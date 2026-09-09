data "aws_iam_policy_document" "assume_role" {
  statement {
    sid     = "AllowStsAssume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = local.trusted_principals
    }
  }
}

data "aws_iam_policy_document" "writer" {
  statement {
    sid    = "S3ListBucket"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "s3:GetBucketLocation",
      "s3:GetEncryptionConfiguration",
    ]
    resources = [aws_s3_bucket.evidence.arn]
  }

  statement {
    sid    = "S3PutGetNoDelete"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetObjectTagging",
      "s3:GetObjectRetention",
    ]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
  }

  statement {
    sid    = "KmsEncryptDecrypt"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.evidence.arn]
  }

  statement {
    sid    = "DynamoIndexWrite"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:BatchGetItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:Query",
      "dynamodb:DescribeTable",
    ]
    resources = [
      aws_dynamodb_table.index.arn,
      "${aws_dynamodb_table.index.arn}/index/*",
    ]
  }
}

data "aws_iam_policy_document" "auditor" {
  statement {
    sid    = "S3ListBucket"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:ListBucketVersions",
      "s3:GetBucketLocation",
      "s3:GetEncryptionConfiguration",
    ]
    resources = [aws_s3_bucket.evidence.arn]
  }

  statement {
    sid    = "S3ReadObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetObjectTagging",
      "s3:GetObjectRetention",
    ]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
  }

  statement {
    sid    = "KmsDecrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.evidence.arn]
  }

  statement {
    sid    = "DynamoIndexRead"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:BatchGetItem",
      "dynamodb:Query",
      "dynamodb:DescribeTable",
    ]
    resources = [
      aws_dynamodb_table.index.arn,
      "${aws_dynamodb_table.index.arn}/index/*",
    ]
  }
}

resource "aws_iam_role" "writer" {
  name               = local.writer_name
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role" "auditor" {
  name               = local.auditor_name
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy" "writer" {
  name   = "${local.writer_name}-evidence"
  role   = aws_iam_role.writer.id
  policy = data.aws_iam_policy_document.writer.json
}

resource "aws_iam_role_policy" "auditor" {
  name   = "${local.auditor_name}-evidence"
  role   = aws_iam_role.auditor.id
  policy = data.aws_iam_policy_document.auditor.json
}

resource "aws_iam_instance_profile" "writer" {
  count = var.enable_instance_profile ? 1 : 0
  name  = local.writer_name
  role  = aws_iam_role.writer.name
}
