resource "aws_dynamodb_table" "index" {
  name         = local.table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "expires_at"
    type = "S"
  }

  global_secondary_index {
    name            = "freshness"
    hash_key        = "pk"
    range_key       = "expires_at"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.evidence.arn
  }
}
