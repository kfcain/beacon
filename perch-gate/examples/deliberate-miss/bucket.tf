# Deliberate miss for a local `perch scan perch-gate/examples/deliberate-miss`.
# The default CI target is deploy/aws. These strings are examples. They are not credentials.

resource "aws_s3_bucket" "open_example" {
  bucket = "perch-gate-deliberate-miss-example"
}

resource "aws_s3_bucket_acl" "open_example" {
  bucket = aws_s3_bucket.open_example.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "open_example" {
  bucket                  = aws_s3_bucket.open_example.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

variable "example_password" {
  default = "example-plaintext-secret"
}
