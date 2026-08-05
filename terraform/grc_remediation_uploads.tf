######################################################################
# GRC — Remediation of the starter's `aws_s3_bucket.uploads` gaps.
#
# The starter (main.tf) creates aws_s3_bucket.uploads with no SSE-KMS,
# no bucket policy, no versioning. Rather than editing main.tf (which
# the design keeps as an intentionally-unmodified "inherited workload"),
# we attach remediation as sibling resources here.
#
# Gaps closed:
#   - GAP-01: SSE-KMS with customer CMK
#   - GAP-03: bucket policy denying non-TLS + non-KMS PutObject
#   - GAP-04: versioning enabled (PHI recovery)
#   - Bonus: public access block (defense-in-depth on top of AWS 2023
#            default)
######################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_at_rest.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.uploads.arn, "${aws_s3_bucket.uploads.arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.uploads.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.uploads]
}
