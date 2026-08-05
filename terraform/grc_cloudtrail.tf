######################################################################
# GRC — CloudTrail.
#
# One multi-region trail, log-file-validation on, KMS-encrypted, with a
# dedicated log bucket separate from the evidence vault. Reasoning for
# separation:
#
#   - CloudTrail buckets have a required, AWS-service bucket policy
#     (allow cloudtrail.amazonaws.com to PutObject with specific ACLs).
#     Mixing that policy with the evidence vault's deny-non-KMS PutObject
#     causes CloudTrail delivery failures.
#   - Retention profiles differ. Trail records are the authoritative
#     activity log and stay long (365 days here). Evidence artifacts
#     are the pipeline's output and lock for 90 days.
#   - Blast radius: a bad bucket policy on one doesn't take down the
#     other.
#
# The trail records:
#   - management events (default, both read and write)
#   - S3 data events for the evidence vault (so we can audit who read
#     evidence bundles — matters for SOC 2 CC7.2)
#   - S3 data events for the uploads bucket (PHI reads)
#   - Lambda data events for the intake handler (Invoke calls)
######################################################################

# ------------------------------------------------------------------
# Log bucket for the trail.
# ------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${local.grc_name_prefix}-cloudtrail-${local.suffix}"
  force_destroy = false

  tags = merge(local.grc_common_tags, {
    Name    = "${local.grc_name_prefix}-cloudtrail-${local.suffix}"
    Purpose = "cloudtrail-log-storage"
  })
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail.arn
    }
    bucket_key_enabled = true
  }
}

# ------------------------------------------------------------------
# Bucket policy — CloudTrail service delivery permissions + TLS-only.
# The Sids match the AWS-documented required policy shape verbatim
# (except with our bucket ARN); deviating trips CloudTrail's "unable
# to validate S3 bucket policy" preflight.
# ------------------------------------------------------------------

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.grc_name_prefix}-trail"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.grc_name_prefix}-trail"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.cloudtrail_logs.arn, "${aws_s3_bucket.cloudtrail_logs.arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail_logs]
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = local.grc_cloudtrail_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = local.grc_cloudtrail_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail_logs]
}

# ------------------------------------------------------------------
# The trail itself.
# ------------------------------------------------------------------

resource "aws_cloudtrail" "main" {
  name = "${local.grc_name_prefix}-trail"

  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  # Advanced event selector: management events + specific S3 buckets
  # + our intake Lambda. Cheaper than "all data events" and still
  # covers the auditable surface.
  advanced_event_selector {
    name = "management-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  advanced_event_selector {
    name = "evidence-and-uploads-s3-data-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field = "resources.ARN"
      starts_with = [
        "${aws_s3_bucket.evidence.arn}/",
        "${aws_s3_bucket.uploads.arn}/",
      ]
    }
  }

  advanced_event_selector {
    name = "lambda-intake-invoke-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::Lambda::Function"]
    }
    field_selector {
      field  = "resources.ARN"
      equals = [aws_lambda_function.intake.arn]
    }
  }

  tags = merge(local.grc_common_tags, {
    Name    = "${local.grc_name_prefix}-trail"
    Purpose = "audit-trail"
  })

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}
