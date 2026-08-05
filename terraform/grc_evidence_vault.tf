######################################################################
# GRC — S3 Object Lock Evidence Vault.
#
# Purpose: the CGE-P pipeline (Layer 3) produces a tar.gz evidence
# bundle on every merge to main, signs it with Cosign (keyless, via
# GHA OIDC), and uploads it here. Object Lock prevents deletion or
# overwrite of an uploaded evidence object for the retention period,
# so an auditor can trust that what they see is what the pipeline
# produced.
#
# Bucket policy denies:
#   - non-TLS requests (aws:SecureTransport = false)
#   - non-KMS-SSE PutObject (enforces the evidence CMK on every write)
#
# Lifecycle: no expiration during the retention window. Object Lock
# rules ensure objects can't be deleted before the retention date,
# so a life-cycle "expire after X" would only take effect after the
# lock releases. We do add a rule to transition old noncurrent
# versions to STANDARD_IA after 30 days (cost hygiene, not compliance).
######################################################################

# ------------------------------------------------------------------
# The bucket itself. Object Lock must be enabled AT CREATION TIME;
# it cannot be added later. If you see `object_lock_enabled = false`
# on an existing bucket, the bucket has to be recreated.
# ------------------------------------------------------------------

resource "aws_s3_bucket" "evidence" {
  bucket              = "${local.grc_name_prefix}-evidence-${local.suffix}"
  object_lock_enabled = true
  # Capstone-mode: force_destroy = true so `make destroy` on day 15 tears
  # the vault down cleanly even with Object Lock GOVERNANCE holds present.
  # A production deployment MUST set this to false — the whole point of
  # the vault is that evidence can't be silently wiped.
  force_destroy = true

  tags = merge(local.grc_common_tags, {
    Name    = "${local.grc_name_prefix}-evidence-${local.suffix}"
    Purpose = "signed-evidence-bundles"
  })
}

# ------------------------------------------------------------------
# Ownership + public access — the evidence vault is private, period.
# Bucket-owner-enforced disables ACLs entirely so IAM policy is the
# single source of access truth.
# ------------------------------------------------------------------

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------------------------------
# Versioning — REQUIRED to be enabled for Object Lock to function.
# AWS enables it automatically when you set object_lock_enabled, but
# declaring it explicitly makes the intent visible in the plan and
# lets our Rego versioning policy find it.
# ------------------------------------------------------------------

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ------------------------------------------------------------------
# Default retention. COMPLIANCE mode = not even the root account can
# shorten or remove the retention on an object before its retain-until
# date. GOVERNANCE mode allows privileged bypass; we don't want the
# capability to exist.
# ------------------------------------------------------------------

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      # Capstone uses GOVERNANCE so a privileged principal (with the
      # s3:BypassGovernanceRetention permission) can remove locks during
      # teardown. A production Type II deployment should switch this to
      # COMPLIANCE — auditors will (correctly) flag GOVERNANCE as
      # bypassable. Documented in WRITEUP.md §"Honest Gaps".
      mode = "GOVERNANCE"
      days = local.grc_evidence_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

# ------------------------------------------------------------------
# SSE-KMS encryption using the evidence CMK.
# BucketKeyEnabled reduces per-object KMS API calls (cost + rate limit).
# ------------------------------------------------------------------

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

# ------------------------------------------------------------------
# Bucket policy — deny non-TLS, deny non-KMS PutObject, deny writes
# with the wrong KMS key.
# ------------------------------------------------------------------

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "DenyWrongKmsKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/*"
        Condition = {
          StringNotEqualsIfExists = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.evidence.arn
          }
        }
      }
    ]
  })

  # Public-access block must be in place before a Deny * bucket policy
  # so the "Bucket policy blocks public access" evaluation on the
  # bucket's Access page correctly reflects the intent.
  depends_on = [aws_s3_bucket_public_access_block.evidence]
}

# ------------------------------------------------------------------
# Lifecycle — cost hygiene only. Do not expire current versions
# (Object Lock protects them anyway); transition non-current versions
# to STANDARD_IA after 30 days.
# ------------------------------------------------------------------

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "transition-noncurrent-to-ia"
    status = "Enabled"

    filter {}

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}
