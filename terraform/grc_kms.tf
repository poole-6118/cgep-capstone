######################################################################
# GRC — Customer-Managed KMS Keys.
#
# Three CMKs, each with rotation enabled and a scoped key policy:
#
#   1. data-at-rest  — encrypts the workload's data stores
#                      (S3 uploads bucket + DynamoDB submissions table)
#   2. evidence      — encrypts the S3 Object Lock evidence vault
#   3. cloudtrail    — encrypts the CloudTrail log bucket + trail events
#
# Rationale for three keys, not one:
#   - Blast radius: rotating or deleting one key never affects the
#     other two workloads' cryptographic material.
#   - Auditor readability: a single-purpose key with a scoped policy
#     tells the story "this key encrypts THIS data" without cross-
#     referencing.
#   - Key policy authorship: each key's policy names exactly the
#     services that need it. No wildcards, no principal='*' with
#     conditions doing all the work.
#
# Rotation: `enable_key_rotation = true` on all three. AWS rotates
# annually; the alias remains stable so consumers don't need updates.
######################################################################

data "aws_caller_identity" "current" {}

# ------------------------------------------------------------------
# Key 1: data-at-rest (S3 uploads + DynamoDB submissions)
# ------------------------------------------------------------------

resource "aws_kms_key" "data_at_rest" {
  description             = "CMK for Acme Health patient intake data at rest (S3 uploads, DynamoDB submissions)"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # Key policy: root + the deploying principal can administer; S3 +
  # DynamoDB services can use the key on our behalf via kms:ViaService
  # condition; Lambda execution role can decrypt (needed for reading
  # uploads and DDB items).
  #
  # The deploying principal (data.aws_caller_identity.current.arn) is
  # granted explicit admin so AWS's policy-lockout-prevention check
  # passes at creation time. Without this, KMS rejects the key with
  # 'MalformedPolicyDocumentException: The new key policy will not
  # allow you to update the key policy in the future.'
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowDeployingPrincipalManage"
        Effect    = "Allow"
        Principal = { AWS = data.aws_caller_identity.current.arn }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3UseOnUploadsBucket"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
        }
      },
      {
        Sid       = "AllowDynamoDBUseOnIntakeTable"
        Effect    = "Allow"
        Principal = { Service = "dynamodb.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "dynamodb.${var.aws_region}.amazonaws.com"
          }
        }
      },
      {
        Sid       = "AllowLambdaExecutionRoleUse"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.lambda.arn }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
      },
      {
        # CloudWatch Logs uses this CMK to encrypt the API Gateway access
        # log group. Scoped by encryption context to the specific log
        # group ARN so no other CW Logs group in the region can slip in.
        Sid       = "AllowCloudWatchLogsForApigwAccess"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/apigw/${local.name_prefix}-api-${local.suffix}"
          }
        }
      }
    ]
  })

  tags = merge(local.grc_common_tags, {
    Name    = "${local.grc_name_prefix}-data-at-rest"
    Purpose = "workload-data-encryption"
  })
}

resource "aws_kms_alias" "data_at_rest" {
  name          = "alias/${local.grc_name_prefix}-data-at-rest"
  target_key_id = aws_kms_key.data_at_rest.key_id
}

# ------------------------------------------------------------------
# Key 2: evidence (Object Lock evidence vault contents)
# ------------------------------------------------------------------

resource "aws_kms_key" "evidence" {
  description             = "CMK for CGE-P signed evidence bundles in the Object Lock vault"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowDeployingPrincipalManage"
        Effect    = "Allow"
        Principal = { AWS = data.aws_caller_identity.current.arn }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3UseOnEvidenceVault"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
        }
      }
      # NOTE: The GHA pipeline (Layer 3) will assume an OIDC role that
      # needs kms:GenerateDataKey against this key to write evidence
      # objects. That role's grant is added in Layer 3 via an
      # aws_kms_grant, keeping this key's policy stable across layers.
    ]
  })

  tags = merge(local.grc_common_tags, {
    Name    = "${local.grc_name_prefix}-evidence"
    Purpose = "evidence-vault-encryption"
  })
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${local.grc_name_prefix}-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}

# ------------------------------------------------------------------
# Key 3: cloudtrail (log bucket + trail events)
# ------------------------------------------------------------------

resource "aws_kms_key" "cloudtrail" {
  description             = "CMK for CloudTrail log encryption (log bucket + event delivery)"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # CloudTrail requires its own service principal be able to encrypt
  # log events, and cross-service access via the log bucket. Policy
  # shape follows the AWS-documented "Allow CloudTrail to encrypt
  # logs" pattern.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowDeployingPrincipalManage"
        Effect    = "Allow"
        Principal = { AWS = data.aws_caller_identity.current.arn }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailEncryptLogs"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        Sid       = "AllowCloudTrailDescribeKey"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3UseForCloudTrailBucket"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(local.grc_common_tags, {
    Name    = "${local.grc_name_prefix}-cloudtrail"
    Purpose = "audit-log-encryption"
  })
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${local.grc_name_prefix}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}
