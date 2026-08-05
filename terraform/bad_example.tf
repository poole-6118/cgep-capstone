######################################################################
# INTENTIONALLY NON-COMPLIANT DEMO RESOURCES
# ------------------------------------------------------------------
# This file exists ONLY on the `layer3a/gate-fail-demo` branch. Its
# purpose is to prove the Layer-3 GRC gate blocks a PR that
# re-introduces named gaps from GAPS.md.
#
# The Rego suite in policies/ should produce >=3 deny messages when
# `terraform show -json plan.tfplan` is fed through
# `conftest test --all-namespaces --parser json --policy policies/`:
#
#   * CC6.1 — bucket has no aws_s3_bucket_server_side_encryption_configuration
#             (re-introduces GAP-01)
#   * CC6.7 — bucket has no companion aws_s3_bucket_policy
#             (re-introduces GAP-03)
#   * CC6.3 — the IAM policy below uses dynamodb:*  (re-introduces GAP-07)
#
# DO NOT MERGE THIS BRANCH. The PR is a demonstration artifact
# referenced in WRITEUP.md §"Pipeline demonstration".
######################################################################

resource "aws_s3_bucket" "bad_uploads_demo" {
  bucket = "acme-health-intake-BAD-uploads-${local.suffix}"
}

# Intentionally no aws_s3_bucket_server_side_encryption_configuration.
# Intentionally no aws_s3_bucket_policy for TLS-only.
# Intentionally no aws_s3_bucket_versioning.

resource "aws_iam_role" "bad_lambda_demo" {
  name = "BAD-demo-lambda-role-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "bad_lambda_inline_demo" {
  name = "BAD-demo-dynamo-star"
  role = aws_iam_role.bad_lambda_demo.id

  # GAP-07 re-introduced: dynamodb:* on any resource.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "dynamodb:*"
      Resource = "*"
    }]
  })
}
