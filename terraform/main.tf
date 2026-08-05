######################################################################
# Acme Health — Patient Intake API (CGE-P Capstone Starter)
#
# This is the workload your capstone repo wraps with GRC controls.
# It is INTENTIONALLY non-compliant. See GAPS.md for the named flaws
# your Rego policies + Terraform overrides are expected to remediate.
######################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }

  # Remote state backend — S3 with server-side encryption, versioning,
  # and DynamoDB-based state locking. Removes the "local state" honest
  # gap from WRITEUP.md §7 and lets the GHA pipeline apply against the
  # same state as local runs.
  backend "s3" {
    bucket         = "acme-health-cgep-tfstate-8d3b72e9"
    key            = "state/patient-intake.tfstate"
    region         = "us-east-1"
    dynamodb_table = "acme-health-cgep-tflocks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "acme-health-intake"
      ManagedBy = "terraform"
      Workload  = "patient-intake-api"
      DataClass = "phi"
    }
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  name_prefix = "acme-health-intake"
  suffix      = random_id.suffix.hex
}

######################################################################
# Networking — VPC the learner is expected to put the Lambda inside.
# Two public + two private subnets across two AZs.
######################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.42.${count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${local.name_prefix}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.42.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "${local.name_prefix}-private-${count.index}" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

######################################################################
# DynamoDB — submissions table.
# GAP-02: encryption uses AWS-owned default, not a CMK you control.
######################################################################

resource "aws_dynamodb_table" "intake" {
  name         = "${local.name_prefix}-submissions-${local.suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  # GAP-02 remediated: SSE with customer-managed KMS key.
  # Key defined in grc_kms.tf (aws_kms_key.data_at_rest).
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data_at_rest.arn
  }

  # A1.2 support: continuous backups (35-day PITR window).
  point_in_time_recovery {
    enabled = true
  }
}

######################################################################
# S3 — uploads bucket.
#
# Original starter gaps (all remediated in Layer 1):
#   GAP-01: SSE-KMS with customer CMK          → grc_remediation_uploads.tf
#   GAP-03: TLS-only bucket policy             → grc_remediation_uploads.tf
#   GAP-04: versioning                          → grc_remediation_uploads.tf
#
# Kept the bare bucket resource here to minimize the diff against the
# original starter and to make the "remediation as sibling resources"
# pattern visible to the reader.
######################################################################

resource "aws_s3_bucket" "uploads" {
  bucket        = "${local.name_prefix}-uploads-${local.suffix}"
  force_destroy = true # capstone teardown; a production deployment would leave this false
}

######################################################################
# Lambda — the intake handler.
# GAP-05: not deployed inside the VPC.
# GAP-06: no reserved concurrency, no DLQ, no X-Ray.
# GAP-07: IAM role has dynamodb:* and s3:* on the resources (over-broad).
######################################################################

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/lambda/handler.zip"
}

resource "aws_iam_role" "lambda" {
  name = "${local.name_prefix}-lambda-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# GAP-07 remediated: least-privilege IAM — only the specific actions the
# Lambda actually needs on the two named resources, plus KMS for the
# data-at-rest CMK.
resource "aws_iam_role_policy" "lambda_inline" {
  name = "intake-data-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBWriteOwnItem"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
        ]
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid    = "S3PutIntakeUpload"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
        ]
        Resource = "${aws_s3_bucket.uploads.arn}/*"
      },
      {
        Sid    = "KMSEncryptDecryptDataAtRest"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = aws_kms_key.data_at_rest.arn
      },
      {
        # Lambda needs to write to its own ENIs when in a VPC (GAP-05
        # remediation). Managed policy AWSLambdaVPCAccessExecutionRole
        # is the AWS-blessed way; attached via aws_iam_role_policy_attachment.
        Sid      = "SQSSendToDLQ"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.intake_dlq.arn
      }
    ]
  })
}

# GAP-05 remediation support — Lambda needs VPC ENI create/manage perms.
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# GAP-06 remediation support — dead-letter queue for failed invocations.
resource "aws_sqs_queue" "intake_dlq" {
  name                              = "${local.name_prefix}-dlq-${local.suffix}"
  message_retention_seconds         = 1209600 # 14 days
  kms_master_key_id                 = aws_kms_key.data_at_rest.arn
  kms_data_key_reuse_period_seconds = 300

  tags = {
    Name    = "${local.name_prefix}-dlq"
    Purpose = "lambda-dlq"
  }
}

resource "aws_lambda_function" "intake" {
  function_name    = "${local.name_prefix}-handler-${local.suffix}"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  timeout          = 10

  # GAP-06 remediated: reserved concurrency prevents runaway costs and
  # provides a documented throughput ceiling for capacity planning.
  reserved_concurrent_executions = 10

  environment {
    variables = {
      INTAKE_TABLE  = aws_dynamodb_table.intake.name
      UPLOAD_BUCKET = aws_s3_bucket.uploads.id
    }
  }

  # GAP-05 remediated: Lambda runs inside the VPC, in private subnets,
  # with a hardened egress-only security group (see grc_security_groups.tf).
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  # GAP-06 remediated: dead-letter queue for failed async invocations.
  dead_letter_config {
    target_arn = aws_sqs_queue.intake_dlq.arn
  }

  # GAP-06 remediated: X-Ray tracing for distributed observability (CC7.2).
  tracing_config {
    mode = "Active"
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_vpc,
    aws_iam_role_policy.lambda_inline,
  ]
}

######################################################################
# API Gateway — HTTP API in front of the Lambda.
# GAP-08: no access logging, no throttling, no WAF.
######################################################################

resource "aws_apigatewayv2_api" "intake" {
  name          = "${local.name_prefix}-api-${local.suffix}"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.intake.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.intake.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "intake" {
  api_id    = aws_apigatewayv2_api.intake.id
  route_key = "POST /intake"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.intake.id
  name        = "$default"
  auto_deploy = true

  # GAP-08 remediated: access logs to a KMS-encrypted CloudWatch log group
  # (grc_apigw_logging.tf).
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_access.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      userAgent      = "$context.identity.userAgent"
    })
  }

  # GAP-08 remediated: default route throttling caps burst + steady-state
  # request rates so a misbehaving client can't exhaust downstream services.
  default_route_settings {
    throttling_burst_limit = 100
    throttling_rate_limit  = 50
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.intake.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.intake.execution_arn}/*/*"
}
