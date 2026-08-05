######################################################################
# GRC — Security groups.
#
# One SG for the Lambda ENIs when we move the function into the VPC in
# Layer 1b. Egress-only: the Lambda calls DynamoDB (regional endpoint)
# and S3 (regional endpoint or VPC gateway endpoint). No ingress
# rules — Lambda ENIs receive traffic via the Lambda service, not
# directly.
######################################################################

resource "aws_security_group" "lambda" {
  name        = "${local.grc_name_prefix}-lambda"
  description = "Egress-only SG for the patient intake Lambda ENIs"
  vpc_id      = aws_vpc.main.id

  tags = merge(local.grc_common_tags, {
    Name    = "${local.grc_name_prefix}-lambda"
    Purpose = "lambda-eni-egress"
  })
}

# Egress: HTTPS to anywhere. Refined in a real prod deployment by
# restricting to specific prefix lists (AWS-managed prefix lists for
# S3 + DynamoDB in us-east-1) or by wiring VPC endpoints. For the
# capstone, HTTPS-to-anywhere is defensible with a comment explaining
# the tightening path.
resource "aws_vpc_security_group_egress_rule" "lambda_https" {
  security_group_id = aws_security_group.lambda.id
  description       = "HTTPS to AWS regional endpoints (S3, DynamoDB, KMS)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"

  tags = local.grc_common_tags
}
