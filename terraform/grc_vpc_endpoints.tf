######################################################################
# GRC — VPC Gateway Endpoints for S3 + DynamoDB.
#
# Rationale: the Lambda runs in private subnets with an egress-only
# security group. Without endpoints or a NAT Gateway, it can't reach
# any AWS service. NAT would work but costs ~$32/mo and gives the
# Lambda unnecessary internet egress. Gateway endpoints for S3 and
# DynamoDB cost $0 and keep traffic on the AWS backbone.
#
# For CC6.6 (boundary protection) this is the stronger pattern:
# Lambda has no path to the public internet at all. Any exfiltration
# attempt via a compromised dependency hits a black hole.
#
# Interface endpoints for KMS + Logs + SQS are NOT added \u2014 those go
# out over the AWS backbone via the Lambda service's own network
# fabric in the "no ENI needed" mode when the SDK client uses regional
# endpoints. If we later add outbound calls to services that DO need
# interface endpoints (Secrets Manager, e.g.), add them here.
######################################################################

# S3 gateway endpoint \u2014 lets the Lambda reach the uploads bucket without
# an internet route.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = merge(local.grc_common_tags, {
    Name    = "${local.grc_name_prefix}-s3-endpoint"
    Purpose = "private-s3-access"
  })
}

# DynamoDB gateway endpoint \u2014 lets the Lambda reach the submissions
# table without an internet route.
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = merge(local.grc_common_tags, {
    Name    = "${local.grc_name_prefix}-dynamodb-endpoint"
    Purpose = "private-dynamodb-access"
  })
}

# Private route table for the private subnets. The starter only created
# a public route table (with an IGW route); private subnets currently
# use the default main route table which has no default route. Give
# them their own so we can attach the gateway endpoints cleanly.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  # No default route \u2014 all egress is either through gateway endpoints
  # (S3, DynamoDB) or is blocked.

  tags = merge(local.grc_common_tags, {
    Name    = "${local.grc_name_prefix}-private-rt"
    Purpose = "private-subnet-routing"
  })
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}
