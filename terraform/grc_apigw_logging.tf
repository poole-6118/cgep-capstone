######################################################################
# GRC — CloudWatch Log Group for API Gateway access logs.
#
# The starter's API Gateway stage has no access_log_settings (GAP-08).
# We create the destination log group here in Layer 1a; Layer 1b wires
# `access_log_settings` on the starter's stage to write to it.
#
# Retention: 90 days. Longer than default (never expire) so we're not
# leaking cost; shorter than CloudTrail because access logs are useful
# for immediate incident triage more than long-term audit.
#
# KMS: encrypted with the data-at-rest CMK. The key policy for that
# CMK includes a scoped "AllowCloudWatchLogsForApigwAccess" statement
# constrained via aws:logs:arn encryption context to this specific
# log group. See grc_kms.tf.
######################################################################

resource "aws_cloudwatch_log_group" "apigw_access" {
  name              = "/aws/apigw/${local.name_prefix}-api-${local.suffix}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.data_at_rest.arn

  tags = merge(local.grc_common_tags, {
    Name    = "${local.name_prefix}-apigw-access-logs"
    Purpose = "apigw-access-logging"
  })
}
