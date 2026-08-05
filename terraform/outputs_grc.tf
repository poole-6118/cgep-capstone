######################################################################
# GRC — outputs for governance resources.
#
# Kept separate from the starter's outputs.tf so the starter file
# remains unedited. The Layer 3 GitHub Actions workflow consumes
# these to know where to write evidence and which trail to reference
# in the OSCAL component.
######################################################################

output "grc_evidence_bucket" {
  description = "Name of the S3 Object Lock evidence vault"
  value       = aws_s3_bucket.evidence.id
}

output "grc_evidence_bucket_arn" {
  description = "ARN of the S3 Object Lock evidence vault"
  value       = aws_s3_bucket.evidence.arn
}

output "grc_cloudtrail_bucket" {
  description = "Name of the CloudTrail log bucket"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "grc_trail_arn" {
  description = "ARN of the multi-region CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "grc_trail_name" {
  description = "Name of the multi-region CloudTrail trail"
  value       = aws_cloudtrail.main.name
}

output "grc_kms_data_at_rest_arn" {
  description = "ARN of the customer-managed KMS key for workload data at rest"
  value       = aws_kms_key.data_at_rest.arn
}

output "grc_kms_evidence_arn" {
  description = "ARN of the customer-managed KMS key for the evidence vault"
  value       = aws_kms_key.evidence.arn
}

output "grc_kms_cloudtrail_arn" {
  description = "ARN of the customer-managed KMS key for CloudTrail"
  value       = aws_kms_key.cloudtrail.arn
}

output "grc_apigw_access_log_group_arn" {
  description = "ARN of the CloudWatch log group receiving API Gateway access logs (Layer 1b wires the stage to write here)"
  value       = aws_cloudwatch_log_group.apigw_access.arn
}

output "grc_lambda_security_group_id" {
  description = "ID of the security group for the Lambda's ENIs (Layer 1b wires the function's vpc_config to reference it)"
  value       = aws_security_group.lambda.id
}
