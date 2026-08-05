# METADATA
# title: Tests for detection_enabled.rego
package soc2.cc7.detection_enabled_test

import rego.v1

import data.soc2.cc7.detection_enabled

# ---------------------- Positive ----------------------

compliant_plan := {"resource_changes": [
	{
		"address": "aws_cloudtrail.governance",
		"type": "aws_cloudtrail",
		"change": {
			"actions": ["create"],
			"after": {"is_multi_region_trail": true, "enable_log_file_validation": true},
			"after_unknown": {},
		},
	},
	{
		"address": "aws_apigatewayv2_stage.default",
		"type": "aws_apigatewayv2_stage",
		"change": {
			"actions": ["create"],
			"after": {"access_log_settings": [{"destination_arn": "arn:aws:logs:us-east-1:1:log-group:/api/access"}]},
			"after_unknown": {},
		},
	},
	{
		"address": "aws_lambda_function.intake",
		"type": "aws_lambda_function",
		"change": {
			"actions": ["create"],
			"after": {
				"dead_letter_config": [{"target_arn": "arn:aws:sqs:us-east-1:1:dlq"}],
				"tracing_config": [{"mode": "Active"}],
			},
			"after_unknown": {},
		},
	},
]}

test_compliant_plan_no_denies if {
	count(detection_enabled.deny) == 0 with input as compliant_plan
}

# ---------------------- Negative ----------------------

# No CloudTrail
no_trail_plan := {"resource_changes": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
}]}

test_no_trail_denies if {
	denies := detection_enabled.deny with input as no_trail_plan
	some m in denies
	contains(m, "no aws_cloudtrail resource")
}

# CloudTrail present but single-region + no log_file_validation
weak_trail_plan := {"resource_changes": [{
	"address": "aws_cloudtrail.governance",
	"type": "aws_cloudtrail",
	"change": {"actions": ["create"], "after": {"is_multi_region_trail": false, "enable_log_file_validation": false}, "after_unknown": {}},
}]}

test_weak_trail_denies if {
	denies := detection_enabled.deny with input as weak_trail_plan
	count(denies) >= 2
}

# API GW stage with no access logs (GAP-08) + Lambda missing DLQ+XRay (GAP-06)
starter_gap_plan := {"resource_changes": [
	{
		"address": "aws_cloudtrail.governance",
		"type": "aws_cloudtrail",
		"change": {"actions": ["create"], "after": {"is_multi_region_trail": true, "enable_log_file_validation": true}, "after_unknown": {}},
	},
	{
		"address": "aws_apigatewayv2_stage.default",
		"type": "aws_apigatewayv2_stage",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
	},
	{
		"address": "aws_lambda_function.intake",
		"type": "aws_lambda_function",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
	},
]}

test_starter_gaps_denied if {
	denies := detection_enabled.deny with input as starter_gap_plan
	# One for API GW access logs, one for Lambda DLQ, one for Lambda X-Ray.
	count(denies) >= 3
}
