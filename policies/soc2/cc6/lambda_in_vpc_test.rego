# METADATA
# title: Tests for lambda_in_vpc.rego
package soc2.cc6.lambda_in_vpc_test

import rego.v1

import data.soc2.cc6.lambda_in_vpc

# Positive
compliant_plan := {"resource_changes": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {
		"actions": ["create"],
		"after": {"vpc_config": [{
			"subnet_ids": ["subnet-abc", "subnet-def"],
			"security_group_ids": ["sg-111"],
		}]},
		"after_unknown": {},
	},
}]}

test_compliant_plan_no_denies if {
	count(lambda_in_vpc.deny) == 0 with input as compliant_plan
}

# Positive with computed refs
computed_plan := {"resource_changes": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {
		"actions": ["create"],
		"after": {"vpc_config": [{}]},
		"after_unknown": {"vpc_config": [{"subnet_ids": true, "security_group_ids": true}]},
	},
}]}

test_computed_vpc_config_no_denies if {
	count(lambda_in_vpc.deny) == 0 with input as computed_plan
}

# Negative — starter's GAP-05
no_vpc_plan := {"resource_changes": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
}]}

test_no_vpc_config_denies if {
	denies := lambda_in_vpc.deny with input as no_vpc_plan
	count(denies) >= 1
	some m in denies
	contains(m, "no vpc_config")
}

# Negative — vpc_config present but subnet_ids empty
empty_subnets_plan := {"resource_changes": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"change": {
		"actions": ["create"],
		"after": {"vpc_config": [{"subnet_ids": [], "security_group_ids": ["sg-111"]}]},
		"after_unknown": {},
	},
}]}

test_empty_subnets_denies if {
	denies := lambda_in_vpc.deny with input as empty_subnets_plan
	some m in denies
	contains(m, "subnet_ids is empty")
}
