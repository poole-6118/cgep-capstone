# METADATA
# title: Tests for least_priv_iam.rego
package soc2.cc6.least_priv_iam_test

import rego.v1

import data.soc2.cc6.least_priv_iam

# ---------------------- Positive ----------------------

narrow_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
			"Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/intake",
		},
		{
			"Effect": "Allow",
			"Action": ["s3:PutObject", "s3:GetObject"],
			"Resource": "arn:aws:s3:::acme-uploads/*",
		},
	],
})

narrow_plan := {"resource_changes": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"change": {"actions": ["create"], "after": {"policy": narrow_policy_json}, "after_unknown": {}},
}]}

test_narrow_policy_no_denies if {
	count(least_priv_iam.deny) == 0 with input as narrow_plan
}

# ---------------------- Negative (starter's GAP-07) ----------------------

starter_bad_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": "dynamodb:*",
			"Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/intake",
		},
		{
			"Effect": "Allow",
			"Action": "s3:*",
			"Resource": ["arn:aws:s3:::acme-uploads", "arn:aws:s3:::acme-uploads/*"],
		},
	],
})

starter_bad_plan := {"resource_changes": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"change": {"actions": ["create"], "after": {"policy": starter_bad_policy_json}, "after_unknown": {}},
}]}

test_starter_dynamodb_star_denied if {
	denies := least_priv_iam.deny with input as starter_bad_plan
	count(denies) >= 2
}

# Admin-god policy — Action:*  Resource:*
admin_god_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
})

admin_god_plan := {"resource_changes": [{
	"address": "aws_iam_policy.god",
	"type": "aws_iam_policy",
	"change": {"actions": ["create"], "after": {"policy": admin_god_json}, "after_unknown": {}},
}]}

test_admin_god_policy_denied if {
	denies := least_priv_iam.deny with input as admin_god_plan
	some m in denies
	contains(m, "wildcard action \"*\"")
}
