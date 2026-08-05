# METADATA
# title: Tests for tls_only_bucket_policy.rego
package soc2.cc6.tls_only_bucket_policy_test

import rego.v1

import data.soc2.cc6.tls_only_bucket_policy

# ---------------------- Positive fixtures ----------------------

compliant_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "DenyInsecureTransport",
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": ["arn:aws:s3:::acme-uploads", "arn:aws:s3:::acme-uploads/*"],
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}],
})

compliant_plan := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
	},
	{
		"address": "aws_s3_bucket_policy.uploads",
		"type": "aws_s3_bucket_policy",
		"change": {"actions": ["create"], "after": {"policy": compliant_policy_json}, "after_unknown": {}},
	},
]}

test_compliant_plan_produces_no_denies if {
	count(tls_only_bucket_policy.deny) == 0 with input as compliant_plan
}

# Policy body is a computed reference (Terraform data.iam_policy_document).
compliant_plan_computed_policy := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
	},
	{
		"address": "aws_s3_bucket_policy.uploads",
		"type": "aws_s3_bucket_policy",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {"policy": true}},
	},
]}

test_computed_policy_plan_produces_no_denies if {
	count(tls_only_bucket_policy.deny) == 0 with input as compliant_plan_computed_policy
}

# ---------------------- Negative fixtures ----------------------

no_bucket_policy_plan := {"resource_changes": [{
	"address": "aws_s3_bucket.uploads",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
}]}

test_no_bucket_policy_denies if {
	denies := tls_only_bucket_policy.deny with input as no_bucket_policy_plan
	count(denies) >= 1
}

# Bucket policy exists but doesn't include SecureTransport=false deny.
weak_policy_json := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {"AWS": "arn:aws:iam::111122223333:role/lambda"},
		"Action": ["s3:GetObject", "s3:PutObject"],
		"Resource": "arn:aws:s3:::acme-uploads/*",
	}],
})

weak_plan := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
	},
	{
		"address": "aws_s3_bucket_policy.uploads",
		"type": "aws_s3_bucket_policy",
		"change": {"actions": ["create"], "after": {"policy": weak_policy_json}, "after_unknown": {}},
	},
]}

test_weak_policy_denies if {
	denies := tls_only_bucket_policy.deny with input as weak_plan
	some m in denies
	contains(m, "does not deny")
}
