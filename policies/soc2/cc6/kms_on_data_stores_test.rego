# METADATA
# title: Tests for kms_on_data_stores.rego
# description: Positive and negative fixtures for CC6.1 KMS-on-data-stores.
package soc2.cc6.kms_on_data_stores_test

import rego.v1

import data.soc2.cc6.kms_on_data_stores

# ---------- Positive: compliant plan produces no denies ----------

compliant_plan := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"bucket": "acme-uploads"}, "after_unknown": {}},
	},
	{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {
			"actions": ["create"],
			"after": {
				"bucket": "acme-uploads",
				"rule": [{"apply_server_side_encryption_by_default": [{
					"sse_algorithm": "aws:kms",
					"kms_master_key_id": "arn:aws:kms:us-east-1:111122223333:key/abcd-1234",
				}]}],
			},
			"after_unknown": {},
		},
	},
	{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {
			"actions": ["create"],
			"after": {"server_side_encryption": [{
				"enabled": true,
				"kms_key_arn": "arn:aws:kms:us-east-1:111122223333:key/abcd-1234",
			}]},
			"after_unknown": {},
		},
	},
]}

test_compliant_plan_produces_no_denies if {
	count(kms_on_data_stores.deny) == 0 with input as compliant_plan
}

# Also accept the plan where the KMS ARN is a computed reference
# (after_unknown = true) — Terraform hasn't resolved the ref yet.
compliant_plan_unknown := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
	},
	{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {
			"actions": ["create"],
			"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
			"after_unknown": {"rule": [{"apply_server_side_encryption_by_default": [{"kms_master_key_id": true}]}]},
		},
	},
	{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {
			"actions": ["create"],
			"after": {"server_side_encryption": [{"enabled": true}]},
			"after_unknown": {"server_side_encryption": [{"kms_key_arn": true}]},
		},
	},
]}

test_compliant_plan_unknown_produces_no_denies if {
	count(kms_on_data_stores.deny) == 0 with input as compliant_plan_unknown
}

# ---------- Negative: unencrypted plan produces denies ----------

# S3 bucket with no SSE config at all + DynamoDB with no SSE block.
starter_gap_plan := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"bucket": "acme-uploads"}, "after_unknown": {}},
	},
	{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
	},
]}

test_starter_gap_plan_denies_s3_and_dynamo if {
	denies := kms_on_data_stores.deny with input as starter_gap_plan
	count(denies) >= 2
}

# SSE config present but sse_algorithm = AES256 (SSE-S3, not SSE-KMS).
sse_s3_plan := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
	},
	{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {
			"actions": ["create"],
			"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]},
			"after_unknown": {},
		},
	},
	{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {"actions": ["create"], "after": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:111122223333:key/a"}]}, "after_unknown": {}},
	},
]}

test_sse_s3_plan_denies_s3_algorithm if {
	denies := kms_on_data_stores.deny with input as sse_s3_plan
	some m in denies
	contains(m, "must be aws:kms")
}

# aws:kms but no key id — falls back to AWS-managed alias.
kms_no_key_plan := {"resource_changes": [
	{
		"address": "aws_s3_bucket.uploads",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
	},
	{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {
			"actions": ["create"],
			"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
			"after_unknown": {},
		},
	},
	{
		"address": "aws_dynamodb_table.intake",
		"type": "aws_dynamodb_table",
		"change": {"actions": ["create"], "after": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:111122223333:key/a"}]}, "after_unknown": {}},
	},
]}

test_kms_no_key_plan_denies if {
	denies := kms_on_data_stores.deny with input as kms_no_key_plan
	some m in denies
	contains(m, "no kms_master_key_id")
}
