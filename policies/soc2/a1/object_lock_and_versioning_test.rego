# METADATA
# title: Tests for object_lock_and_versioning.rego
package soc2.a1.object_lock_and_versioning_test

import rego.v1

import data.soc2.a1.object_lock_and_versioning

# ---------------------- Positive ----------------------

compliant_plan := {"resource_changes": [
	{
		"address": "aws_s3_bucket.evidence",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {"object_lock_enabled": true}, "after_unknown": {}},
	},
	{
		"address": "aws_s3_bucket_object_lock_configuration.evidence",
		"type": "aws_s3_bucket_object_lock_configuration",
		"change": {
			"actions": ["create"],
			"after": {"rule": [{"default_retention": [{"mode": "COMPLIANCE", "days": 365}]}]},
			"after_unknown": {},
		},
	},
	{
		"address": "aws_s3_bucket_versioning.evidence",
		"type": "aws_s3_bucket_versioning",
		"change": {
			"actions": ["create"],
			"after": {"versioning_configuration": [{"status": "Enabled"}]},
			"after_unknown": {},
		},
	},
]}

test_compliant_plan_no_denies if {
	count(object_lock_and_versioning.deny) == 0 with input as compliant_plan
}

# ---------------------- Negative ----------------------

# Evidence bucket present but no Object Lock config or versioning at all
no_lock_or_versioning_plan := {"resource_changes": [{
	"address": "aws_s3_bucket.evidence",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
}]}

test_no_lock_or_versioning_denies if {
	denies := object_lock_and_versioning.deny with input as no_lock_or_versioning_plan
	count(denies) >= 2
}

# Object Lock config exists but has retention days == 0
zero_retention_plan := {"resource_changes": [
	{
		"address": "aws_s3_bucket.evidence",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
	},
	{
		"address": "aws_s3_bucket_object_lock_configuration.evidence",
		"type": "aws_s3_bucket_object_lock_configuration",
		"change": {
			"actions": ["create"],
			"after": {"rule": [{"default_retention": [{"mode": "COMPLIANCE", "days": 0}]}]},
			"after_unknown": {},
		},
	},
	{
		"address": "aws_s3_bucket_versioning.evidence",
		"type": "aws_s3_bucket_versioning",
		"change": {"actions": ["create"], "after": {"versioning_configuration": [{"status": "Enabled"}]}, "after_unknown": {}},
	},
]}

test_zero_retention_denies if {
	denies := object_lock_and_versioning.deny with input as zero_retention_plan
	some m in denies
	contains(m, "days > 0")
}

# Versioning present but Suspended
versioning_suspended_plan := {"resource_changes": [
	{
		"address": "aws_s3_bucket.evidence",
		"type": "aws_s3_bucket",
		"change": {"actions": ["create"], "after": {}, "after_unknown": {}},
	},
	{
		"address": "aws_s3_bucket_object_lock_configuration.evidence",
		"type": "aws_s3_bucket_object_lock_configuration",
		"change": {"actions": ["create"], "after": {"rule": [{"default_retention": [{"mode": "COMPLIANCE", "days": 365}]}]}, "after_unknown": {}},
	},
	{
		"address": "aws_s3_bucket_versioning.evidence",
		"type": "aws_s3_bucket_versioning",
		"change": {"actions": ["create"], "after": {"versioning_configuration": [{"status": "Suspended"}]}, "after_unknown": {}},
	},
]}

test_versioning_suspended_denies if {
	denies := object_lock_and_versioning.deny with input as versioning_suspended_plan
	some m in denies
	contains(m, "Enabled")
}
