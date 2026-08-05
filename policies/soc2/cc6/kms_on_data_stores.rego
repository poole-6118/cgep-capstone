# METADATA
# title: KMS CMK required on all PHI-bearing data stores
# description: |
#   Every aws_s3_bucket and aws_dynamodb_table in the plan must be
#   encrypted at rest with a customer-managed KMS key (CMK), not the
#   AWS-managed default key. Enforces SOC 2 CC6.1 by ensuring PHI keys
#   remain under customer custody.
# custom:
#   controls: ["CC6.1"]
#   severity: high
#   remediation: |
#     For S3: add an aws_s3_bucket_server_side_encryption_configuration
#     resource whose rule.apply_server_side_encryption_by_default has
#     sse_algorithm = "aws:kms" and kms_master_key_id referencing an
#     aws_kms_key.<name>.arn (a CMK). For DynamoDB: on the
#     aws_dynamodb_table, set server_side_encryption { enabled = true,
#     kms_key_arn = aws_kms_key.<name>.arn }.
#   hipaa: ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"]
#   cmmc: ["SC.L2-3.13.11", "SC.L2-3.13.16"]
#   gaps: ["GAP-01", "GAP-02"]
package soc2.cc6.kms_on_data_stores

import rego.v1

# Terraform plan JSON shape: input.resource_changes[] with
#   { address, type, change: { after: {...}, after_unknown: {...} } }

# ------------------------------------------------------------------ S3

s3_buckets contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	not is_delete(rc)
}

s3_sse_configs contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_server_side_encryption_configuration"
	not is_delete(rc)
}

# Deny when there are S3 buckets but no SSE config resources at all.
# (Coarse but sufficient: if you have buckets in the plan and zero SSE
# config resources, at least one bucket is misencrypted.)
deny contains msg if {
	count(s3_buckets) > 0
	count(s3_sse_configs) == 0
	msg := "CC6.1: no aws_s3_bucket_server_side_encryption_configuration resources found; every S3 bucket must have SSE-KMS with a customer CMK"
}

# Deny when the number of SSE configs is less than the number of
# buckets (some bucket must be missing one).
deny contains msg if {
	count(s3_buckets) > 0
	count(s3_sse_configs) > 0
	count(s3_sse_configs) < count(s3_buckets)
	msg := sprintf(
		"CC6.1: found %d aws_s3_bucket resources but only %d SSE config resources; every bucket must be individually encrypted with a CMK",
		[count(s3_buckets), count(s3_sse_configs)],
	)
}

# Deny SSE configs that aren't aws:kms.
deny contains msg if {
	some cfg in s3_sse_configs
	rule := cfg.change.after.rule[_]
	default_enc := rule.apply_server_side_encryption_by_default[_]
	default_enc.sse_algorithm != "aws:kms"
	msg := sprintf(
		"CC6.1: %s sse_algorithm=%q; must be aws:kms with a customer CMK",
		[cfg.address, default_enc.sse_algorithm],
	)
}

# Deny SSE configs that use aws:kms without a kms_master_key_id.
deny contains msg if {
	some cfg in s3_sse_configs
	rule := cfg.change.after.rule[_]
	default_enc := rule.apply_server_side_encryption_by_default[_]
	default_enc.sse_algorithm == "aws:kms"
	not kms_key_id_present(default_enc, cfg)
	msg := sprintf(
		"CC6.1: %s uses aws:kms but has no kms_master_key_id set; would fall back to AWS-managed alias",
		[cfg.address],
	)
}

# kms_master_key_id is present if the resolved value is a non-empty
# string OR the plan has it as computed (`after_unknown` == true), which
# indicates a Terraform reference to another resource that will be
# resolved at apply time.
kms_key_id_present(enc, _) if {
	enc.kms_master_key_id
	enc.kms_master_key_id != ""
}

kms_key_id_present(_, cfg) if {
	# after_unknown.rule[N].apply_server_side_encryption_by_default[M].kms_master_key_id == true
	some rule_unknown in cfg.change.after_unknown.rule
	some enc_unknown in rule_unknown.apply_server_side_encryption_by_default
	enc_unknown.kms_master_key_id == true
}

# ------------------------------------------------------------- DynamoDB

dynamo_tables contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_dynamodb_table"
	not is_delete(rc)
}

deny contains msg if {
	some tbl in dynamo_tables
	not dynamo_has_cmk(tbl)
	msg := sprintf(
		"CC6.1: DynamoDB table %q must set server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.<name>.arn }",
		[tbl.address],
	)
}

dynamo_has_cmk(tbl) if {
	sse := tbl.change.after.server_side_encryption[_]
	sse.enabled == true
	kms_arn_present(sse, tbl)
}

kms_arn_present(sse, _) if {
	sse.kms_key_arn
	sse.kms_key_arn != ""
}

kms_arn_present(_, tbl) if {
	some sse_unknown in tbl.change.after_unknown.server_side_encryption
	sse_unknown.kms_key_arn == true
}

# --------------------------------------------------------------- helpers

is_delete(rc) if {
	rc.change.actions == ["delete"]
}
