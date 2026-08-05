# METADATA
# title: Evidence vault must have Object Lock + versioning
# description: |
#   The evidence vault S3 bucket (identified by having "evidence" in its
#   Terraform address) must have:
#     (a) an aws_s3_bucket_object_lock_configuration companion resource
#         with a rule.default_retention block that sets days > 0;
#     (b) an aws_s3_bucket_versioning companion resource whose
#         versioning_configuration.status = "Enabled".
#   Enforces SOC 2 A1.2 (availability — backups, recovery) and gives the
#   Cosign-signed evidence bundles WORM properties suitable for a Type
#   II audit trail.
#   Closes GAP-04 (no versioning on PHI buckets — extended here to
#   apply strictly to the evidence vault).
# custom:
#   controls: ["A1.2"]
#   severity: high
#   remediation: |
#     Add aws_s3_bucket_object_lock_configuration referencing the
#     evidence bucket with rule.default_retention.mode = "COMPLIANCE"
#     (or GOVERNANCE) and days >= 90 (adjust for your retention SLA).
#     Add aws_s3_bucket_versioning with versioning_configuration.status
#     = "Enabled". Note: Object Lock requires the bucket to be created
#     with object_lock_enabled = true (see the aws_s3_bucket resource).
#   hipaa: ["164.308(a)(7)(i)", "164.308(a)(7)(ii)(A)"]
#   cmmc: ["MP.L2-3.8.9", "CP.L2-3.8.9"]
#   gaps: ["GAP-04"]
package soc2.a1.object_lock_and_versioning

import rego.v1

evidence_buckets contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	is_evidence_address(rc.address)
	not is_delete(rc)
}

lock_configs contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_object_lock_configuration"
	not is_delete(rc)
}

versioning_configs contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_versioning"
	not is_delete(rc)
}

# Deny if evidence bucket present but no Object Lock config resource
# specifically targeting it.
deny contains msg if {
	some bucket in evidence_buckets
	not has_lock_for(bucket)
	msg := sprintf(
		"A1.2: evidence bucket %q has no aws_s3_bucket_object_lock_configuration companion resource",
		[bucket.address],
	)
}

# Deny if the Object Lock config exists but has no default_retention with days>0.
deny contains msg if {
	some lock in lock_configs
	lock_targets_evidence(lock)
	not lock_has_retention(lock)
	msg := sprintf(
		"A1.2: %s must set rule.default_retention with days > 0",
		[lock.address],
	)
}

# Deny if versioning not Enabled.
deny contains msg if {
	some bucket in evidence_buckets
	not has_versioning_enabled_for(bucket)
	msg := sprintf(
		"A1.2: evidence bucket %q must have an aws_s3_bucket_versioning companion resource with versioning_configuration.status = \"Enabled\"",
		[bucket.address],
	)
}

# ------------------------- helpers -------------------------

# The evidence bucket is any aws_s3_bucket whose Terraform address
# contains "evidence" (case-insensitive). Adjust here if your naming
# convention differs.
is_evidence_address(addr) if {
	contains(lower(addr), "evidence")
}

# The companion resources reference the bucket by short name; we match
# by requiring "evidence" in their addresses too. (Terraform naming
# convention across the repo is to keep companion resources aligned to
# the bucket they belong to, e.g., aws_s3_bucket_versioning.evidence.)
has_lock_for(bucket) if {
	some lock in lock_configs
	lock_targets_evidence(lock)
}

lock_targets_evidence(lock) if {
	contains(lower(lock.address), "evidence")
}

lock_has_retention(lock) if {
	some rule in lock.change.after.rule
	some ret in rule.default_retention
	is_number(ret.days)
	ret.days > 0
}

lock_has_retention(lock) if {
	# Retention days may be a computed reference at plan time.
	some rule in lock.change.after_unknown.rule
	some ret in rule.default_retention
	ret.days == true
}

has_versioning_enabled_for(bucket) if {
	some v in versioning_configs
	contains(lower(v.address), "evidence")
	versioning_status(v) == "Enabled"
}

versioning_status(v) := s if {
	some cfg in v.change.after.versioning_configuration
	s := cfg.status
}

is_delete(rc) if {
	rc.change.actions == ["delete"]
}
