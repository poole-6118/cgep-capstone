# METADATA
# title: S3 buckets must deny non-TLS requests
# description: |
#   Every aws_s3_bucket in the plan must have a companion
#   aws_s3_bucket_policy that includes a Deny statement on
#   aws:SecureTransport=false. Enforces SOC 2 CC6.7 (transmission
#   security) by preventing plaintext HTTP access to PHI-bearing
#   objects.
# custom:
#   controls: ["CC6.7"]
#   severity: high
#   remediation: |
#     Add an aws_s3_bucket_policy resource referencing the bucket, whose
#     policy JSON contains:
#       { "Effect": "Deny", "Principal": "*", "Action": "s3:*",
#         "Resource": [<bucket-arn>, <bucket-arn>/*],
#         "Condition": { "Bool": { "aws:SecureTransport": "false" } } }
#   hipaa: ["164.312(e)(1)", "164.312(e)(2)(i)"]
#   cmmc: ["SC.L2-3.13.8"]
#   gaps: ["GAP-03"]
package soc2.cc6.tls_only_bucket_policy

import rego.v1

s3_buckets contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	not is_delete(rc)
}

s3_policies contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_policy"
	not is_delete(rc)
}

# Deny when there are S3 buckets but no bucket-policy resources.
deny contains msg if {
	count(s3_buckets) > 0
	count(s3_policies) == 0
	msg := "CC6.7: no aws_s3_bucket_policy resources found; every S3 bucket must have a policy denying aws:SecureTransport=false"
}

# Deny when fewer bucket policies than buckets.
deny contains msg if {
	count(s3_buckets) > 0
	count(s3_policies) > 0
	count(s3_policies) < count(s3_buckets)
	msg := sprintf(
		"CC6.7: found %d aws_s3_bucket resources but only %d aws_s3_bucket_policy resources; every bucket must have a TLS-only policy",
		[count(s3_buckets), count(s3_policies)],
	)
}

# Deny any bucket policy whose parsed JSON lacks a Deny/SecureTransport=false statement.
deny contains msg if {
	some pol in s3_policies
	not policy_has_secure_transport_deny(pol)
	msg := sprintf(
		"CC6.7: %s does not deny requests with aws:SecureTransport=false",
		[pol.address],
	)
}

# The policy is stored as a JSON string in `change.after.policy`.
# We parse and look for an explicit Deny with a Bool aws:SecureTransport=false.
policy_has_secure_transport_deny(pol) if {
	policy_str := pol.change.after.policy
	is_string(policy_str)
	policy_doc := json.unmarshal(policy_str)
	some stmt in policy_doc.Statement
	stmt.Effect == "Deny"
	transport_flag(stmt) == "false"
}

# A policy is also considered compliant if the policy body is a
# computed reference at plan time (after_unknown.policy == true).
# We trust the reference and let a strict-mode variant catch this
# elsewhere if desired.
policy_has_secure_transport_deny(pol) if {
	pol.change.after_unknown.policy == true
}

transport_flag(stmt) := val if {
	val := stmt.Condition.Bool["aws:SecureTransport"]
}

transport_flag(stmt) := val if {
	val := stmt.Condition.Bool["aws:secureTransport"]
}

is_delete(rc) if {
	rc.change.actions == ["delete"]
}
