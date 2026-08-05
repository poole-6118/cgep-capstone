# METADATA
# title: Lambda functions must run inside a VPC
# description: |
#   Every aws_lambda_function in the plan must have a non-empty
#   vpc_config with at least one subnet_id and one security_group_id.
#   Enforces SOC 2 CC6.6 (boundary protection) by ensuring PHI-handling
#   compute lives inside the customer's VPC, not the shared Lambda
#   environment. Closes GAP-05 in the starter.
# custom:
#   controls: ["CC6.6"]
#   severity: high
#   remediation: |
#     Add a vpc_config { subnet_ids = [...], security_group_ids = [...] }
#     block to the aws_lambda_function referencing at least one private
#     subnet and one dedicated security group. Confirm the SG's egress
#     is scoped to only what the function needs (S3 gateway endpoint,
#     DynamoDB gateway endpoint).
#   hipaa: ["164.312(e)(1)", "164.308(a)(4)"]
#   cmmc: ["SC.L2-3.13.1", "SC.L2-3.13.5"]
#   gaps: ["GAP-05"]
package soc2.cc6.lambda_in_vpc

import rego.v1

lambdas contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_lambda_function"
	not is_delete(rc)
}

# Deny lambdas with no vpc_config block at all.
deny contains msg if {
	some fn in lambdas
	not has_vpc_config(fn)
	msg := sprintf(
		"CC6.6: aws_lambda_function %q has no vpc_config; must be attached to the workload VPC with subnet_ids and security_group_ids",
		[fn.address],
	)
}

# Deny lambdas whose vpc_config has empty subnet_ids or security_group_ids.
deny contains msg if {
	some fn in lambdas
	has_vpc_config(fn)
	not subnets_non_empty(fn)
	msg := sprintf(
		"CC6.6: aws_lambda_function %q vpc_config.subnet_ids is empty",
		[fn.address],
	)
}

deny contains msg if {
	some fn in lambdas
	has_vpc_config(fn)
	not sgs_non_empty(fn)
	msg := sprintf(
		"CC6.6: aws_lambda_function %q vpc_config.security_group_ids is empty",
		[fn.address],
	)
}

has_vpc_config(fn) if {
	some _ in fn.change.after.vpc_config
}

has_vpc_config(fn) if {
	some _ in fn.change.after_unknown.vpc_config
}

subnets_non_empty(fn) if {
	some cfg in fn.change.after.vpc_config
	count(cfg.subnet_ids) > 0
}

subnets_non_empty(fn) if {
	# after_unknown lists computed refs
	some cfg in fn.change.after_unknown.vpc_config
	cfg.subnet_ids == true
}

sgs_non_empty(fn) if {
	some cfg in fn.change.after.vpc_config
	count(cfg.security_group_ids) > 0
}

sgs_non_empty(fn) if {
	some cfg in fn.change.after_unknown.vpc_config
	cfg.security_group_ids == true
}

is_delete(rc) if {
	rc.change.actions == ["delete"]
}
