# METADATA
# title: IAM policies must not use wildcard actions
# description: |
#   Any aws_iam_policy, aws_iam_role_policy, or aws_iam_user_policy in
#   the plan whose policy document contains "Action": "*" or a
#   service-scoped wildcard like "dynamodb:*" or "s3:*" on any resource
#   is denied. Enforces SOC 2 CC6.3 (least privilege). This is the exact
#   rule that catches GAP-07 in the starter (the Lambda inline role
#   policy that grants dynamodb:* and s3:*).
# custom:
#   controls: ["CC6.3"]
#   severity: high
#   remediation: |
#     Scope IAM actions to the minimum required. Prefer explicit action
#     lists like ["dynamodb:PutItem", "dynamodb:GetItem"] and specific
#     resource ARNs (never Resource: "*"). Use service-specific
#     condition keys where possible.
#   hipaa: ["164.312(a)(1)", "164.308(a)(4)(ii)(B)"]
#   cmmc: ["AC.L2-3.1.5", "AC.L2-3.1.6"]
#   gaps: ["GAP-07"]
package soc2.cc6.least_priv_iam

import rego.v1

iam_policy_types := {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

iam_policies contains rc if {
	some rc in input.resource_changes
	iam_policy_types[rc.type]
	not is_delete(rc)
}

# Deny wildcard actions on any statement.
deny contains msg if {
	some pol in iam_policies
	policy_str := pol.change.after.policy
	is_string(policy_str)
	doc := json.unmarshal(policy_str)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	some action in actions_of(stmt)
	is_wildcard(action)
	msg := sprintf(
		"CC6.3: %s has an Allow statement with wildcard action %q; least-privilege requires enumerated actions",
		[pol.address, action],
	)
}

# Also deny "Action": "*" or "Resource": "*" combined — the classic
# over-broad admin grant. We express this as two separate rules so the
# operator sees which condition triggered.
deny contains msg if {
	some pol in iam_policies
	policy_str := pol.change.after.policy
	is_string(policy_str)
	doc := json.unmarshal(policy_str)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	resource_is_star(stmt)
	# Only flag on-non-empty statements to avoid false positives on
	# strictly narrow ones. If the statement has any wildcard action
	# already, the rule above will fire; here we specifically catch
	# "Resource: *" alone.
	not any_action_is_narrow(stmt)
	msg := sprintf(
		"CC6.3: %s has an Allow statement with Resource=\"*\" and no narrowly-scoped action; must target specific resource ARNs",
		[pol.address],
	)
}

# ------------------------- helpers -------------------------

# Action may be a string or a list of strings. Return a set of actions
# (always a set) so the caller can iterate uniformly.
actions_of(stmt) := s if {
	is_string(stmt.Action)
	s := {stmt.Action}
}

actions_of(stmt) := s if {
	is_array(stmt.Action)
	s := {a | some a in stmt.Action}
}

is_wildcard("*")

is_wildcard(a) if {
	is_string(a)
	endswith(a, ":*")
}

resource_is_star(stmt) if {
	stmt.Resource == "*"
}

resource_is_star(stmt) if {
	is_array(stmt.Resource)
	some r in stmt.Resource
	r == "*"
}

any_action_is_narrow(stmt) if {
	is_string(stmt.Action)
	not is_wildcard(stmt.Action)
}

any_action_is_narrow(stmt) if {
	is_array(stmt.Action)
	some a in stmt.Action
	not is_wildcard(a)
}

is_delete(rc) if {
	rc.change.actions == ["delete"]
}
