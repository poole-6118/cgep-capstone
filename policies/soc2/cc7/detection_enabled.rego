# METADATA
# title: Detection controls (CloudTrail, API GW access logs, Lambda DLQ + X-Ray)
# description: |
#   SOC 2 CC7.2 (system monitoring — detection). Enforces:
#     (a) at least one aws_cloudtrail resource exists, is_multi_region_trail=true,
#         and log_file_validation_enabled=true;
#     (b) every aws_apigatewayv2_stage has an access_log_settings block;
#     (c) every aws_lambda_function has a non-empty dead_letter_config
#         and tracing_config.mode = "Active".
#   Closes GAP-06 (Lambda: no DLQ, no X-Ray) and GAP-08 (API GW: no
#   access logging).
# custom:
#   controls: ["CC7.2"]
#   severity: high
#   remediation: |
#     Terraform: aws_cloudtrail.governance { is_multi_region_trail = true,
#     enable_log_file_validation = true }. Add access_log_settings on
#     every API GW v2 stage. On every Lambda, set:
#       dead_letter_config { target_arn = aws_sqs_queue.<name>.arn }
#       tracing_config     { mode       = "Active" }
#   hipaa: ["164.312(b)", "164.308(a)(1)(ii)(D)"]
#   cmmc: ["AU.L2-3.3.1", "SI.L2-3.14.6", "SI.L2-3.14.7"]
#   gaps: ["GAP-06", "GAP-08"]
package soc2.cc7.detection_enabled

import rego.v1

# --------------------- CloudTrail ---------------------

cloudtrails contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_cloudtrail"
	not is_delete(rc)
}

deny contains msg if {
	count(cloudtrails) == 0
	msg := "CC7.2: no aws_cloudtrail resource in plan; a multi-region, log-file-validation-enabled trail is required"
}

deny contains msg if {
	some tr in cloudtrails
	not multi_region(tr)
	msg := sprintf(
		"CC7.2: aws_cloudtrail %q must have is_multi_region_trail = true",
		[tr.address],
	)
}

deny contains msg if {
	some tr in cloudtrails
	not log_file_validation(tr)
	msg := sprintf(
		"CC7.2: aws_cloudtrail %q must have enable_log_file_validation = true",
		[tr.address],
	)
}

multi_region(tr) if {
	tr.change.after.is_multi_region_trail == true
}

log_file_validation(tr) if {
	tr.change.after.enable_log_file_validation == true
}

# --------------------- API Gateway v2 stages ---------------------

api_stages contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_apigatewayv2_stage"
	not is_delete(rc)
}

deny contains msg if {
	some stg in api_stages
	not has_access_logs(stg)
	msg := sprintf(
		"CC7.2: aws_apigatewayv2_stage %q has no access_log_settings",
		[stg.address],
	)
}

has_access_logs(stg) if {
	some cfg in stg.change.after.access_log_settings
	cfg.destination_arn != ""
}

has_access_logs(stg) if {
	some _ in stg.change.after_unknown.access_log_settings
}

# --------------------- Lambda DLQ + X-Ray ---------------------

lambdas contains rc if {
	some rc in input.resource_changes
	rc.type == "aws_lambda_function"
	not is_delete(rc)
}

deny contains msg if {
	some fn in lambdas
	not has_dlq(fn)
	msg := sprintf(
		"CC7.2: aws_lambda_function %q must set dead_letter_config { target_arn = ... }",
		[fn.address],
	)
}

deny contains msg if {
	some fn in lambdas
	not xray_active(fn)
	msg := sprintf(
		"CC7.2: aws_lambda_function %q must set tracing_config { mode = \"Active\" }",
		[fn.address],
	)
}

has_dlq(fn) if {
	some cfg in fn.change.after.dead_letter_config
	cfg.target_arn != ""
}

has_dlq(fn) if {
	some cfg in fn.change.after_unknown.dead_letter_config
	cfg.target_arn == true
}

xray_active(fn) if {
	some cfg in fn.change.after.tracing_config
	cfg.mode == "Active"
}

is_delete(rc) if {
	rc.change.actions == ["delete"]
}
