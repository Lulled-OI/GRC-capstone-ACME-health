# METADATA
# title: AU.L2-3.3.1 - API Gateway must have access logging enabled
# description: API Gateway stages must configure access_log_settings with a
#   CloudWatch destination. Without this, API activity against PHI endpoints
#   is not auditable.
# custom:
#   framework: cmmc_l2
#   controls:
#     - "AU.L2-3.3.1"
#   severity: high
#   gaps:
#     - GAP-08
package compliance.cmmc.au3_1_audit_logging

import rego.v1

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_apigatewayv2_stage"
  logs := resource.change.after.access_log_settings
  count(logs) == 0
  msg := sprintf(
    "[AU.L2-3.3.1] [GAP-08] %s: API Gateway stage must have access_log_settings configured to satisfy audit logging requirements",
    [resource.address]
  )
}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_apigatewayv2_stage"
  log := resource.change.after.access_log_settings[_]
  not log.destination_arn
  msg := sprintf(
    "[AU.L2-3.3.1] [GAP-08] %s: API Gateway access_log_settings must specify a destination_arn (CloudWatch log group)",
    [resource.address]
  )
}
