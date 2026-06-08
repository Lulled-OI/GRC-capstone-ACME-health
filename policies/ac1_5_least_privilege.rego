# METADATA
# title: AC.L2-3.1.5 - Least privilege required on Lambda IAM policies
# description: IAM role policies must not use wildcard actions (e.g. dynamodb:*
#   or s3:*). Only explicitly scoped actions are permitted on PHI data stores.
# custom:
#   framework: cmmc_l2
#   controls:
#     - "AC.L2-3.1.5"
#   severity: high
#   gaps:
#     - GAP-07
package compliance.cmmc.ac1_5_least_privilege

import rego.v1

wildcard_actions := {"dynamodb:*", "s3:*", "*"}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role_policy"
  policy := json.unmarshal(resource.change.after.policy)
  stmt := policy.Statement[_]
  stmt.Effect == "Allow"
  action := stmt.Action
  is_string(action)
  wildcard_actions[action]
  msg := sprintf(
    "[AC.L2-3.1.5] [GAP-07] %s: IAM policy uses wildcard action '%s' - scope to minimum required actions",
    [resource.address, action]
  )
}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role_policy"
  policy := json.unmarshal(resource.change.after.policy)
  stmt := policy.Statement[_]
  stmt.Effect == "Allow"
  action := stmt.Action[_]
  is_string(action)
  wildcard_actions[action]
  msg := sprintf(
    "[AC.L2-3.1.5] [GAP-07] %s: IAM policy uses wildcard action '%s' - scope to minimum required actions",
    [resource.address, action]
  )
}
