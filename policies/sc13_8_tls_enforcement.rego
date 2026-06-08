# METADATA
# title: SC.L2-3.13.8 - TLS-only access required on S3 buckets containing PHI
# description: S3 buckets must have a bucket policy that explicitly denies
#   requests not using TLS (aws:SecureTransport = false).
# custom:
#   framework: cmmc_l2
#   controls:
#     - "SC.L2-3.13.8"
#   severity: high
#   gaps:
#     - GAP-03
package compliance.cmmc.sc13_8_tls_enforcement

import rego.v1

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_policy"
  policy := json.unmarshal(resource.change.after.policy)
  not has_deny_non_tls(policy)
  msg := sprintf(
    "[SC.L2-3.13.8] [GAP-03] %s: S3 bucket policy must include a Deny statement for aws:SecureTransport=false to enforce TLS-only access",
    [resource.address]
  )
}

has_deny_non_tls(policy) if {
  stmt := policy.Statement[_]
  stmt.Effect == "Deny"
  stmt.Condition.Bool["aws:SecureTransport"] == "false"
}
