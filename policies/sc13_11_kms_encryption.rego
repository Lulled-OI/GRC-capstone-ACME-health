# METADATA
# title: SC.L2-3.13.11 - KMS customer-managed key encryption required
# description: S3 buckets and DynamoDB tables storing PHI must use SSE-KMS
#   with a customer-managed key, not AWS-managed or default encryption.
# custom:
#   framework: cmmc_l2
#   controls:
#     - "SC.L2-3.13.11"
#   severity: high
#   gaps:
#     - GAP-01
#     - GAP-02
package compliance.cmmc.sc13_11_kms_encryption

import rego.v1

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_server_side_encryption_configuration"
  rule := resource.change.after.rule[_]
  rule.apply_server_side_encryption_by_default[_].sse_algorithm != "aws:kms"
  msg := sprintf(
    "[SC.L2-3.13.11] [GAP-01] %s: S3 bucket must use SSE-KMS with a customer-managed key, not %s",
    [resource.address, rule.apply_server_side_encryption_by_default[_].sse_algorithm]
  )
}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_server_side_encryption_configuration"
  rule := resource.change.after.rule[_]
  default_config := rule.apply_server_side_encryption_by_default[_]
  not default_config.kms_master_key_id
  msg := sprintf(
    "[SC.L2-3.13.11] [GAP-01] %s: SSE-KMS must specify a customer-managed KMS key ARN, not the AWS-managed default",
    [resource.address]
  )
}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_dynamodb_table"
  resource.change.after.server_side_encryption == null
  msg := sprintf(
    "[SC.L2-3.13.11] [GAP-02] %s: DynamoDB table must have server_side_encryption enabled with a customer-managed KMS key",
    [resource.address]
  )
}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_dynamodb_table"
  sse := resource.change.after.server_side_encryption[_]
  sse.enabled == true
  not sse.kms_key_arn
  msg := sprintf(
    "[SC.L2-3.13.11] [GAP-02] %s: DynamoDB server_side_encryption must specify a customer kms_key_arn",
    [resource.address]
  )
}
