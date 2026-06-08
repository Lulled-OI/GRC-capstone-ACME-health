# METADATA
# title: SC.L2-3.13.1 - Lambda must be deployed inside the VPC
# description: Lambda functions processing PHI must be placed inside the
#   provisioned VPC with a vpc_config block specifying private subnets
#   and a security group. Running outside the VPC bypasses network boundary controls.
# custom:
#   framework: cmmc_l2
#   controls:
#     - "SC.L2-3.13.1"
#   severity: high
#   gaps:
#     - GAP-05
package compliance.cmmc.sc13_1_vpc_boundary

import rego.v1

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_lambda_function"
  vpc := resource.change.after.vpc_config
  count(vpc) == 0
  msg := sprintf(
    "[SC.L2-3.13.1] [GAP-05] %s: Lambda function must include a vpc_config block to enforce network boundary protection",
    [resource.address]
  )
}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_lambda_function"
  vpc := resource.change.after.vpc_config[_]
  count(vpc.subnet_ids) == 0
  msg := sprintf(
    "[SC.L2-3.13.1] [GAP-05] %s: Lambda vpc_config must specify at least one subnet_id",
    [resource.address]
  )
}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "aws_lambda_function"
  vpc := resource.change.after.vpc_config[_]
  count(vpc.security_group_ids) == 0
  msg := sprintf(
    "[SC.L2-3.13.1] [GAP-05] %s: Lambda vpc_config must specify at least one security_group_id",
    [resource.address]
  )
}
