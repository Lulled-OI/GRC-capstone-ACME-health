package compliance.cmmc.ac1_5_least_privilege

import rego.v1

test_scoped_actions_pass if {
  count(deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_iam_role_policy.lambda_least_privilege",
      "type": "aws_iam_role_policy",
      "change": {"after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\",\"dynamodb:GetItem\"],\"Resource\":\"*\"}]}"}}
    }]
  }
}

test_dynamodb_wildcard_fails if {
  count(deny) > 0 with input as {
    "resource_changes": [{
      "address": "aws_iam_role_policy.lambda_inline",
      "type": "aws_iam_role_policy",
      "change": {"after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"*\"}]}"}}
    }]
  }
}

test_s3_wildcard_fails if {
  count(deny) > 0 with input as {
    "resource_changes": [{
      "address": "aws_iam_role_policy.lambda_inline",
      "type": "aws_iam_role_policy",
      "change": {"after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:*\"],\"Resource\":\"*\"}]}"}}
    }]
  }
}
