package compliance.cmmc.sc13_1_vpc_boundary

import rego.v1

test_lambda_in_vpc_passes if {
  count(deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_lambda_function.intake",
      "type": "aws_lambda_function",
      "change": {"after": {"vpc_config": [{
        "subnet_ids": ["subnet-aaa", "subnet-bbb"],
        "security_group_ids": ["sg-111"]
      }]}}
    }]
  }
}

test_lambda_no_vpc_fails if {
  count(deny) > 0 with input as {
    "resource_changes": [{
      "address": "aws_lambda_function.intake",
      "type": "aws_lambda_function",
      "change": {"after": {"vpc_config": []}}
    }]
  }
}

test_lambda_vpc_no_subnets_fails if {
  count(deny) > 0 with input as {
    "resource_changes": [{
      "address": "aws_lambda_function.intake",
      "type": "aws_lambda_function",
      "change": {"after": {"vpc_config": [{
        "subnet_ids": [],
        "security_group_ids": ["sg-111"]
      }]}}
    }]
  }
}
