package compliance.cmmc.au3_1_audit_logging

import rego.v1

test_logging_configured_passes if {
  count(deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_apigatewayv2_stage.default",
      "type": "aws_apigatewayv2_stage",
      "change": {"after": {"access_log_settings": [{
        "destination_arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/acme-health-intake"
      }]}}
    }]
  }
}

test_no_logging_fails if {
  count(deny) > 0 with input as {
    "resource_changes": [{
      "address": "aws_apigatewayv2_stage.default",
      "type": "aws_apigatewayv2_stage",
      "change": {"after": {"access_log_settings": []}}
    }]
  }
}

test_logging_no_destination_fails if {
  count(deny) > 0 with input as {
    "resource_changes": [{
      "address": "aws_apigatewayv2_stage.default",
      "type": "aws_apigatewayv2_stage",
      "change": {"after": {"access_log_settings": [{}]}}
    }]
  }
}
