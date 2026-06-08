package compliance.cmmc.sc13_8_tls_enforcement

import rego.v1

test_tls_deny_policy_passes if {
  count(deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_s3_bucket_policy.uploads_tls_only",
      "type": "aws_s3_bucket_policy",
      "change": {"after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyNonTLS\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"}}
    }]
  }
}

test_missing_tls_deny_fails if {
  count(deny) > 0 with input as {
    "resource_changes": [{
      "address": "aws_s3_bucket_policy.uploads_tls_only",
      "type": "aws_s3_bucket_policy",
      "change": {"after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowAll\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"}}
    }]
  }
}
