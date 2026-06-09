package compliance.cmmc.sc13_11_kms_encryption

import rego.v1

# --- S3 tests ---

test_s3_kms_with_cmk_passes if {
  count(deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
      "type": "aws_s3_bucket_server_side_encryption_configuration",
      "change": {"after": {"rule": [{
        "apply_server_side_encryption_by_default": [{
          "sse_algorithm": "aws:kms",
          "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc"
        }]
      }]}}
    }]
  }
}

test_s3_sse_s3_fails if {
  count(deny) > 0 with input as {
    "resource_changes": [{
      "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
      "type": "aws_s3_bucket_server_side_encryption_configuration",
      "change": {"after": {"rule": [{
        "apply_server_side_encryption_by_default": [{
          "sse_algorithm": "AES256",
          "kms_master_key_id": null
        }]
      }]}}
    }]
  }
}

test_s3_kms_without_cmk_passes_plan_time if {
  # kms_master_key_id may be null/absent in plan JSON (known after apply)
  # algorithm check is sufficient at plan time
  count(deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
      "type": "aws_s3_bucket_server_side_encryption_configuration",
      "change": {"after": {"rule": [{
        "apply_server_side_encryption_by_default": [{
          "sse_algorithm": "aws:kms"
        }]
      }]}}
    }]
  }
}

# --- DynamoDB tests ---

test_dynamodb_with_cmk_passes if {
  count(deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_dynamodb_table.intake",
      "type": "aws_dynamodb_table",
      "change": {"after": {
        "server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/abc"}]
      }}
    }]
  }
}

test_dynamodb_no_sse_fails if {
  count(deny) > 0 with input as {
    "resource_changes": [{
      "address": "aws_dynamodb_table.intake",
      "type": "aws_dynamodb_table",
      "change": {"after": {
        "server_side_encryption": null
      }}
    }]
  }
}
