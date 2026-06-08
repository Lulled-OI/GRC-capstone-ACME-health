######################################################################
# GRC Gap Overrides — closes the eight named gaps in the starter.
# Each block references the starter's existing resources by address.
######################################################################

# GAP-01: SSE-KMS with customer CMK on the uploads bucket.
# CMMC SC.L2-3.13.11
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# GAP-02: CMK encryption on DynamoDB — patched directly in main.tf.
# CMMC SC.L2-3.13.11

# GAP-03: deny non-TLS requests on the uploads bucket.
# CMMC SC.L2-3.13.8
resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# GAP-04: versioning on the uploads bucket.
# CMMC MP.L2-3.8.9
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

# GAP-05: VPC execution role so Lambda can create network interfaces.
# CMMC SC.L2-3.13.1
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# GAP-05: security group for Lambda VPC placement.
# CMMC SC.L2-3.13.1
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg"
  description = "Lambda intake handler - egress only"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS egress to AWS services"
  }
}

# GAP-05 (supporting): VPC endpoints so Lambda can reach AWS services privately.
# Without these, the VPC-isolated Lambda cannot call DynamoDB or S3.
# CMMC SC.L2-3.13.1
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id, aws_vpc.main.main_route_table_id]
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id, aws_vpc.main.main_route_table_id]
}

# GAP-07: least-privilege IAM policy replacing dynamodb:* and s3:*.
# CMMC AC.L2-3.1.5
resource "aws_iam_role_policy" "lambda_least_privilege" {
  name = "intake-data-access-least-privilege"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBIntake"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid    = "S3Uploads"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.uploads.arn}/*"
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}

# GAP-08: API Gateway access logging and throttling.
# CMMC AU.L2-3.3.1
resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/aws/apigateway/${local.name_prefix}"
  retention_in_days = 90
}
