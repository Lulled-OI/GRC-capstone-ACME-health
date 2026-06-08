######################################################################
# KMS — Customer-managed keys for PHI data stores.
# Closes GAP-01 (S3) and GAP-02 (DynamoDB) by placing encryption keys
# under customer custody with mandatory annual rotation.
# CMMC SC.L2-3.13.11: FIPS-validated cryptography for CUI.
######################################################################

resource "aws_kms_key" "phi" {
  description             = "acme-health-intake: CMK for PHI data stores (S3 + DynamoDB)"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowLambdaEncryptDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda.arn
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "phi" {
  name          = "alias/acme-health-intake-phi"
  target_key_id = aws_kms_key.phi.key_id
}

resource "aws_kms_key" "evidence" {
  description             = "acme-health-intake: CMK for the GRC evidence vault"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/acme-health-intake-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}

data "aws_caller_identity" "current" {}
