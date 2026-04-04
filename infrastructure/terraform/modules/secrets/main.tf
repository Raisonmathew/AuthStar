# ============================================================================
# Secrets Module — AWS Secrets Manager for application secrets
# ============================================================================

variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

locals {
  secret_name = "${var.project_name}/${var.environment}/backend"
}

# ── KMS Key for secrets encryption ──────────────────────────────────────
resource "aws_kms_key" "secrets" {
  description             = "Secrets Manager encryption key for ${local.secret_name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "${var.project_name}-${var.environment}-secrets"
  }
}

# ── Secrets Manager Secret ──────────────────────────────────────────────
resource "aws_secretsmanager_secret" "backend" {
  name        = local.secret_name
  description = "Backend application secrets for ${var.environment}"
  kms_key_id  = aws_kms_key.secrets.arn

  # Allow recovery during deletion window
  recovery_window_in_days = var.environment == "production" ? 30 : 7

  tags = {
    Name = local.secret_name
  }
}

# Initial secret value template — populated manually or via CI/CD
resource "aws_secretsmanager_secret_version" "backend" {
  secret_id = aws_secretsmanager_secret.backend.id

  secret_string = jsonencode({
    database_url                = "CHANGE_ME"
    redis_url                   = "CHANGE_ME"
    jwt_private_key             = "CHANGE_ME"
    jwt_public_key              = "CHANGE_ME"
    compiler_sk_b64             = "CHANGE_ME"
    oauth_token_encryption_key  = "CHANGE_ME"
    sso_encryption_key          = "CHANGE_ME"
    factor_encryption_key       = "CHANGE_ME"
    stripe_secret_key           = "CHANGE_ME"
    stripe_webhook_secret       = "CHANGE_ME"
    sendgrid_api_key            = "CHANGE_ME"
  })

  lifecycle {
    # Don't overwrite secrets that have been manually updated
    ignore_changes = [secret_string]
  }
}

# ── IAM Policy for EKS pods to read secrets (IRSA) ─────────────────────
resource "aws_iam_policy" "secrets_reader" {
  name        = "${var.project_name}-${var.environment}-secrets-reader"
  description = "Allow reading backend secrets from Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [aws_secretsmanager_secret.backend.arn]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = [aws_kms_key.secrets.arn]
      }
    ]
  })
}

# ── Outputs ──────────────────────────────────────────────────────────────
output "secret_arn" {
  value = aws_secretsmanager_secret.backend.arn
}

output "secret_name" {
  value = aws_secretsmanager_secret.backend.name
}

output "secrets_reader_policy_arn" {
  value = aws_iam_policy.secrets_reader.arn
}

output "kms_key_arn" {
  value = aws_kms_key.secrets.arn
}
