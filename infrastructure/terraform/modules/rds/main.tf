# ============================================================================
# RDS Module — PostgreSQL with Multi-AZ and encryption
# ============================================================================

variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "allowed_security_group_id" {
  description = "Security group ID allowed to connect to RDS (EKS nodes)"
  type        = string
}

variable "instance_class" {
  type = string
}

variable "allocated_storage" {
  type = number
}

variable "max_allocated_storage" {
  type = number
}

variable "engine_version" {
  type = string
}

variable "multi_az" {
  type = bool
}

variable "db_name" {
  type = string
}

locals {
  identifier = "${var.project_name}-${var.environment}"
}

# ── Subnet Group ─────────────────────────────────────────────────────────
resource "aws_db_subnet_group" "main" {
  name       = "${local.identifier}-db-subnet"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "${local.identifier}-db-subnet-group"
  }
}

# ── Security Group ──────────────────────────────────────────────────────
resource "aws_security_group" "rds" {
  name_prefix = "${local.identifier}-rds-"
  description = "RDS PostgreSQL security group"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${local.identifier}-rds-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "rds_ingress" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = var.allowed_security_group_id
  security_group_id        = aws_security_group.rds.id
  description              = "PostgreSQL from EKS nodes"
}

# ── KMS Key for encryption at rest ──────────────────────────────────────
resource "aws_kms_key" "rds" {
  description             = "RDS encryption key for ${local.identifier}"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "${local.identifier}-rds"
  }
}

# ── Parameter Group ─────────────────────────────────────────────────────
resource "aws_db_parameter_group" "main" {
  family = "postgres16"
  name   = "${local.identifier}-pg16"

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  # Connection pooling — PgBouncer in k8s handles this, but set sane defaults
  parameter {
    name  = "max_connections"
    value = "200"
  }

  parameter {
    name  = "shared_buffers"
    value = "{DBInstanceClassMemory/4}"
  }

  tags = {
    Name = "${local.identifier}-params"
  }
}

# ── RDS Instance ─────────────────────────────────────────────────────────
resource "aws_db_instance" "main" {
  identifier = local.identifier

  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn

  db_name  = var.db_name
  username = "idaas_admin"
  # Password managed via Secrets Manager (see secrets module)
  manage_master_user_password = true

  multi_az               = var.multi_az
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.main.name

  # Backup
  backup_retention_period = 14
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  # Protection
  deletion_protection       = var.environment == "production"
  skip_final_snapshot       = var.environment != "production"
  final_snapshot_identifier = var.environment == "production" ? "${local.identifier}-final" : null
  copy_tags_to_snapshot     = true

  # Monitoring
  monitoring_interval          = 60
  monitoring_role_arn          = aws_iam_role.rds_monitoring.arn
  performance_insights_enabled          = true
  performance_insights_retention_period = 31

  # Auto minor version upgrades
  auto_minor_version_upgrade = true

  tags = {
    Name = local.identifier
  }
}

# ── Enhanced Monitoring IAM Role ─────────────────────────────────────────
resource "aws_iam_role" "rds_monitoring" {
  name = "${local.identifier}-rds-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "monitoring.rds.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
  role       = aws_iam_role.rds_monitoring.name
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.identifier}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# ── Outputs ──────────────────────────────────────────────────────────────
output "endpoint" {
  value = aws_db_instance.main.endpoint
}

output "reader_endpoint" {
  value = aws_db_instance.main.endpoint # For a single instance; use aws_rds_cluster for Aurora
}

output "master_username" {
  value = aws_db_instance.main.username
}

output "security_group_id" {
  value = aws_security_group.rds.id
}
