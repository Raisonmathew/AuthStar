# ============================================================================
# ElastiCache Module — Redis with replication and encryption
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
  description = "Security group ID allowed to connect to Redis (EKS nodes)"
  type        = string
}

variable "node_type" {
  type = string
}

variable "num_cache_nodes" {
  type = number
}

variable "engine_version" {
  type = string
}

locals {
  cluster_id = "${var.project_name}-${var.environment}"
}

# ── Subnet Group ─────────────────────────────────────────────────────────
resource "aws_elasticache_subnet_group" "main" {
  name       = "${local.cluster_id}-redis-subnet"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "${local.cluster_id}-redis-subnet-group"
  }
}

# ── Security Group ──────────────────────────────────────────────────────
resource "aws_security_group" "redis" {
  name_prefix = "${local.cluster_id}-redis-"
  description = "ElastiCache Redis security group"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${local.cluster_id}-redis-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "redis_ingress" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = var.allowed_security_group_id
  security_group_id        = aws_security_group.redis.id
  description              = "Redis from EKS nodes"
}

# ── Parameter Group ─────────────────────────────────────────────────────
resource "aws_elasticache_parameter_group" "main" {
  family = "redis7"
  name   = "${local.cluster_id}-redis7"

  # Session store tuning
  parameter {
    name  = "maxmemory-policy"
    value = "volatile-lru"
  }

  parameter {
    name  = "notify-keyspace-events"
    value = "Ex"
  }

  tags = {
    Name = "${local.cluster_id}-redis-params"
  }
}

# ── Replication Group (Redis with automatic failover) ───────────────────
resource "aws_elasticache_replication_group" "main" {
  replication_group_id = local.cluster_id
  description          = "IDaaS Redis cluster for ${var.environment}"

  node_type            = var.node_type
  num_cache_clusters   = var.num_cache_nodes
  parameter_group_name = aws_elasticache_parameter_group.main.name
  engine_version       = var.engine_version

  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]

  # HA
  automatic_failover_enabled = var.num_cache_nodes > 1
  multi_az_enabled           = var.num_cache_nodes > 1

  # Encryption
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  # Maintenance
  maintenance_window       = "Mon:05:00-Mon:06:00"
  snapshot_retention_limit = 7
  snapshot_window          = "03:00-04:00"

  # Auto minor version upgrades
  auto_minor_version_upgrade = true

  tags = {
    Name = "${local.cluster_id}-redis"
  }
}

# ── Outputs ──────────────────────────────────────────────────────────────
output "primary_endpoint" {
  value = aws_elasticache_replication_group.main.primary_endpoint_address
}

output "reader_endpoint" {
  value = aws_elasticache_replication_group.main.reader_endpoint_address
}

output "security_group_id" {
  value = aws_security_group.redis.id
}
