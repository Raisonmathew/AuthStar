# ============================================================================
# Outputs — values needed by CI/CD and Kubernetes
# ============================================================================

# ── VPC ───────────────────────────────────────────────────────────────────
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs (EKS nodes, RDS, Redis)"
  value       = module.vpc.private_subnet_ids
}

output "public_subnet_ids" {
  description = "Public subnet IDs (load balancers)"
  value       = module.vpc.public_subnet_ids
}

# ── EKS ───────────────────────────────────────────────────────────────────
output "eks_cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS API server endpoint"
  value       = module.eks.cluster_endpoint
}

output "eks_cluster_ca_certificate" {
  description = "EKS cluster CA certificate (base64)"
  value       = module.eks.cluster_ca_certificate
  sensitive   = true
}

output "eks_node_role_arn" {
  description = "IAM role ARN for EKS worker nodes"
  value       = module.eks.node_role_arn
}

output "kubeconfig_command" {
  description = "Command to configure kubectl"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
}

output "external_secrets_role_arn" {
  description = "IAM role ARN for external-secrets-operator (annotate SA with this)"
  value       = module.eks.external_secrets_role_arn
}

# ── RDS ───────────────────────────────────────────────────────────────────
output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = module.rds.endpoint
}

output "rds_reader_endpoint" {
  description = "RDS read replica endpoint (if available)"
  value       = module.rds.reader_endpoint
}

output "database_url" {
  description = "Full DATABASE_URL for the backend (store in Secrets Manager)"
  value       = "postgresql://${module.rds.master_username}:<PASSWORD>@${module.rds.endpoint}/${var.rds_db_name}?sslmode=require"
  sensitive   = true
}

# ── ElastiCache ──────────────────────────────────────────────────────────
output "redis_endpoint" {
  description = "ElastiCache Redis primary endpoint"
  value       = module.redis.primary_endpoint
}

output "redis_url" {
  description = "Full REDIS_URL for the backend"
  value       = "redis://${module.redis.primary_endpoint}:6379"
  sensitive   = true
}

# ── Secrets ──────────────────────────────────────────────────────────────
output "secrets_manager_arn" {
  description = "ARN of the Secrets Manager secret for backend"
  value       = module.secrets.secret_arn
}
