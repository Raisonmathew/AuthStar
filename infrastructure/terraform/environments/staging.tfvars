# ============================================================================
# Staging Environment — cost-optimized, single-AZ where possible
# ============================================================================

environment = "staging"
aws_region  = "us-east-1"

# VPC
vpc_cidr           = "10.1.0.0/16"
availability_zones = ["us-east-1a", "us-east-1b"]

# EKS — smaller cluster for staging
eks_cluster_version     = "1.29"
eks_node_instance_types = ["t3.medium"]
eks_node_desired_size   = 2
eks_node_min_size       = 1
eks_node_max_size       = 5

# RDS — single-AZ, smaller instance
rds_instance_class        = "db.t3.medium"
rds_allocated_storage     = 20
rds_max_allocated_storage = 50
rds_engine_version        = "16.3"
rds_multi_az              = false
rds_db_name               = "idaas"

# Redis — single node (no replication)
redis_node_type       = "cache.t3.micro"
redis_num_cache_nodes = 1
redis_engine_version  = "7.1"

# Domain
domain_name = "staging.idaas.example.com"
