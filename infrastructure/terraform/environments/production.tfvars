# ============================================================================
# Production Environment — HA, Multi-AZ, encrypted
# ============================================================================

environment = "production"
aws_region  = "us-east-1"

# VPC
vpc_cidr           = "10.0.0.0/16"
availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

# EKS — production-grade cluster
eks_cluster_version     = "1.29"
eks_node_instance_types = ["t3.large"]
eks_node_desired_size   = 3
eks_node_min_size       = 3
eks_node_max_size       = 15

# RDS — Multi-AZ, larger instance, more storage
rds_instance_class        = "db.r6g.large"
rds_allocated_storage     = 100
rds_max_allocated_storage = 500
rds_engine_version        = "16.3"
rds_multi_az              = true
rds_db_name               = "idaas"

# Redis — 2-node replication group with failover
redis_node_type       = "cache.r6g.large"
redis_num_cache_nodes = 2
redis_engine_version  = "7.1"

# Domain
domain_name = "idaas.example.com"
