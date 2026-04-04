# ============================================================================
# IDaaS Platform — Terraform Infrastructure
#
# Provisions a production-grade AWS environment:
#   - VPC with public/private subnets across 3 AZs
#   - EKS cluster with managed node groups
#   - RDS PostgreSQL (Multi-AZ)
#   - ElastiCache Redis (cluster mode)
#   - S3 for Terraform state
#   - IAM roles with least-privilege
#   - Secrets Manager for application secrets
#
# Usage:
#   cd infrastructure/terraform
#   terraform init
#   terraform plan -var-file=environments/production.tfvars
#   terraform apply -var-file=environments/production.tfvars
# ============================================================================

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Remote state — uncomment after creating the S3 bucket
  # backend "s3" {
  #   bucket         = "idaas-terraform-state"
  #   key            = "infrastructure/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "idaas-terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "idaas-platform"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Configure kubernetes provider after EKS is created
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_ca_certificate)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_ca_certificate)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

# ============================================================================
# Module Composition
# ============================================================================

# ── VPC ───────────────────────────────────────────────────────────────────
module "vpc" {
  source = "./modules/vpc"

  project_name       = var.project_name
  environment        = var.environment
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
}

# ── EKS ───────────────────────────────────────────────────────────────────
module "eks" {
  source = "./modules/eks"

  project_name             = var.project_name
  environment              = var.environment
  cluster_version          = var.eks_cluster_version
  vpc_id                   = module.vpc.vpc_id
  private_subnet_ids       = module.vpc.private_subnet_ids
  node_instance_types      = var.eks_node_instance_types
  node_desired_size        = var.eks_node_desired_size
  node_min_size            = var.eks_node_min_size
  node_max_size            = var.eks_node_max_size
  secrets_reader_policy_arn = module.secrets.secrets_reader_policy_arn
}

# ── RDS PostgreSQL ───────────────────────────────────────────────────────
module "rds" {
  source = "./modules/rds"

  project_name              = var.project_name
  environment               = var.environment
  vpc_id                    = module.vpc.vpc_id
  private_subnet_ids        = module.vpc.private_subnet_ids
  allowed_security_group_id = module.eks.node_security_group_id
  instance_class            = var.rds_instance_class
  allocated_storage         = var.rds_allocated_storage
  max_allocated_storage     = var.rds_max_allocated_storage
  engine_version            = var.rds_engine_version
  multi_az                  = var.rds_multi_az
  db_name                   = var.rds_db_name
}

# ── ElastiCache Redis ───────────────────────────────────────────────────
module "redis" {
  source = "./modules/redis"

  project_name              = var.project_name
  environment               = var.environment
  vpc_id                    = module.vpc.vpc_id
  private_subnet_ids        = module.vpc.private_subnet_ids
  allowed_security_group_id = module.eks.node_security_group_id
  node_type                 = var.redis_node_type
  num_cache_nodes           = var.redis_num_cache_nodes
  engine_version            = var.redis_engine_version
}

# ── Secrets Manager ──────────────────────────────────────────────────────
module "secrets" {
  source = "./modules/secrets"

  project_name = var.project_name
  environment  = var.environment
}

# ── Helm: NGINX Ingress Controller ──────────────────────────────────────
resource "helm_release" "nginx_ingress" {
  name       = "ingress-nginx"
  repository = "https://kubernetes.github.io/ingress-nginx"
  chart      = "ingress-nginx"
  namespace  = "ingress-nginx"
  version    = "4.10.0"

  create_namespace = true

  set {
    name  = "controller.replicaCount"
    value = "2"
  }

  set {
    name  = "controller.service.type"
    value = "LoadBalancer"
  }

  set {
    name  = "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-type"
    value = "nlb"
  }

  set {
    name  = "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-scheme"
    value = "internet-facing"
  }

  set {
    name  = "controller.metrics.enabled"
    value = "true"
  }

  depends_on = [module.eks]
}

# ── Helm: cert-manager for TLS certificates ────────────────────────────
resource "helm_release" "cert_manager" {
  name       = "cert-manager"
  repository = "https://charts.jetstack.io"
  chart      = "cert-manager"
  namespace  = "cert-manager"
  version    = "1.14.0"

  create_namespace = true

  set {
    name  = "installCRDs"
    value = "true"
  }

  depends_on = [module.eks]
}

# ── Helm: external-secrets-operator ─────────────────────────────────────
resource "helm_release" "external_secrets" {
  name       = "external-secrets"
  repository = "https://charts.external-secrets.io"
  chart      = "external-secrets"
  namespace  = "external-secrets-system"
  version    = "0.9.0"

  create_namespace = true

  set {
    name  = "serviceAccount.create"
    value = "true"
  }

  set {
    name  = "serviceAccount.name"
    value = "external-secrets-sa"
  }

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.eks.external_secrets_role_arn
  }

  depends_on = [module.eks]
}

# ── Helm: Prometheus + Grafana for monitoring ───────────────────────────
resource "helm_release" "kube_prometheus_stack" {
  name       = "kube-prometheus-stack"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  namespace  = "monitoring"
  version    = "56.0.0"

  create_namespace = true

  set {
    name  = "prometheus.prometheusSpec.retention"
    value = "15d"
  }

  set {
    name  = "grafana.adminPassword"
    value = var.grafana_admin_password
  }

  depends_on = [module.eks]
}
