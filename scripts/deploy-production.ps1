# Production deployment script for IDaaS Platform (PowerShell)

param(
    [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"

Write-Host "🚀 Starting production deployment..." -ForegroundColor Cyan

# Configuration
$Registry = "ghcr.io"
$Repo = "your-org/idaas-platform"

Write-Host "📦 Building Docker images..." -ForegroundColor Cyan

# Build backend
docker build -t "${Registry}/${Repo}/backend:${Version}" -f backend/Dockerfile .
docker push "${Registry}/${Repo}/backend:${Version}"

# Build frontend
docker build -t "${Registry}/${Repo}/frontend:${Version}" -f frontend/Dockerfile .
docker push "${Registry}/${Repo}/frontend:${Version}"

Write-Host "✅ Docker images pushed successfully" -ForegroundColor Green

Write-Host "🔧 Applying Kubernetes manifests..." -ForegroundColor Cyan

# Create namespace if not exists
kubectl create namespace idaas-platform --dry-run=client -o yaml | kubectl apply -f -

# Apply configurations
kubectl apply -f infrastructure/kubernetes/base/

Write-Host "⏳ Waiting for deployments..." -ForegroundColor Yellow

# Wait for rollout
kubectl rollout status deployment/backend -n idaas-platform --timeout=5m
kubectl rollout status deployment/frontend -n idaas-platform --timeout=5m

Write-Host "✅ Deployment complete!" -ForegroundColor Green

# Show status
kubectl get pods -n idaas-platform
kubectl get svc -n idaas-platform
kubectl get ingress -n idaas-platform

Write-Host ""
Write-Host "🎉 IDaaS Platform deployed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Configure DNS to point to the ingress IP"
Write-Host "2. Verify TLS certificates are issued"
Write-Host "3. Test all endpoints"
Write-Host ""
