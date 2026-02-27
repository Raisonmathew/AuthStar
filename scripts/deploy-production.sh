#!/bin/bash

# Production deployment script for IDaaS Platform
set -e

echo "🚀 Starting production deployment..."

# Configuration
REGISTRY="ghcr.io"
REPO="your-org/idaas-platform"
VERSION=${1:-"latest"}

echo "📦 Building Docker images..."

# Build backend
docker build -t ${REGISTRY}/${REPO}/backend:${VERSION} -f backend/Dockerfile .
docker push ${REGISTRY}/${REPO}/backend:${VERSION}

# Build frontend
docker build -t ${REGISTRY}/${REPO}/frontend:${VERSION} -f frontend/Dockerfile .
docker push ${REGISTRY}/${REPO}/frontend:${VERSION}

echo "✅ Docker images pushed successfully"

echo "🔧 Applying Kubernetes manifests..."

# Create namespace if not exists
kubectl create namespace idaas-platform --dry-run=client -o yaml | kubectl apply -f -

# Apply configurations
kubectl apply -f infrastructure/kubernetes/base/

echo "⏳ Waiting for deployments..."

# Wait for rollout
kubectl rollout status deployment/backend -n idaas-platform --timeout=5m
kubectl rollout status deployment/frontend -n idaas-platform --timeout=5m

echo "✅ Deployment complete!"

# Show status
kubectl get pods -n idaas-platform
kubectl get svc -n idaas-platform
kubectl get ingress -n idaas-platform

echo ""
echo "🎉 IDaaS Platform deployed successfully!"
echo ""
echo "Next steps:"
echo "1. Configure DNS to point to the ingress IP"
echo "2. Verify TLS certificates are issued"
echo "3. Test all endpoints"
echo ""
