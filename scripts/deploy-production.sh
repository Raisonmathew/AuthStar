#!/bin/bash
# Production deployment script for IDaaS Platform
#
# CRITICAL-12 FIX: Captures immutable SHA-256 digests after docker push and
# substitutes them into Kubernetes manifests before kubectl apply.
# This ensures the exact image that was built is deployed — never a mutable tag.
#
# Usage:
#   ./scripts/deploy-production.sh [VERSION] [ORG]
#
# Examples:
#   ./scripts/deploy-production.sh 1.2.0 my-github-org
#   VERSION=1.2.0 ORG=my-github-org ./scripts/deploy-production.sh

set -euo pipefail

echo "🚀 Starting production deployment..."

# Configuration
REGISTRY="ghcr.io"
ORG="${2:-${ORG:-"your-org"}}"
REPO="${REGISTRY}/${ORG}/idaas-platform"
VERSION="${1:-${VERSION:-"latest"}}"

# Validate required tools
for tool in docker kubectl sed grep; do
    if ! command -v "$tool" &>/dev/null; then
        echo "ERROR: Required tool '$tool' not found in PATH"
        exit 1
    fi
done

echo "📦 Building and pushing Docker images (version: ${VERSION})..."

# ── Backend ──────────────────────────────────────────────────────────────────
BACKEND_TAG="${REGISTRY}/${ORG}/backend:${VERSION}"
docker build -t "${BACKEND_TAG}" -f backend/Dockerfile .
docker push "${BACKEND_TAG}"

# Capture the immutable digest (sha256:<hex>) from the registry
BACKEND_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${BACKEND_TAG}" \
    | sed 's/.*@//')
if [[ ! "${BACKEND_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "ERROR: Failed to capture backend digest (got: '${BACKEND_DIGEST}')"
    exit 1
fi
echo "  backend digest: ${BACKEND_DIGEST}"

# ── Frontend ─────────────────────────────────────────────────────────────────
FRONTEND_TAG="${REGISTRY}/${ORG}/frontend:${VERSION}"
docker build -t "${FRONTEND_TAG}" -f frontend/Dockerfile .
docker push "${FRONTEND_TAG}"

FRONTEND_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${FRONTEND_TAG}" \
    | sed 's/.*@//')
if [[ ! "${FRONTEND_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "ERROR: Failed to capture frontend digest (got: '${FRONTEND_DIGEST}')"
    exit 1
fi
echo "  frontend digest: ${FRONTEND_DIGEST}"

# ── Runtime ──────────────────────────────────────────────────────────────────
RUNTIME_TAG="${REGISTRY}/${ORG}/runtime:${VERSION}"
docker build -t "${RUNTIME_TAG}" -f backend/Dockerfile.runtime .
docker push "${RUNTIME_TAG}"

RUNTIME_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${RUNTIME_TAG}" \
    | sed 's/.*@//')
if [[ ! "${RUNTIME_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "ERROR: Failed to capture runtime digest (got: '${RUNTIME_DIGEST}')"
    exit 1
fi
echo "  runtime digest: ${RUNTIME_DIGEST}"

echo "✅ Docker images pushed successfully"

# ── Inject digests into manifests ────────────────────────────────────────────
echo "🔏 Injecting immutable image digests into Kubernetes manifests..."

# Work on copies so the originals stay as templates with placeholders
DEPLOY_DIR=$(mktemp -d)
cp -r infrastructure/kubernetes/base/. "${DEPLOY_DIR}/"

sed -i \
    -e "s|REPLACE_WITH_ORG|${ORG}|g" \
    -e "s|REPLACE_WITH_ACTUAL_DIGEST|${BACKEND_DIGEST#sha256:}|g" \
    "${DEPLOY_DIR}/backend-deployment.yaml"

sed -i \
    -e "s|REPLACE_WITH_ORG|${ORG}|g" \
    -e "s|REPLACE_WITH_ACTUAL_DIGEST|${FRONTEND_DIGEST#sha256:}|g" \
    "${DEPLOY_DIR}/frontend-deployment.yaml"

sed -i \
    -e "s|REPLACE_WITH_ORG|${ORG}|g" \
    -e "s|REPLACE_WITH_ACTUAL_DIGEST|${RUNTIME_DIGEST#sha256:}|g" \
    "${DEPLOY_DIR}/runtime-deployment.yaml"

# Verify no placeholder remains
if grep -rE "REPLACE_WITH_(ACTUAL_DIGEST|ORG)" "${DEPLOY_DIR}/"; then
    echo "ERROR: Unreplaced placeholder found in manifests — aborting"
    rm -rf "${DEPLOY_DIR}"
    exit 1
fi

echo "✅ Manifests prepared:"
grep "image:" "${DEPLOY_DIR}"/*.yaml | grep -v "^#"

# ── Apply to Kubernetes ───────────────────────────────────────────────────────
echo "🔧 Applying Kubernetes manifests..."

# Create namespace if not exists
kubectl create namespace idaas-platform --dry-run=client -o yaml | kubectl apply -f -

# Apply from the temp directory (with real digests, not placeholders)
kubectl apply -f "${DEPLOY_DIR}/"

# Clean up temp dir
rm -rf "${DEPLOY_DIR}"

echo "⏳ Waiting for rollouts..."

kubectl rollout status deployment/backend  -n idaas-platform --timeout=5m
kubectl rollout status deployment/frontend -n idaas-platform --timeout=5m
kubectl rollout status deployment/runtime  -n idaas-platform --timeout=5m

echo "✅ Deployment complete!"

# Show status
echo ""
echo "=== Deployed image digests ==="
kubectl get deployment backend  -n idaas-platform -o jsonpath='{.spec.template.spec.containers[0].image}' && echo
kubectl get deployment frontend -n idaas-platform -o jsonpath='{.spec.template.spec.containers[0].image}' && echo
kubectl get deployment runtime  -n idaas-platform -o jsonpath='{.spec.template.spec.containers[0].image}' && echo
echo ""

kubectl get pods    -n idaas-platform
kubectl get svc     -n idaas-platform
kubectl get ingress -n idaas-platform

echo ""
echo "🎉 IDaaS Platform deployed successfully!"
echo ""
echo "Next steps:"
echo "1. Configure DNS to point to the ingress IP"
echo "2. Verify TLS certificates are issued"
echo "3. Test all endpoints"
echo ""
