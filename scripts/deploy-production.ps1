# Production deployment script for IDaaS Platform (PowerShell)
#
# Builds multi-stage Docker images with cargo-chef dependency caching,
# captures immutable SHA-256 digests, and deploys to Kubernetes.

param(
    [string]$Version = "latest",
    [string]$Org = "your-org",
    [string]$Environment = "production"
)

$ErrorActionPreference = "Stop"

Write-Host "Starting production deployment (version: $Version)..." -ForegroundColor Cyan

# Configuration
$Registry = "ghcr.io"

Write-Host "Building Docker images..." -ForegroundColor Cyan

# Build and push backend (uses cargo-chef for dependency caching)
docker build -t "${Registry}/${Org}/backend:${Version}" -f backend/Dockerfile .
docker push "${Registry}/${Org}/backend:${Version}"
$BackendDigest = (docker inspect --format='{{index .RepoDigests 0}}' "${Registry}/${Org}/backend:${Version}") -replace '^.*@', ''
if ($BackendDigest -notmatch '^sha256:[0-9a-f]{64}$') {
    Write-Error "Failed to capture backend digest (got: '$BackendDigest')"
    exit 1
}
Write-Host "  backend digest: $BackendDigest" -ForegroundColor Gray

# Build and push runtime service
docker build -t "${Registry}/${Org}/runtime:${Version}" -f backend/Dockerfile.runtime .
docker push "${Registry}/${Org}/runtime:${Version}"
$RuntimeDigest = (docker inspect --format='{{index .RepoDigests 0}}' "${Registry}/${Org}/runtime:${Version}") -replace '^.*@', ''
if ($RuntimeDigest -notmatch '^sha256:[0-9a-f]{64}$') {
    Write-Error "Failed to capture runtime digest (got: '$RuntimeDigest')"
    exit 1
}
Write-Host "  runtime digest: $RuntimeDigest" -ForegroundColor Gray

# Build and push frontend
docker build -t "${Registry}/${Org}/frontend:${Version}" -f frontend/Dockerfile .
docker push "${Registry}/${Org}/frontend:${Version}"
$FrontendDigest = (docker inspect --format='{{index .RepoDigests 0}}' "${Registry}/${Org}/frontend:${Version}") -replace '^.*@', ''
if ($FrontendDigest -notmatch '^sha256:[0-9a-f]{64}$') {
    Write-Error "Failed to capture frontend digest (got: '$FrontendDigest')"
    exit 1
}
Write-Host "  frontend digest: $FrontendDigest" -ForegroundColor Gray

Write-Host "Docker images pushed successfully" -ForegroundColor Green

# ── Inject digests into manifests ────────────────────────────────────────────
Write-Host "Injecting immutable image digests into Kubernetes manifests..." -ForegroundColor Cyan

$DeployDir = Join-Path ([System.IO.Path]::GetTempPath()) "idaas-deploy-$(Get-Random)"
New-Item -ItemType Directory -Path $DeployDir -Force | Out-Null
Copy-Item -Recurse "infrastructure/kubernetes/*" $DeployDir

# Substitute placeholders with actual org and digests
$ShortBackend = $BackendDigest -replace '^sha256:', ''
$ShortFrontend = $FrontendDigest -replace '^sha256:', ''
$ShortRuntime = $RuntimeDigest -replace '^sha256:', ''

(Get-Content "$DeployDir/base/backend-deployment.yaml") `
    -replace 'REPLACE_WITH_ORG', $Org `
    -replace 'REPLACE_WITH_ACTUAL_DIGEST', $ShortBackend |
    Set-Content "$DeployDir/base/backend-deployment.yaml"

(Get-Content "$DeployDir/base/frontend-deployment.yaml") `
    -replace 'REPLACE_WITH_ORG', $Org `
    -replace 'REPLACE_WITH_ACTUAL_DIGEST', $ShortFrontend |
    Set-Content "$DeployDir/base/frontend-deployment.yaml"

(Get-Content "$DeployDir/base/runtime-deployment.yaml") `
    -replace 'REPLACE_WITH_ORG', $Org `
    -replace 'REPLACE_WITH_ACTUAL_DIGEST', $ShortRuntime |
    Set-Content "$DeployDir/base/runtime-deployment.yaml"

(Get-Content "$DeployDir/base/db-migration-job.yaml") `
    -replace 'REPLACE_WITH_ORG', $Org `
    -replace 'REPLACE_WITH_ACTUAL_DIGEST', $ShortBackend |
    Set-Content "$DeployDir/base/db-migration-job.yaml"

# Verify no placeholders remain
$remaining = Select-String -Path "$DeployDir/base/*.yaml" -Pattern 'REPLACE_WITH_(ACTUAL_DIGEST|ORG)' -SimpleMatch:$false
if ($remaining) {
    Write-Error "Unreplaced placeholder found in manifests — aborting"
    Remove-Item -Recurse -Force $DeployDir
    exit 1
}

Write-Host "Manifests prepared with immutable digests" -ForegroundColor Green

Write-Host "Applying Kubernetes manifests with kustomize ($Environment)..." -ForegroundColor Cyan

# Create namespace if not exists
kubectl create namespace idaas-platform --dry-run=client -o yaml | kubectl apply -f -

# Apply using kustomize overlay (with real digests)
kubectl apply -k "$DeployDir/overlays/${Environment}/"

# Clean up temp dir
Remove-Item -Recurse -Force $DeployDir

Write-Host "Waiting for deployments..." -ForegroundColor Yellow

# Wait for rollout
kubectl rollout status deployment/backend -n idaas-platform --timeout=5m
kubectl rollout status deployment/frontend -n idaas-platform --timeout=5m
kubectl rollout status deployment/runtime -n idaas-platform --timeout=5m

Write-Host "Deployment complete!" -ForegroundColor Green

# Show status
kubectl get pods -n idaas-platform
kubectl get svc -n idaas-platform
kubectl get ingress -n idaas-platform

Write-Host ""
Write-Host "IDaaS Platform deployed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Configure DNS to point to the ingress IP"
Write-Host "2. Verify TLS certificates are issued"
Write-Host "3. Test all endpoints"
Write-Host ""
