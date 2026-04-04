# ============================================================================
# IDaaS Platform — Unified Deployment Script (PowerShell)
#
# Supports three environments:
#   local       — Docker Compose (postgres, redis, backend, frontend, runtime)
#   staging     — Build images, push to registry, deploy to K8s staging overlay
#   production  — Build images, push to registry, deploy to K8s production overlay
#
# Usage:
#   .\scripts\deploy.ps1 -Environment local
#   .\scripts\deploy.ps1 -Environment staging -Version 1.2.0 -Org my-org
#   .\scripts\deploy.ps1 -Environment production -Version 1.2.0 -Org my-org
#
# Prerequisites:
#   local:      Docker / Podman running
#   staging:    Docker, kubectl configured for staging cluster, ghcr.io login
#   production: Docker, kubectl configured for production cluster, ghcr.io login
# ============================================================================

param(
    [Parameter(Mandatory)]
    [ValidateSet("local", "staging", "production")]
    [string]$Environment,

    [string]$Version = "latest",
    [string]$Org = "your-org",
    [switch]$SkipBuild,
    [switch]$SkipMigrations
)

$ErrorActionPreference = "Stop"
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptRoot

Push-Location $RepoRoot

try {
    # ========================================================================
    # LOCAL DEPLOYMENT
    # ========================================================================
    if ($Environment -eq "local") {
        Write-Host "=== IDaaS Local Deployment ===" -ForegroundColor Cyan
        Write-Host ""

        # ── Detect container engine ──────────────────────────────────────
        $engine = $null
        $compose = $null

        if (Get-Command docker -ErrorAction SilentlyContinue) {
            $engine = "docker"
            try { docker info 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw } }
            catch { Write-Error "Docker is installed but not running. Start Docker Desktop and retry."; exit 1 }
        }
        elseif (Get-Command podman -ErrorAction SilentlyContinue) {
            $engine = "podman"
            try { podman info 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw } }
            catch { Write-Error "Podman is installed but not running. Run 'podman machine start'."; exit 1 }
        }
        else {
            Write-Error "No container engine found. Install Docker Desktop or Podman."
            exit 1
        }
        Write-Host "[OK] Container engine: $engine" -ForegroundColor Green

        # Detect compose command
        if ($engine -eq "docker") {
            # Prefer 'docker compose' (V2 plugin) over standalone 'docker-compose'
            $testCompose = docker compose version 2>&1
            if ($LASTEXITCODE -eq 0) { $compose = "docker compose" }
            elseif (Get-Command docker-compose -ErrorAction SilentlyContinue) { $compose = "docker-compose" }
        }
        if (-not $compose -and (Get-Command podman-compose -ErrorAction SilentlyContinue)) {
            $compose = "podman-compose"
        }
        if (-not $compose) {
            Write-Error "No compose tool found. Install 'docker compose' plugin or 'podman-compose'."
            exit 1
        }
        Write-Host "[OK] Compose command: $compose" -ForegroundColor Green

        $ComposeFile = "infrastructure\docker-compose\docker-compose.dev.yml"

        # ── Start infrastructure services ────────────────────────────────
        Write-Host ""
        Write-Host "Starting infrastructure services (postgres, redis, mailhog, minio)..." -ForegroundColor Cyan

        if ($compose -eq "docker compose") {
            docker compose -f $ComposeFile up -d postgres redis mailhog minio
        }
        else {
            & $compose -f $ComposeFile up -d postgres redis mailhog minio
        }

        # ── Wait for database health ────────────────────────────────────
        Write-Host "Waiting for PostgreSQL..." -ForegroundColor Yellow
        $maxRetries = 30
        $healthy = $false
        for ($i = 0; $i -lt $maxRetries; $i++) {
            $result = & $engine exec idaas-postgres-dev pg_isready -U idaas_user -d idaas 2>&1
            if ($LASTEXITCODE -eq 0) { $healthy = $true; break }
            Start-Sleep -Seconds 1
        }
        if (-not $healthy) { Write-Error "PostgreSQL failed to start within ${maxRetries}s"; exit 1 }
        Write-Host "[OK] PostgreSQL is ready" -ForegroundColor Green

        # ── Wait for Redis health ────────────────────────────────────────
        $result = & $engine exec idaas-redis-dev redis-cli ping 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Redis is ready" -ForegroundColor Green
        }
        else {
            Write-Host "[WARN] Redis ping failed, it may still be starting" -ForegroundColor Yellow
        }

        # ── Create .env if missing ───────────────────────────────────────
        if (-not (Test-Path backend\.env)) {
            if (Test-Path backend\.env.example) {
                Copy-Item backend\.env.example backend\.env
                # Patch default DATABASE_URL to match compose credentials
                (Get-Content backend\.env) `
                    -replace 'postgres://idaas_user:password@', 'postgres://idaas_user:dev_password_change_me@' |
                    Set-Content backend\.env
                Write-Host "[OK] Created backend\.env from template (review and update secrets)" -ForegroundColor Green
            }
            else {
                Write-Error "backend\.env.example not found. Cannot create .env file."
                exit 1
            }
        }

        if (-not (Test-Path frontend\.env)) {
            if (Test-Path frontend\.env.example) {
                Copy-Item frontend\.env.example frontend\.env
            }
            else {
                "VITE_API_URL=http://localhost:3000" | Out-File -Encoding UTF8 frontend\.env
            }
            Write-Host "[OK] Created frontend\.env" -ForegroundColor Green
        }

        # ── Run database migrations ──────────────────────────────────────
        if (-not $SkipMigrations) {
            if (Get-Command sqlx -ErrorAction SilentlyContinue) {
                Write-Host "Running database migrations..." -ForegroundColor Cyan
                $env:DATABASE_URL = "postgres://idaas_user:dev_password_change_me@localhost:5432/idaas"
                Push-Location backend
                sqlx migrate run --source crates/db_migrations/migrations
                Pop-Location
                Write-Host "[OK] Migrations complete" -ForegroundColor Green
            }
            else {
                Write-Host "[SKIP] sqlx-cli not installed. Run: cargo install sqlx-cli --no-default-features --features postgres" -ForegroundColor Yellow
            }
        }

        # ── Generate JWT keys if missing ─────────────────────────────────
        if (-not (Test-Path backend\.keys\private.pem)) {
            if (Get-Command openssl -ErrorAction SilentlyContinue) {
                New-Item -ItemType Directory -Force -Path backend\.keys | Out-Null
                openssl ecparam -genkey -name prime256v1 -noout -out backend\.keys\private.pem
                openssl ec -in backend\.keys\private.pem -pubout -out backend\.keys\public.pem
                Write-Host "[OK] JWT keys generated in backend\.keys\" -ForegroundColor Green
            }
            else {
                Write-Host "[SKIP] openssl not found — generate JWT keys manually" -ForegroundColor Yellow
            }
        }

        # ── Install frontend dependencies ────────────────────────────────
        if (Test-Path frontend\package.json) {
            if (-not (Test-Path frontend\node_modules)) {
                Write-Host "Installing frontend dependencies..." -ForegroundColor Cyan
                Push-Location frontend; npm install; Pop-Location
                Write-Host "[OK] Frontend deps installed" -ForegroundColor Green
            }
        }

        # ── Print summary ────────────────────────────────────────────────
        Write-Host ""
        Write-Host "=== Local deployment ready ===" -ForegroundColor Green
        Write-Host ""
        Write-Host "Start the application:" -ForegroundColor Cyan
        Write-Host "  Backend:  cd backend && cargo run --bin api_server"
        Write-Host "  Runtime:  cd backend && cargo run --bin runtime_service"
        Write-Host "  Frontend: cd frontend && npm run dev"
        Write-Host ""
        Write-Host "Or run everything in Docker:" -ForegroundColor Cyan
        if ($compose -eq "docker compose") {
            Write-Host "  docker compose -f $ComposeFile up -d"
        }
        else {
            Write-Host "  $compose -f $ComposeFile up -d"
        }
        Write-Host ""
        Write-Host "Services:" -ForegroundColor Cyan
        Write-Host "  API:             http://localhost:3000"
        Write-Host "  Frontend:        http://localhost:5173 (vite) or http://localhost:8080 (docker)"
        Write-Host "  PostgreSQL:      localhost:5432"
        Write-Host "  Redis:           localhost:6379"
        Write-Host "  MailHog UI:      http://localhost:8025"
        Write-Host "  MinIO Console:   http://localhost:9001"
        Write-Host ""
        Write-Host "Manage:" -ForegroundColor Cyan
        Write-Host "  Stop:    $compose -f $ComposeFile down"
        Write-Host "  Logs:    $compose -f $ComposeFile logs -f"
        Write-Host "  Reset:   $compose -f $ComposeFile down -v"
        Write-Host ""
        return
    }

    # ========================================================================
    # STAGING / PRODUCTION DEPLOYMENT
    # ========================================================================
    Write-Host "=== IDaaS $($Environment.ToUpper()) Deployment (v$Version) ===" -ForegroundColor Cyan
    Write-Host ""

    # ── Validate prerequisites ───────────────────────────────────────────
    foreach ($tool in @("docker", "kubectl")) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            Write-Error "'$tool' is required but not found in PATH."
            exit 1
        }
    }

    # Verify kubectl can reach the cluster
    kubectl cluster-info 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "kubectl cannot connect to a cluster. Configure kubeconfig first."
        exit 1
    }
    Write-Host "[OK] Kubernetes cluster is accessible" -ForegroundColor Green

    $Registry = "ghcr.io"

    # ── Build and push Docker images ─────────────────────────────────────
    if (-not $SkipBuild) {
        Write-Host ""
        Write-Host "Building and pushing Docker images..." -ForegroundColor Cyan

        $images = @(
            @{ Name = "backend";  Dockerfile = "backend/Dockerfile" },
            @{ Name = "runtime";  Dockerfile = "backend/Dockerfile.runtime" },
            @{ Name = "frontend"; Dockerfile = "frontend/Dockerfile" }
        )

        $digests = @{}

        foreach ($img in $images) {
            $tag = "${Registry}/${Org}/$($img.Name):${Version}"
            Write-Host "  Building $($img.Name)..." -ForegroundColor Gray

            docker build -t $tag -f $img.Dockerfile .
            if ($LASTEXITCODE -ne 0) { Write-Error "Failed to build $($img.Name)"; exit 1 }

            docker push $tag
            if ($LASTEXITCODE -ne 0) { Write-Error "Failed to push $($img.Name)"; exit 1 }

            $digest = (docker inspect --format='{{index .RepoDigests 0}}' $tag) -replace '^.*@', ''
            if ($digest -notmatch '^sha256:[0-9a-f]{64}$') {
                Write-Error "Failed to capture $($img.Name) digest (got: '$digest')"
                exit 1
            }
            $digests[$img.Name] = $digest
            Write-Host "  $($img.Name) digest: $digest" -ForegroundColor Gray
        }

        Write-Host "[OK] All images pushed" -ForegroundColor Green
    }
    else {
        Write-Host "[SKIP] Build skipped (-SkipBuild). Using existing images." -ForegroundColor Yellow
        # When skipping build, pull digests from the registry
        $images = @("backend", "runtime", "frontend")
        $digests = @{}
        foreach ($name in $images) {
            $tag = "${Registry}/${Org}/${name}:${Version}"
            $digest = (docker inspect --format='{{index .RepoDigests 0}}' $tag 2>$null) -replace '^.*@', ''
            if ($digest -notmatch '^sha256:[0-9a-f]{64}$') {
                Write-Error "Cannot find digest for $tag. Build first or pull the image."
                exit 1
            }
            $digests[$name] = $digest
        }
    }

    # ── Inject digests into manifests ────────────────────────────────────
    Write-Host ""
    Write-Host "Preparing Kubernetes manifests..." -ForegroundColor Cyan

    $DeployDir = Join-Path ([System.IO.Path]::GetTempPath()) "idaas-deploy-$(Get-Random)"
    New-Item -ItemType Directory -Path $DeployDir -Force | Out-Null
    Copy-Item -Recurse "infrastructure\kubernetes\*" $DeployDir

    $shortBackend  = ($digests["backend"]  -replace '^sha256:', '')
    $shortRuntime  = ($digests["runtime"]  -replace '^sha256:', '')
    $shortFrontend = ($digests["frontend"] -replace '^sha256:', '')

    # Backend deployment + migration job use backend digest
    foreach ($file in @("base\backend-deployment.yaml", "base\db-migration-job.yaml")) {
        $path = Join-Path $DeployDir $file
        if (Test-Path $path) {
            (Get-Content $path) `
                -replace 'REPLACE_WITH_ORG', $Org `
                -replace 'REPLACE_WITH_ACTUAL_DIGEST', $shortBackend |
                Set-Content $path
        }
    }

    # Frontend
    $fePath = Join-Path $DeployDir "base\frontend-deployment.yaml"
    (Get-Content $fePath) `
        -replace 'REPLACE_WITH_ORG', $Org `
        -replace 'REPLACE_WITH_ACTUAL_DIGEST', $shortFrontend |
        Set-Content $fePath

    # Runtime
    $rtPath = Join-Path $DeployDir "base\runtime-deployment.yaml"
    (Get-Content $rtPath) `
        -replace 'REPLACE_WITH_ORG', $Org `
        -replace 'REPLACE_WITH_ACTUAL_DIGEST', $shortRuntime |
        Set-Content $rtPath

    # Verify no placeholders remain
    $remaining = Select-String -Path "$DeployDir\base\*.yaml" -Pattern 'REPLACE_WITH_(ACTUAL_DIGEST|ORG)'
    if ($remaining) {
        Write-Error "Unreplaced placeholder found in manifests"
        Remove-Item -Recurse -Force $DeployDir
        exit 1
    }
    Write-Host "[OK] Manifests prepared with immutable digests" -ForegroundColor Green

    # ── Run database migration ───────────────────────────────────────────
    if (-not $SkipMigrations) {
        Write-Host ""
        Write-Host "Running database migration job..." -ForegroundColor Cyan
        kubectl apply -f "$DeployDir\base\db-migration-job.yaml"
        kubectl wait --for=condition=complete job/db-migrate -n idaas-platform --timeout=120s 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] Database migration complete" -ForegroundColor Green
        }
        else {
            Write-Host "[WARN] Migration job may still be running or already completed" -ForegroundColor Yellow
        }
    }

    # ── Apply via kustomize ──────────────────────────────────────────────
    Write-Host ""
    Write-Host "Applying Kubernetes manifests ($Environment overlay)..." -ForegroundColor Cyan

    kubectl create namespace idaas-platform --dry-run=client -o yaml | kubectl apply -f -
    kubectl apply -k "$DeployDir\overlays\${Environment}\"
    if ($LASTEXITCODE -ne 0) {
        Remove-Item -Recurse -Force $DeployDir
        Write-Error "kubectl apply failed"
        exit 1
    }

    Remove-Item -Recurse -Force $DeployDir

    # ── Wait for rollouts ────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Waiting for rollouts..." -ForegroundColor Yellow

    $deployments = @("backend", "frontend", "runtime")
    foreach ($dep in $deployments) {
        kubectl rollout status deployment/$dep -n idaas-platform --timeout=5m
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[FAIL] $dep rollout failed" -ForegroundColor Red
        }
        else {
            Write-Host "[OK] $dep rolled out" -ForegroundColor Green
        }
    }

    # ── Show status ──────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "=== Deployment Status ===" -ForegroundColor Cyan
    kubectl get pods -n idaas-platform
    Write-Host ""
    kubectl get svc -n idaas-platform
    Write-Host ""
    kubectl get ingress -n idaas-platform
    Write-Host ""

    Write-Host "=== $($Environment.ToUpper()) deployment complete ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Verify DNS points to the ingress load balancer"
    Write-Host "  2. Check TLS certificates: kubectl get certificate -n idaas-platform"
    Write-Host "  3. Test health: curl https://api.idaas.example.com/health"
    Write-Host "  4. Grafana: kubectl port-forward svc/kube-prometheus-stack-grafana 3001:80 -n monitoring"
    Write-Host ""
}
finally {
    Pop-Location
}
