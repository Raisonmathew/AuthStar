#!/usr/bin/env bash
# ============================================================================
# IDaaS Platform — Unified Deployment Script (Bash)
#
# Supports three environments:
#   local       — Docker Compose (postgres, redis, backend, frontend, runtime)
#   staging     — Build images, push to registry, deploy to K8s staging overlay
#   production  — Build images, push to registry, deploy to K8s production overlay
#
# Usage:
#   ./scripts/deploy.sh local
#   ./scripts/deploy.sh staging  --version 1.2.0 --org my-org
#   ./scripts/deploy.sh production --version 1.2.0 --org my-org
#
# Prerequisites:
#   local:      Docker / Podman running
#   staging:    Docker, kubectl configured for staging cluster, ghcr.io login
#   production: Docker, kubectl configured for production cluster, ghcr.io login
# ============================================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; GRAY='\033[0;37m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${CYAN}$*${NC}"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
skip() { echo -e "${YELLOW}[SKIP]${NC} $*"; }

# ── Defaults ─────────────────────────────────────────────────────────────────
ENVIRONMENT=""
VERSION="latest"
ORG="your-org"
SKIP_BUILD=false
SKIP_MIGRATIONS=false
REGISTRY="ghcr.io"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="infrastructure/docker-compose/docker-compose.dev.yml"

# ── Parse arguments ──────────────────────────────────────────────────────────
usage() {
    echo "Usage: $0 <local|staging|production> [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --version VERSION    Image version/tag (default: latest)"
    echo "  --org ORG            Container registry org (default: your-org)"
    echo "  --skip-build         Skip Docker build/push (reuse existing images)"
    echo "  --skip-migrations    Skip database migrations"
    echo "  -h, --help           Show this help"
    exit 1
}

if [ $# -lt 1 ]; then usage; fi
ENVIRONMENT="$1"; shift

case "$ENVIRONMENT" in
    local|staging|production) ;;
    *) echo "Error: Invalid environment '$ENVIRONMENT'. Use local, staging, or production."; exit 1 ;;
esac

while [ $# -gt 0 ]; do
    case "$1" in
        --version)    VERSION="$2"; shift 2 ;;
        --org)        ORG="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --skip-migrations) SKIP_MIGRATIONS=true; shift ;;
        -h|--help)    usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

cd "$REPO_ROOT"

# ============================================================================
# LOCAL DEPLOYMENT
# ============================================================================
deploy_local() {
    echo ""
    info "=== IDaaS Local Deployment ==="
    echo ""

    # ── Detect container engine ──────────────────────────────────────────
    ENGINE=""
    COMPOSE_CMD=""

    if command -v docker &>/dev/null; then
        ENGINE="docker"
        if ! docker info &>/dev/null; then
            fail "Docker is installed but not running. Start Docker Desktop and retry."
            exit 1
        fi
    elif command -v podman &>/dev/null; then
        ENGINE="podman"
        if ! podman info &>/dev/null; then
            fail "Podman is installed but not running. Run 'podman machine start'."
            exit 1
        fi
    else
        fail "No container engine found. Install Docker or Podman."
        exit 1
    fi
    ok "Container engine: $ENGINE"

    # ── Detect compose command ───────────────────────────────────────────
    if [ "$ENGINE" = "docker" ]; then
        if docker compose version &>/dev/null; then
            COMPOSE_CMD="docker compose"
        elif command -v docker-compose &>/dev/null; then
            COMPOSE_CMD="docker-compose"
        fi
    fi
    if [ -z "$COMPOSE_CMD" ] && command -v podman-compose &>/dev/null; then
        COMPOSE_CMD="podman-compose"
    fi
    if [ -z "$COMPOSE_CMD" ]; then
        fail "No compose tool found. Install 'docker compose' plugin or 'podman-compose'."
        exit 1
    fi
    ok "Compose command: $COMPOSE_CMD"

    # ── Start infrastructure services ────────────────────────────────────
    echo ""
    info "Starting infrastructure services (postgres, redis, mailhog, minio)..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" up -d postgres redis mailhog minio 2>/dev/null || \
        $COMPOSE_CMD -f "$COMPOSE_FILE" up -d

    # ── Wait for database ────────────────────────────────────────────────
    info "Waiting for PostgreSQL..."
    local max_retries=30
    local healthy=false
    for i in $(seq 1 $max_retries); do
        if $ENGINE exec idaas-postgres-dev pg_isready -U idaas_user -d idaas &>/dev/null; then
            healthy=true; break
        fi
        sleep 1
    done
    if [ "$healthy" = true ]; then
        ok "PostgreSQL is ready"
    else
        fail "PostgreSQL failed to start within ${max_retries}s"
        exit 1
    fi

    # ── Wait for Redis ───────────────────────────────────────────────────
    if $ENGINE exec idaas-redis-dev redis-cli ping &>/dev/null; then
        ok "Redis is ready"
    else
        warn "Redis ping failed — it may still be starting"
    fi

    # ── Create .env if missing ───────────────────────────────────────────
    if [ ! -f backend/.env ]; then
        if [ -f backend/.env.example ]; then
            cp backend/.env.example backend/.env
            ok "Created backend/.env from template (review and update secrets)"
        else
            fail "backend/.env.example not found. Cannot create .env file."
            exit 1
        fi
    fi

    if [ ! -f frontend/.env ]; then
        if [ -f frontend/.env.example ]; then
            cp frontend/.env.example frontend/.env
        else
            echo "VITE_API_URL=http://localhost:3000" > frontend/.env
        fi
        ok "Created frontend/.env"
    fi

    # ── Run database migrations ──────────────────────────────────────────
    if [ "$SKIP_MIGRATIONS" = false ]; then
        if command -v sqlx &>/dev/null; then
            info "Running database migrations..."
            export DATABASE_URL="postgres://idaas_user:dev_password_change_me@localhost:5432/idaas"
            (cd backend && sqlx migrate run --source crates/db_migrations/migrations)
            ok "Migrations complete"
        else
            skip "sqlx-cli not installed. Run: cargo install sqlx-cli --no-default-features --features postgres"
        fi
    fi

    # ── Generate JWT keys if missing ─────────────────────────────────────
    if [ ! -f backend/.keys/private.pem ]; then
        if command -v openssl &>/dev/null; then
            mkdir -p backend/.keys
            openssl ecparam -genkey -name prime256v1 -noout -out backend/.keys/private.pem
            openssl ec -in backend/.keys/private.pem -pubout -out backend/.keys/public.pem
            ok "JWT keys generated in backend/.keys/"
        else
            skip "openssl not found — generate JWT keys manually"
        fi
    fi

    # ── Install frontend dependencies ────────────────────────────────────
    if [ -f frontend/package.json ] && [ ! -d frontend/node_modules ]; then
        info "Installing frontend dependencies..."
        (cd frontend && npm install)
        ok "Frontend deps installed"
    fi

    # ── Summary ──────────────────────────────────────────────────────────
    echo ""
    info "=== Local deployment ready ==="
    echo ""
    info "Start the application:"
    echo "  Backend:  cd backend && cargo run --bin api_server"
    echo "  Runtime:  cd backend && cargo run --bin runtime_service"
    echo "  Frontend: cd frontend && npm run dev"
    echo ""
    info "Or run everything in Docker:"
    echo "  $COMPOSE_CMD -f $COMPOSE_FILE up -d"
    echo ""
    info "Services:"
    echo "  API:             http://localhost:3000"
    echo "  Frontend:        http://localhost:5173 (vite) or http://localhost:8080 (docker)"
    echo "  PostgreSQL:      localhost:5432"
    echo "  Redis:           localhost:6379"
    echo "  MailHog UI:      http://localhost:8025"
    echo "  MinIO Console:   http://localhost:9001"
    echo ""
    info "Manage:"
    echo "  Stop:    $COMPOSE_CMD -f $COMPOSE_FILE down"
    echo "  Logs:    $COMPOSE_CMD -f $COMPOSE_FILE logs -f"
    echo "  Reset:   $COMPOSE_CMD -f $COMPOSE_FILE down -v"
    echo ""
}

# ============================================================================
# STAGING / PRODUCTION DEPLOYMENT
# ============================================================================
deploy_cloud() {
    echo ""
    info "=== IDaaS $(echo "$ENVIRONMENT" | tr '[:lower:]' '[:upper:]') Deployment (v${VERSION}) ==="
    echo ""

    # ── Validate prerequisites ───────────────────────────────────────────
    for tool in docker kubectl; do
        if ! command -v "$tool" &>/dev/null; then
            fail "'$tool' is required but not found in PATH."
            exit 1
        fi
    done

    if ! kubectl cluster-info &>/dev/null; then
        fail "kubectl cannot connect to a cluster. Configure kubeconfig first."
        exit 1
    fi
    ok "Kubernetes cluster is accessible"

    # ── Build and push Docker images ─────────────────────────────────────
    declare -A DIGESTS=()

    if [ "$SKIP_BUILD" = false ]; then
        echo ""
        info "Building and pushing Docker images..."

        declare -A IMAGES=(
            [backend]="backend/Dockerfile"
            [runtime]="backend/Dockerfile.runtime"
            [frontend]="frontend/Dockerfile"
        )

        for name in backend runtime frontend; do
            local tag="${REGISTRY}/${ORG}/${name}:${VERSION}"
            echo -e "  ${GRAY}Building ${name}...${NC}"

            docker build -t "$tag" -f "${IMAGES[$name]}" .
            docker push "$tag"

            local digest
            digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$tag" | sed 's/.*@//')
            if ! echo "$digest" | grep -qE '^sha256:[0-9a-f]{64}$'; then
                fail "Failed to capture ${name} digest (got: '$digest')"
                exit 1
            fi
            DIGESTS[$name]="$digest"
            echo -e "  ${GRAY}${name} digest: ${digest}${NC}"
        done

        ok "All images pushed"
    else
        skip "Build skipped (--skip-build). Using existing images."
        for name in backend runtime frontend; do
            local tag="${REGISTRY}/${ORG}/${name}:${VERSION}"
            local digest
            digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$tag" 2>/dev/null | sed 's/.*@//')
            if ! echo "$digest" | grep -qE '^sha256:[0-9a-f]{64}$'; then
                fail "Cannot find digest for $tag. Build first or pull the image."
                exit 1
            fi
            DIGESTS[$name]="$digest"
        done
    fi

    # ── Inject digests into manifests ────────────────────────────────────
    echo ""
    info "Preparing Kubernetes manifests..."

    local DEPLOY_DIR
    DEPLOY_DIR=$(mktemp -d)
    cp -r infrastructure/kubernetes/* "$DEPLOY_DIR/"

    local short_backend short_runtime short_frontend
    short_backend="${DIGESTS[backend]#sha256:}"
    short_runtime="${DIGESTS[runtime]#sha256:}"
    short_frontend="${DIGESTS[frontend]#sha256:}"

    # Backend deployment + migration job
    for file in base/backend-deployment.yaml base/db-migration-job.yaml; do
        local fpath="$DEPLOY_DIR/$file"
        if [ -f "$fpath" ]; then
            sed -i "s/REPLACE_WITH_ORG/$ORG/g; s/REPLACE_WITH_ACTUAL_DIGEST/$short_backend/g" "$fpath"
        fi
    done

    # Frontend
    sed -i "s/REPLACE_WITH_ORG/$ORG/g; s/REPLACE_WITH_ACTUAL_DIGEST/$short_frontend/g" \
        "$DEPLOY_DIR/base/frontend-deployment.yaml"

    # Runtime
    sed -i "s/REPLACE_WITH_ORG/$ORG/g; s/REPLACE_WITH_ACTUAL_DIGEST/$short_runtime/g" \
        "$DEPLOY_DIR/base/runtime-deployment.yaml"

    # Verify no placeholders remain
    if grep -rq 'REPLACE_WITH_\(ACTUAL_DIGEST\|ORG\)' "$DEPLOY_DIR/base/"*.yaml 2>/dev/null; then
        fail "Unreplaced placeholder found in manifests"
        rm -rf "$DEPLOY_DIR"
        exit 1
    fi
    ok "Manifests prepared with immutable digests"

    # ── Run database migration ───────────────────────────────────────────
    if [ "$SKIP_MIGRATIONS" = false ]; then
        echo ""
        info "Running database migration job..."
        kubectl apply -f "$DEPLOY_DIR/base/db-migration-job.yaml"
        if kubectl wait --for=condition=complete job/db-migrate -n idaas-platform --timeout=120s 2>/dev/null; then
            ok "Database migration complete"
        else
            warn "Migration job may still be running or already completed"
        fi
    fi

    # ── Apply via kustomize ──────────────────────────────────────────────
    echo ""
    info "Applying Kubernetes manifests ($ENVIRONMENT overlay)..."

    kubectl create namespace idaas-platform --dry-run=client -o yaml | kubectl apply -f -
    if ! kubectl apply -k "$DEPLOY_DIR/overlays/${ENVIRONMENT}/"; then
        rm -rf "$DEPLOY_DIR"
        fail "kubectl apply failed"
        exit 1
    fi

    rm -rf "$DEPLOY_DIR"

    # ── Wait for rollouts ────────────────────────────────────────────────
    echo ""
    info "Waiting for rollouts..."

    for dep in backend frontend runtime; do
        if kubectl rollout status "deployment/$dep" -n idaas-platform --timeout=5m 2>/dev/null; then
            ok "$dep rolled out"
        else
            fail "$dep rollout failed"
        fi
    done

    # ── Show status ──────────────────────────────────────────────────────
    echo ""
    info "=== Deployment Status ==="
    echo ""
    kubectl get pods -n idaas-platform
    echo ""
    kubectl get svc -n idaas-platform
    echo ""
    kubectl get ingress -n idaas-platform 2>/dev/null || true
    echo ""

    info "=== $(echo "$ENVIRONMENT" | tr '[:lower:]' '[:upper:]') deployment complete ==="
    echo ""
    info "Next steps:"
    echo "  1. Verify DNS points to the ingress load balancer"
    echo "  2. Check TLS certificates: kubectl get certificate -n idaas-platform"
    echo "  3. Test health: curl https://api.idaas.example.com/health"
    echo "  4. Grafana: kubectl port-forward svc/kube-prometheus-stack-grafana 3001:80 -n monitoring"
    echo ""
}

# ============================================================================
# DISPATCH
# ============================================================================
case "$ENVIRONMENT" in
    local)                deploy_local ;;
    staging|production)   deploy_cloud ;;
esac
