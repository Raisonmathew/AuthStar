#!/usr/bin/env bash
# =============================================================================
# AuthStar SDK Integration Test Runner
# =============================================================================
# Runs all three SDK integration suites (Python, Go, TypeScript) against a
# live AuthStar backend.
#
# Usage:
#   ./run.sh                        # run all suites
#   ./run.sh python                 # run only the Python suite
#   ./run.sh go                     # run only the Go suite
#   ./run.sh ts                     # run only the TypeScript suite
#
# Environment variables (all optional — defaults match the dev stack):
#   AUTHSTAR_BASE_URL           default: http://localhost:3000
#   ADMIN_EMAIL                 default: admin@example.com
#   IDAAS_BOOTSTRAP_PASSWORD    default: Admin@1234!DevOnly
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

export AUTHSTAR_BASE_URL="${AUTHSTAR_BASE_URL:-http://localhost:3000}"
export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
export IDAAS_BOOTSTRAP_PASSWORD="${IDAAS_BOOTSTRAP_PASSWORD:-Admin@1234!DevOnly}"

SUITE="${1:-all}"

# Colour helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[run.sh]${NC} $*"; }
success() { echo -e "${GREEN}[run.sh] ✓${NC} $*"; }
warn()    { echo -e "${YELLOW}[run.sh] ⚠${NC}  $*"; }
error()   { echo -e "${RED}[run.sh] ✗${NC} $*"; }

PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Preflight: check the backend is reachable
# ---------------------------------------------------------------------------
preflight() {
  info "Checking backend at $AUTHSTAR_BASE_URL ..."
  if ! curl -sf "$AUTHSTAR_BASE_URL/health" -o /dev/null 2>/dev/null && \
     ! curl -sf "$AUTHSTAR_BASE_URL/api/v1/sdk/manifest" -o /dev/null 2>/dev/null; then
    error "Backend is not reachable at $AUTHSTAR_BASE_URL"
    echo "  Start the backend first:"
    echo "    cd backend && cargo run --bin api_server"
    exit 1
  fi
  success "Backend is reachable"
}

# ---------------------------------------------------------------------------
# Python suite
# ---------------------------------------------------------------------------
run_python() {
  info "Running Python SDK integration tests ..."

  local PY_DIR="$SCRIPT_DIR/python"
  local SDK_DIR="$ROOT_DIR/sdks/python"

  if ! command -v python3 &>/dev/null; then
    warn "python3 not found — skipping Python suite"
    return 0
  fi

  # Create an isolated venv so we don't pollute the system Python
  local VENV="$PY_DIR/.venv"
  if [ ! -d "$VENV" ]; then
    info "Creating Python venv ..."
    python3 -m venv "$VENV"
  fi

  local PIP="$VENV/bin/pip"
  local PYTEST="$VENV/bin/pytest"

  info "Installing dependencies ..."
  "$PIP" install --quiet --upgrade pip
  "$PIP" install --quiet -e "$SDK_DIR"   # installs authstar-agent from sdks/python
  "$PIP" install --quiet requests pytest

  info "pytest -v $PY_DIR/test_agent_authz.py"
  if "$PYTEST" -v "$PY_DIR/test_agent_authz.py" 2>&1; then
    success "Python suite PASSED"
    PASS=$((PASS + 1))
  else
    error "Python suite FAILED"
    FAIL=$((FAIL + 1))
  fi
}

# ---------------------------------------------------------------------------
# Go suite
# ---------------------------------------------------------------------------
run_go() {
  info "Running Go SDK integration tests ..."

  local GO_DIR="$SCRIPT_DIR/go"

  if ! command -v go &>/dev/null; then
    warn "go not found — skipping Go suite"
    return 0
  fi

  info "go test -v ./... (in $GO_DIR)"
  if (cd "$GO_DIR" && go test -v -timeout 120s ./... 2>&1); then
    success "Go suite PASSED"
    PASS=$((PASS + 1))
  else
    error "Go suite FAILED"
    FAIL=$((FAIL + 1))
  fi
}

# ---------------------------------------------------------------------------
# TypeScript suite
# ---------------------------------------------------------------------------
run_ts() {
  info "Running TypeScript SDK integration tests ..."

  local TS_DIR="$SCRIPT_DIR/ts"

  if ! command -v node &>/dev/null; then
    warn "node not found — skipping TypeScript suite"
    return 0
  fi

  local NPM="npm"
  if command -v npm &>/dev/null; then
    NPM="npm"
  else
    warn "npm not found — skipping TypeScript suite"
    return 0
  fi

  if [ ! -d "$TS_DIR/node_modules" ]; then
    info "Installing npm dependencies ..."
    (cd "$TS_DIR" && "$NPM" install --silent)
  fi

  info "npm test (in $TS_DIR)"
  if (cd "$TS_DIR" && "$NPM" test 2>&1); then
    success "TypeScript suite PASSED"
    PASS=$((PASS + 1))
  else
    error "TypeScript suite FAILED"
    FAIL=$((FAIL + 1))
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
preflight

case "$SUITE" in
  python) run_python ;;
  go)     run_go ;;
  ts|typescript) run_ts ;;
  all)
    run_python
    run_go
    run_ts
    ;;
  *)
    error "Unknown suite: $SUITE (choose: python | go | ts | all)"
    exit 1
    ;;
esac

echo ""
echo "─────────────────────────────────────"
if [ $FAIL -eq 0 ]; then
  success "All suites passed  ($PASS passed, $FAIL failed)"
  exit 0
else
  error "Some suites failed ($PASS passed, $FAIL failed)"
  exit 1
fi
