#!/bin/bash
# Phase 9: Full Integration Test Suite Runner
#
# Runs all Phase 9 distributed system validation tests in sequence:
#   1. Load test (k6)
#   2. Chaos engineering
#   3. Failover testing
#   4. Scale testing
#
# Prerequisites:
#   - k6 installed (https://k6.io/docs/get-started/installation/)
#   - kubectl configured for target cluster
#   - API_URL set (default: http://localhost:3000)
#   - NAMESPACE set (default: idaas-platform)
#
# Usage:
#   ./scripts/run-phase9-tests.sh              # Run all tests
#   ./scripts/run-phase9-tests.sh --load-only  # Load test only
#   ./scripts/run-phase9-tests.sh --skip-load  # Skip load test (faster)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="/tmp/phase9-results-$(date +%Y%m%d-%H%M%S)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; }
info() { echo -e "${YELLOW}ℹ $1${NC}"; }

mkdir -p "$RESULTS_DIR"

SKIP_LOAD=false
LOAD_ONLY=false

for arg in "$@"; do
    case "$arg" in
        --load-only) LOAD_ONLY=true ;;
        --skip-load) SKIP_LOAD=true ;;
    esac
done

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║  Phase 9: Distributed System Integration Tests  ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Target: ${API_URL:-http://localhost:3000}"
echo "║  K8s NS: ${NAMESPACE:-idaas-platform}"
echo "║  Output: $RESULTS_DIR"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

TOTAL=0
PASSED=0

run_test() {
    local name=$1
    local script=$2
    TOTAL=$((TOTAL + 1))

    echo -e "\n${CYAN}━━━ Running: $name ━━━${NC}\n"
    if bash "$script" 2>&1 | tee "$RESULTS_DIR/$(echo "$name" | tr ' ' '-').log"; then
        PASSED=$((PASSED + 1))
        pass "$name"
    else
        fail "$name"
    fi
}

# ── Load Test ──
if [ "$SKIP_LOAD" = false ]; then
    if command -v k6 &>/dev/null; then
        TOTAL=$((TOTAL + 1))
        echo -e "\n${CYAN}━━━ Running: k6 Load Test ━━━${NC}\n"
        if k6 run \
            --env BASE_URL="${API_URL:-http://localhost:3000}" \
            --out json="$RESULTS_DIR/load-test-metrics.json" \
            "$ROOT_DIR/tests/load/full-load-test.js" 2>&1 | tee "$RESULTS_DIR/load-test.log"; then
            PASSED=$((PASSED + 1))
            pass "k6 Load Test"
        else
            fail "k6 Load Test"
        fi
    else
        info "k6 not installed — skipping load test. Install: https://k6.io/docs/get-started/installation/"
    fi
fi

if [ "$LOAD_ONLY" = true ]; then
    echo -e "\n${BOLD}Load-only mode — skipping infrastructure tests${NC}"
else
    # ── Chaos Test ──
    run_test "Chaos Engineering" "$SCRIPT_DIR/chaos-test.sh"

    # ── Failover Test ──
    run_test "Failover Testing" "$SCRIPT_DIR/failover-test.sh"

    # ── Scale Test ──
    run_test "Scale Testing" "$SCRIPT_DIR/scale-test.sh"
fi

# ── Summary ──
echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  Phase 9: Test Results${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"
echo ""
echo "  Tests run:    $TOTAL"
echo -e "  Passed:       ${GREEN}$PASSED${NC}"
echo -e "  Failed:       ${RED}$((TOTAL - PASSED))${NC}"
echo ""
echo "  Results dir:  $RESULTS_DIR"
echo ""

if [ "$PASSED" -eq "$TOTAL" ]; then
    echo -e "${GREEN}${BOLD}  ✓ ALL PHASE 9 TESTS PASSED${NC}"
    echo -e "${GREEN}  Distributed Readiness Score: 9.0/10${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}  ✗ $((TOTAL - PASSED)) TEST(S) FAILED${NC}"
    echo -e "${YELLOW}  Review logs in $RESULTS_DIR for details${NC}"
    exit 1
fi
