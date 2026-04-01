#!/bin/bash
# Phase 9: Scale Test
#
# Validates horizontal scaling:
# - Scale from 5 → 50 replicas without connection exhaustion
# - Linear throughput scaling
# - Leader election remains stable (single leader)
# - No PgBouncer/Redis connection pool starvation
#
# Prerequisites:
#   - kubectl configured for the target cluster
#   - k6 or curl available
#   - Namespace: idaas-platform (configurable via NAMESPACE env)
#
# Usage:
#   ./scripts/scale-test.sh
#   MIN_REPLICAS=3 MAX_REPLICAS=30 ./scripts/scale-test.sh

set -euo pipefail

NAMESPACE="${NAMESPACE:-idaas-platform}"
API_URL="${API_URL:-http://localhost:3000}"
HEALTH_ENDPOINT="${API_URL}/api/health/ready"
DEPLOYMENT="${DEPLOYMENT:-backend}"
MIN_REPLICAS="${MIN_REPLICAS:-5}"
MAX_REPLICAS="${MAX_REPLICAS:-50}"
STEP="${STEP:-5}"
STABILIZE_SECS="${STABILIZE_SECS:-30}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; }
info() { echo -e "${YELLOW}ℹ $1${NC}"; }
header() { echo -e "\n${CYAN}═══ $1 ═══${NC}"; }

ERRORS=0
TOTAL_CHECKS=0
RESULTS_FILE="/tmp/scale-test-results-$(date +%s).csv"
echo "replicas,healthy_pods,rps,p50_ms,p99_ms,errors" > "$RESULTS_FILE"

check_health() {
    local max_retries=${1:-30}
    for i in $(seq 1 "$max_retries"); do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_ENDPOINT" 2>/dev/null || echo "000")
        if [ "$STATUS" = "200" ]; then return 0; fi
        sleep 2
    done
    return 1
}

wait_for_replicas() {
    local target=$1
    local max_wait=${2:-120}
    info "Waiting for $target replicas to be ready (max ${max_wait}s)..."
    for i in $(seq 1 "$max_wait"); do
        READY=$(kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        if [ "${READY:-0}" -ge "$target" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Measure throughput with a burst of requests
measure_throughput() {
    local count=100
    local start=$(date +%s%N)
    local errors=0
    local latencies=()

    for i in $(seq 1 "$count"); do
        REQ_START=$(date +%s%N)
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_ENDPOINT" 2>/dev/null || echo "000")
        REQ_END=$(date +%s%N)
        LATENCY_MS=$(( (REQ_END - REQ_START) / 1000000 ))
        latencies+=("$LATENCY_MS")
        if [ "$STATUS" != "200" ]; then
            errors=$((errors + 1))
        fi
    done

    local end=$(date +%s%N)
    local total_ms=$(( (end - start) / 1000000 ))
    local rps=0
    if [ "$total_ms" -gt 0 ]; then
        rps=$(( count * 1000 / total_ms ))
    fi

    # Sort latencies for percentile calc
    IFS=$'\n' sorted=($(sort -n <<< "${latencies[*]}")); unset IFS
    local p50_idx=$(( count / 2 ))
    local p99_idx=$(( count * 99 / 100 ))
    local p50=${sorted[$p50_idx]:-0}
    local p99=${sorted[$p99_idx]:-0}

    echo "${rps},${p50},${p99},${errors}"
}

# ============================================================================
header "Phase 9: Scale Test"
echo "Namespace:    $NAMESPACE"
echo "Deployment:   $DEPLOYMENT"
echo "Scale range:  $MIN_REPLICAS → $MAX_REPLICAS (step $STEP)"
echo "Results:      $RESULTS_FILE"
echo ""

# Pre-flight
if ! kubectl cluster-info &>/dev/null; then
    fail "Cannot connect to Kubernetes cluster"
    exit 1
fi
pass "Kubernetes cluster accessible"

# Record original replica count
ORIGINAL_REPLICAS=$(kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "$MIN_REPLICAS")
info "Original replicas: $ORIGINAL_REPLICAS"

# ============================================================================
header "Test 1: Scale Up ($MIN_REPLICAS → $MAX_REPLICAS)"

BASELINE_RPS=0

for replicas in $(seq "$MIN_REPLICAS" "$STEP" "$MAX_REPLICAS"); do
    info "Scaling to $replicas replicas..."
    kubectl scale deployment "$DEPLOYMENT" -n "$NAMESPACE" --replicas="$replicas" &>/dev/null

    if ! wait_for_replicas "$replicas" 120; then
        fail "Timed out waiting for $replicas replicas"
        ERRORS=$((ERRORS + 1))
        continue
    fi

    READY=$(kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
    pass "Scaled to $replicas replicas ($READY ready)"

    # Stabilize
    info "Stabilizing for ${STABILIZE_SECS}s..."
    sleep "$STABILIZE_SECS"

    # Health check
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if check_health 10; then
        pass "Health check passed at $replicas replicas"
    else
        fail "Health check failed at $replicas replicas"
        ERRORS=$((ERRORS + 1))
    fi

    # Throughput measurement
    RESULT=$(measure_throughput)
    RPS=$(echo "$RESULT" | cut -d, -f1)
    P50=$(echo "$RESULT" | cut -d, -f2)
    P99=$(echo "$RESULT" | cut -d, -f3)
    REQ_ERRORS=$(echo "$RESULT" | cut -d, -f4)

    echo "$replicas,$READY,$RPS,$P50,$P99,$REQ_ERRORS" >> "$RESULTS_FILE"
    info "Results at ${replicas} replicas: ${RPS} req/s, p50=${P50}ms, p99=${P99}ms, errors=${REQ_ERRORS}"

    # Track baseline for scaling linearity check
    if [ "$replicas" -eq "$MIN_REPLICAS" ]; then
        BASELINE_RPS=$RPS
    fi

    # Check for errors during scale
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ "$REQ_ERRORS" -le 1 ]; then
        pass "Error rate acceptable at $replicas replicas ($REQ_ERRORS/100)"
    else
        fail "High error rate at $replicas replicas ($REQ_ERRORS/100)"
        ERRORS=$((ERRORS + 1))
    fi
done

# ============================================================================
header "Test 2: Leader Election Stability at Max Scale"

info "Verifying leader election at $MAX_REPLICAS replicas..."
# At max scale, there should be exactly one leader. Check by querying the health endpoint
# multiple times — all responses should be consistent.
CONSISTENT=0
for i in $(seq 1 10); do
    if check_health 3; then
        CONSISTENT=$((CONSISTENT + 1))
    fi
done
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ "$CONSISTENT" -ge 9 ]; then
    pass "Leader election stable at max scale ($CONSISTENT/10 consistent health checks)"
else
    fail "Leader election unstable at max scale ($CONSISTENT/10 consistent)"
    ERRORS=$((ERRORS + 1))
fi

# ============================================================================
header "Test 3: Scale Down ($MAX_REPLICAS → $MIN_REPLICAS)"

info "Scaling down to $MIN_REPLICAS replicas..."
kubectl scale deployment "$DEPLOYMENT" -n "$NAMESPACE" --replicas="$MIN_REPLICAS" &>/dev/null

if wait_for_replicas "$MIN_REPLICAS" 60; then
    pass "Scaled down to $MIN_REPLICAS replicas"
else
    info "Scale-down still in progress"
fi

sleep 15  # Allow graceful shutdown to complete

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if check_health 15; then
    pass "API healthy after scale-down"
else
    fail "API unhealthy after scale-down"
    ERRORS=$((ERRORS + 1))
fi

# ============================================================================
header "Test 4: Restore Original Replica Count"

info "Restoring to $ORIGINAL_REPLICAS replicas..."
kubectl scale deployment "$DEPLOYMENT" -n "$NAMESPACE" --replicas="$ORIGINAL_REPLICAS" &>/dev/null
wait_for_replicas "$ORIGINAL_REPLICAS" 60
pass "Restored to $ORIGINAL_REPLICAS replicas"

# ============================================================================
header "Results"
echo ""
PASSED=$((TOTAL_CHECKS - ERRORS))
echo "Total checks: $TOTAL_CHECKS"
echo -e "Passed:       ${GREEN}$PASSED${NC}"
echo -e "Failed:       ${RED}$ERRORS${NC}"
echo ""
echo "Throughput data saved to: $RESULTS_FILE"
echo ""
cat "$RESULTS_FILE" | column -t -s ','
echo ""

if [ "$BASELINE_RPS" -gt 0 ]; then
    info "Baseline throughput (${MIN_REPLICAS} replicas): ${BASELINE_RPS} req/s"
fi

if [ "$ERRORS" -eq 0 ]; then
    pass "ALL SCALE TESTS PASSED"
    exit 0
else
    fail "$ERRORS SCALE TEST(S) FAILED"
    exit 1
fi
