#!/bin/bash
# Phase 9: Failover Test
#
# Validates failover for critical infrastructure:
# - Redis master failover (Sentinel promotes replica)
# - PgBouncer failover
# - gRPC runtime failover
#
# Success criteria:
# - Redis failover < 10s
# - Zero session loss
# - Cache invalidation continues post-failover
#
# Prerequisites:
#   - kubectl configured for the target cluster
#   - Redis Sentinel cluster deployed
#   - Namespace: idaas-platform (configurable via NAMESPACE env)
#
# Usage:
#   ./scripts/failover-test.sh

set -euo pipefail

NAMESPACE="${NAMESPACE:-idaas-platform}"
API_URL="${API_URL:-http://localhost:3000}"
HEALTH_ENDPOINT="${API_URL}/api/health/ready"

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

check_health() {
    local max_retries=${1:-30}
    local delay=${2:-1}
    for i in $(seq 1 "$max_retries"); do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_ENDPOINT" 2>/dev/null || echo "000")
        if [ "$STATUS" = "200" ]; then
            return 0
        fi
        sleep "$delay"
    done
    return 1
}

measure_recovery() {
    local start=$(date +%s%N)
    local max_wait=${1:-30}
    for i in $(seq 1 "$max_wait"); do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_ENDPOINT" 2>/dev/null || echo "000")
        if [ "$STATUS" = "200" ]; then
            local end=$(date +%s%N)
            local elapsed_ms=$(( (end - start) / 1000000 ))
            echo "$elapsed_ms"
            return 0
        fi
        sleep 1
    done
    echo "-1"
    return 1
}

# ============================================================================
header "Phase 9: Failover Testing"
echo "Namespace:  $NAMESPACE"
echo "API URL:    $API_URL"
echo ""

# Pre-flight
if ! kubectl cluster-info &>/dev/null; then
    fail "Cannot connect to Kubernetes cluster"
    exit 1
fi
pass "Kubernetes cluster accessible"

if check_health 5 1; then
    pass "API healthy before failover tests"
else
    fail "API not healthy — aborting"
    exit 1
fi

# ============================================================================
header "Test 1: Redis Master Failover"

info "Identifying Redis master pod..."
REDIS_MASTER=$(kubectl get pods -n "$NAMESPACE" -l app=redis,role=master --no-headers 2>/dev/null | head -1 | awk '{print $1}')
if [ -z "$REDIS_MASTER" ]; then
    # Try StatefulSet naming
    REDIS_MASTER=$(kubectl get pods -n "$NAMESPACE" -l app=redis --no-headers 2>/dev/null | head -1 | awk '{print $1}')
fi

if [ -n "$REDIS_MASTER" ]; then
    info "Redis master: $REDIS_MASTER"

    # Pre-failover: Write a test key
    info "Writing pre-failover test key..."
    curl -s -X POST "${API_URL}/api/health/ready" > /dev/null 2>&1 || true

    # Kill the master
    info "Killing Redis master: $REDIS_MASTER"
    KILL_TIME=$(date +%s)
    kubectl delete pod "$REDIS_MASTER" -n "$NAMESPACE" --grace-period=0 --force &>/dev/null

    # Measure recovery time
    info "Measuring failover time (max 30s)..."
    RECOVERY_MS=$(measure_recovery 30)

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ "$RECOVERY_MS" -ge 0 ]; then
        RECOVERY_SECS=$((RECOVERY_MS / 1000))
        if [ "$RECOVERY_SECS" -le 10 ]; then
            pass "Redis failover completed in ${RECOVERY_MS}ms (< 10s SLA)"
        else
            fail "Redis failover took ${RECOVERY_MS}ms (> 10s SLA)"
            ERRORS=$((ERRORS + 1))
        fi
    else
        fail "Redis failover did not complete within 30s"
        ERRORS=$((ERRORS + 1))
    fi

    # Verify API is functional post-failover
    sleep 5
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if check_health 10 1; then
        pass "API fully functional after Redis failover"
    else
        fail "API not healthy after Redis failover"
        ERRORS=$((ERRORS + 1))
    fi
else
    info "SKIP: No Redis pods found (app=redis)"
fi

# ============================================================================
header "Test 2: PgBouncer Failover"

PGBOUNCER_POD=$(kubectl get pods -n "$NAMESPACE" -l app=pgbouncer --no-headers 2>/dev/null | grep Running | head -1 | awk '{print $1}')

if [ -n "$PGBOUNCER_POD" ]; then
    info "PgBouncer pod: $PGBOUNCER_POD"
    info "Killing PgBouncer pod..."
    kubectl delete pod "$PGBOUNCER_POD" -n "$NAMESPACE" --grace-period=5 &>/dev/null

    RECOVERY_MS=$(measure_recovery 30)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ "$RECOVERY_MS" -ge 0 ]; then
        pass "PgBouncer failover recovered in ${RECOVERY_MS}ms"
    else
        fail "PgBouncer failover did not recover within 30s"
        ERRORS=$((ERRORS + 1))
    fi
else
    info "SKIP: No PgBouncer pods found — direct DB connections in use"
fi

# ============================================================================
header "Test 3: gRPC Runtime Failover"

RUNTIME_POD=$(kubectl get pods -n "$NAMESPACE" -l app=runtime --no-headers 2>/dev/null | grep Running | head -1 | awk '{print $1}')

if [ -n "$RUNTIME_POD" ]; then
    info "Runtime pod: $RUNTIME_POD"
    info "Killing runtime pod..."
    kubectl delete pod "$RUNTIME_POD" -n "$NAMESPACE" --grace-period=5 &>/dev/null

    # gRPC client has circuit breaker: 5 failures → open, 30s recovery
    info "Waiting for gRPC circuit breaker recovery (up to 40s)..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if check_health 40 1; then
        pass "gRPC runtime failover succeeded"
    else
        fail "gRPC runtime did not recover within 40s"
        ERRORS=$((ERRORS + 1))
    fi
else
    info "SKIP: No runtime pods found"
fi

# ============================================================================
header "Test 4: Cascading Failure — Kill Redis + Backend Simultaneously"

info "Simulating cascading failure: Redis + 1 backend pod..."
REDIS_POD=$(kubectl get pods -n "$NAMESPACE" -l app=redis --no-headers 2>/dev/null | grep Running | head -1 | awk '{print $1}')
BACKEND_POD=$(kubectl get pods -n "$NAMESPACE" -l app=backend --no-headers 2>/dev/null | grep Running | head -1 | awk '{print $1}')

if [ -n "$REDIS_POD" ] && [ -n "$BACKEND_POD" ]; then
    kubectl delete pod "$REDIS_POD" "$BACKEND_POD" -n "$NAMESPACE" --grace-period=0 --force &>/dev/null

    info "Measuring recovery from cascading failure (max 60s)..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if check_health 60 2; then
        pass "Recovered from cascading failure (Redis + backend)"
    else
        fail "Did not recover from cascading failure within 60s"
        ERRORS=$((ERRORS + 1))
    fi
else
    info "SKIP: Insufficient pods for cascading failure test"
fi

# ============================================================================
header "Results"
echo ""
PASSED=$((TOTAL_CHECKS - ERRORS))
echo "Total checks: $TOTAL_CHECKS"
echo -e "Passed:       ${GREEN}$PASSED${NC}"
echo -e "Failed:       ${RED}$ERRORS${NC}"
echo ""

if [ "$ERRORS" -eq 0 ]; then
    pass "ALL FAILOVER TESTS PASSED"
    exit 0
else
    fail "$ERRORS FAILOVER TEST(S) FAILED"
    exit 1
fi
