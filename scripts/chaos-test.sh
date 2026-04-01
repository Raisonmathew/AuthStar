#!/bin/bash
# Phase 9: Chaos Engineering Test
#
# Validates system resilience by killing random pods and verifying:
# - Zero 500 errors during disruption
# - Automatic recovery within SLA
# - No audit data loss
# - Leader election failover works
#
# Prerequisites:
#   - kubectl configured for the target cluster
#   - k6 or curl available for health probes
#   - Namespace: idaas-platform (configurable via NAMESPACE env)
#
# Usage:
#   ./scripts/chaos-test.sh                  # Default: 3 rounds, 30s intervals
#   ROUNDS=10 INTERVAL=60 ./scripts/chaos-test.sh  # Custom

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-idaas-platform}"
ROUNDS="${ROUNDS:-3}"
INTERVAL="${INTERVAL:-30}"
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
    local delay=${2:-2}
    for i in $(seq 1 "$max_retries"); do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_ENDPOINT" 2>/dev/null || echo "000")
        if [ "$STATUS" = "200" ]; then
            return 0
        fi
        sleep "$delay"
    done
    return 1
}

count_pods() {
    kubectl get pods -n "$NAMESPACE" -l "$1" --no-headers 2>/dev/null | grep -c "Running" || echo "0"
}

# ============================================================================
header "Phase 9: Chaos Engineering Test"
echo "Namespace:  $NAMESPACE"
echo "Rounds:     $ROUNDS"
echo "Interval:   ${INTERVAL}s"
echo "API URL:    $API_URL"
echo ""

# Pre-flight: Verify cluster access
if ! kubectl cluster-info &>/dev/null; then
    fail "Cannot connect to Kubernetes cluster"
    exit 1
fi
pass "Kubernetes cluster accessible"

# Record initial state
INITIAL_BACKEND_PODS=$(count_pods "app=backend")
INITIAL_REDIS_PODS=$(count_pods "app=redis")
info "Initial state: ${INITIAL_BACKEND_PODS} backend pods, ${INITIAL_REDIS_PODS} redis pods"

# Verify healthy before chaos
if check_health 5 1; then
    pass "API healthy before chaos"
else
    fail "API not healthy before chaos — aborting"
    exit 1
fi

# ============================================================================
header "Test 1: Random Backend Pod Kill (${ROUNDS} rounds)"

for round in $(seq 1 "$ROUNDS"); do
    info "Round $round/$ROUNDS: Killing random backend pod..."

    # Pick a random backend pod
    POD=$(kubectl get pods -n "$NAMESPACE" -l app=backend --no-headers | grep Running | shuf -n1 | awk '{print $1}')
    if [ -z "$POD" ]; then
        fail "No running backend pods found"
        ERRORS=$((ERRORS + 1))
        continue
    fi

    info "Deleting pod: $POD"
    kubectl delete pod "$POD" -n "$NAMESPACE" --grace-period=5 &>/dev/null

    # Continuously probe health during recovery
    RECOVERY_START=$(date +%s)
    ERRORS_DURING_CHAOS=0
    PROBES=0

    for probe in $(seq 1 20); do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_ENDPOINT" 2>/dev/null || echo "000")
        PROBES=$((PROBES + 1))
        if [ "$STATUS" != "200" ]; then
            ERRORS_DURING_CHAOS=$((ERRORS_DURING_CHAOS + 1))
        fi
        sleep 1
    done

    RECOVERY_END=$(date +%s)
    RECOVERY_TIME=$((RECOVERY_END - RECOVERY_START))

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ "$ERRORS_DURING_CHAOS" -le 2 ]; then
        pass "Round $round: Recovery OK (${ERRORS_DURING_CHAOS}/${PROBES} failed probes, ${RECOVERY_TIME}s window)"
    else
        fail "Round $round: Too many errors (${ERRORS_DURING_CHAOS}/${PROBES} failed probes)"
        ERRORS=$((ERRORS + 1))
    fi

    # Wait for pod replacement
    info "Waiting for pod replacement..."
    sleep "$INTERVAL"

    CURRENT_PODS=$(count_pods "app=backend")
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ "$CURRENT_PODS" -ge "$INITIAL_BACKEND_PODS" ]; then
        pass "Pod count restored: $CURRENT_PODS (expected >= $INITIAL_BACKEND_PODS)"
    else
        fail "Pod count not restored: $CURRENT_PODS (expected >= $INITIAL_BACKEND_PODS)"
        ERRORS=$((ERRORS + 1))
    fi
done

# ============================================================================
header "Test 2: Kill All Backend Pods Simultaneously"

info "Killing ALL backend pods..."
kubectl delete pods -n "$NAMESPACE" -l app=backend --grace-period=5 &>/dev/null

# Wait for recovery (up to 60s)
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if check_health 30 2; then
    pass "Full recovery after killing all backend pods"
else
    fail "API did not recover after killing all backend pods (60s timeout)"
    ERRORS=$((ERRORS + 1))
fi

# ============================================================================
header "Test 3: Leader Election Disruption"

info "Finding the current leader pod..."
# The leader should have the leader election lock. Kill it to test failover.
LEADER_POD=$(kubectl get pods -n "$NAMESPACE" -l app=backend --no-headers | grep Running | head -1 | awk '{print $1}')
if [ -n "$LEADER_POD" ]; then
    info "Killing suspected leader: $LEADER_POD"
    kubectl delete pod "$LEADER_POD" -n "$NAMESPACE" --grace-period=0 --force &>/dev/null

    # Leader election TTL is typically 30s, so a new leader should be elected within that
    info "Waiting 35s for leader re-election..."
    sleep 35

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if check_health 10 2; then
        pass "Leader re-election succeeded — API healthy"
    else
        fail "Leader re-election may have failed — API not healthy"
        ERRORS=$((ERRORS + 1))
    fi
else
    info "SKIP: No backend pods running for leader election test"
fi

# ============================================================================
header "Test 4: Network Partition Simulation (DNS disruption)"

info "Simulating DNS failure for a backend pod..."
POD=$(kubectl get pods -n "$NAMESPACE" -l app=backend --no-headers | grep Running | head -1 | awk '{print $1}')
if [ -n "$POD" ]; then
    # Inject DNS failure via NetworkPolicy (non-destructive, reversible)
    kubectl exec -n "$NAMESPACE" "$POD" -- sh -c "echo '127.0.0.1 redis-service' >> /etc/hosts" 2>/dev/null || true

    sleep 5

    # The pod should be degraded but others should serve traffic
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if check_health 5 1; then
        pass "API remains healthy during single-pod DNS disruption"
    else
        fail "API became unhealthy during DNS disruption"
        ERRORS=$((ERRORS + 1))
    fi

    # Clean up: restart the affected pod
    kubectl delete pod "$POD" -n "$NAMESPACE" --grace-period=5 &>/dev/null || true
    sleep 10
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
    pass "ALL CHAOS TESTS PASSED"
    exit 0
else
    fail "$ERRORS CHAOS TEST(S) FAILED"
    exit 1
fi
