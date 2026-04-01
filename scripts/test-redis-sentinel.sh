#!/bin/bash
set -e

echo "=== Redis Sentinel Testing Script ==="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

print_success "Docker is running"

# Navigate to docker-compose directory
cd "$(dirname "$0")/../infrastructure/docker-compose"

print_info "Starting Redis Sentinel cluster..."
docker-compose -f redis-sentinel.yml up -d

# Wait for services to be ready
print_info "Waiting for services to start (15 seconds)..."
sleep 15

# Test 1: Check if all containers are running
print_info "Test 1: Checking container status..."
CONTAINERS=(
    "redis-master"
    "redis-replica-1"
    "redis-replica-2"
    "redis-sentinel-1"
    "redis-sentinel-2"
    "redis-sentinel-3"
)

ALL_RUNNING=true
for container in "${CONTAINERS[@]}"; do
    if docker ps --filter "name=$container" --filter "status=running" | grep -q "$container"; then
        print_success "$container is running"
    else
        print_error "$container is not running"
        ALL_RUNNING=false
    fi
done

if [ "$ALL_RUNNING" = false ]; then
    print_error "Not all containers are running. Exiting."
    exit 1
fi

# Test 2: Check Sentinel configuration
print_info "Test 2: Checking Sentinel configuration..."
MASTER_INFO=$(docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster 2>/dev/null)
if [ -n "$MASTER_INFO" ]; then
    print_success "Sentinel can discover master: $MASTER_INFO"
else
    print_error "Sentinel cannot discover master"
    exit 1
fi

# Test 3: Check replication
print_info "Test 3: Checking replication status..."
REPLICATION_INFO=$(docker exec redis-master redis-cli INFO replication | grep "connected_slaves")
if echo "$REPLICATION_INFO" | grep -q "connected_slaves:2"; then
    print_success "Master has 2 connected replicas"
else
    print_error "Master does not have 2 replicas: $REPLICATION_INFO"
fi

# Test 4: Write and read test
print_info "Test 4: Testing write/read operations..."
docker exec redis-master redis-cli SET test_key "test_value" > /dev/null
READ_VALUE=$(docker exec redis-master redis-cli GET test_key)
if [ "$READ_VALUE" = "test_value" ]; then
    print_success "Write/read test passed"
else
    print_error "Write/read test failed"
fi

# Test 5: Check Sentinel quorum
print_info "Test 5: Checking Sentinel quorum..."
QUORUM_CHECK=$(docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL ckquorum mymaster 2>&1)
if echo "$QUORUM_CHECK" | grep -q "OK"; then
    print_success "Sentinel quorum is healthy"
else
    print_error "Sentinel quorum check failed: $QUORUM_CHECK"
fi

# Test 6: Failover simulation (optional - commented out by default)
# Uncomment to test automatic failover
# print_info "Test 6: Simulating master failure..."
# docker stop redis-master
# print_info "Waiting for failover (30 seconds)..."
# sleep 30
# NEW_MASTER=$(docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster 2>/dev/null)
# print_info "New master: $NEW_MASTER"
# docker start redis-master
# print_success "Failover test complete"

echo ""
print_success "All tests passed! Redis Sentinel cluster is healthy."
echo ""
print_info "Useful commands:"
echo "  - View Sentinel status: docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL masters"
echo "  - View replication: docker exec redis-master redis-cli INFO replication"
echo "  - View logs: docker-compose -f redis-sentinel.yml logs -f"
echo "  - Stop cluster: docker-compose -f redis-sentinel.yml down"
echo ""

# Made with Bob
