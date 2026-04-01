# Redis Sentinel High Availability Setup

This directory contains the Docker Compose configuration for running Redis in Sentinel mode, providing automatic failover and high availability.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Redis Sentinel Cluster                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Sentinel   │  │   Sentinel   │  │   Sentinel   │      │
│  │   :26379     │  │   :26380     │  │   :26381     │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                 │
│         ┌──────────────────┴──────────────────┐              │
│         │                                     │              │
│  ┌──────▼───────┐  ┌──────────────┐  ┌──────▼───────┐      │
│  │    Master    │  │   Replica    │  │   Replica    │      │
│  │   :6379      │──│   :6380      │  │   :6381      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Components

- **1 Redis Master** (port 6379): Primary read/write node
- **2 Redis Replicas** (ports 6380, 6381): Read replicas with automatic sync
- **3 Redis Sentinels** (ports 26379, 26380, 26381): Monitor and manage failover

## Quick Start

### 1. Start the Sentinel Cluster

```bash
cd infrastructure/docker-compose
docker-compose -f redis-sentinel.yml up -d
```

### 2. Verify Cluster Status

```bash
# Check sentinel status
docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL masters

# Check master status
docker exec redis-master redis-cli INFO replication

# Check replica status
docker exec redis-replica-1 redis-cli INFO replication
```

### 3. Configure Backend

Update your `.env` file:

```bash
# Enable Sentinel mode
REDIS_MODE=sentinel

# Sentinel addresses (comma-separated)
REDIS_SENTINEL_URLS=redis://localhost:26379,redis://localhost:26380,redis://localhost:26381

# Master name (must match sentinel configuration)
REDIS_MASTER_NAME=mymaster

# Optional: Redis password
# REDIS_PASSWORD=your_password_here

# Connection settings
REDIS_MAX_CONNECTIONS=10
REDIS_MIN_IDLE=2
REDIS_CONNECTION_TIMEOUT_MS=5000
REDIS_COMMAND_TIMEOUT_MS=3000
```

### 4. Start Backend

```bash
cd backend
cargo run --bin api_server
```

## Failover Testing

### Manual Failover Test

1. **Check current master:**
   ```bash
   docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster
   ```

2. **Simulate master failure:**
   ```bash
   docker stop redis-master
   ```

3. **Watch failover (should complete in ~10 seconds):**
   ```bash
   docker logs -f redis-sentinel-1
   ```

4. **Verify new master:**
   ```bash
   docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster
   ```

5. **Check backend logs:**
   The backend should automatically detect the new master and reconnect.

6. **Restore original master:**
   ```bash
   docker start redis-master
   ```
   The original master will rejoin as a replica.

### Automatic Failover Behavior

- **Detection Time**: ~5 seconds (down-after-milliseconds)
- **Failover Time**: ~5 seconds (failover-timeout)
- **Total Downtime**: < 10 seconds
- **Quorum**: 2 sentinels must agree before failover
- **Backend Reconnection**: Automatic via SentinelConnectionManager

## Monitoring

### Sentinel Commands

```bash
# Get master info
docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL masters

# Get replica info
docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL replicas mymaster

# Get sentinel info
docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL sentinels mymaster

# Check failover status
docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL ckquorum mymaster
```

### Redis Commands

```bash
# Check replication status
docker exec redis-master redis-cli INFO replication

# Monitor commands in real-time
docker exec redis-master redis-cli MONITOR

# Check connected clients
docker exec redis-master redis-cli CLIENT LIST
```

## Production Deployment

### Kubernetes

For production Kubernetes deployment, use the Redis Sentinel Helm chart:

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install redis bitnami/redis \
  --set sentinel.enabled=true \
  --set master.persistence.enabled=true \
  --set replica.replicaCount=2 \
  --set sentinel.quorum=2
```

### Configuration Recommendations

1. **Persistence**: Enable AOF + RDB for data durability
2. **Resources**: 
   - Master: 2 CPU, 4GB RAM
   - Replicas: 1 CPU, 2GB RAM
   - Sentinels: 0.5 CPU, 512MB RAM
3. **Network**: Use private network, no public exposure
4. **Monitoring**: Integrate with Prometheus + Grafana
5. **Backups**: Daily snapshots to S3/GCS

## Troubleshooting

### Issue: Sentinels can't reach master

**Symptom**: Logs show "master is down" repeatedly

**Solution**:
```bash
# Check network connectivity
docker exec redis-sentinel-1 redis-cli -h redis-master -p 6379 PING

# Verify sentinel configuration
docker exec redis-sentinel-1 cat /etc/redis/sentinel.conf
```

### Issue: Split-brain scenario

**Symptom**: Multiple masters exist

**Solution**:
```bash
# Force reconfiguration
docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL reset mymaster

# Restart all sentinels
docker-compose -f redis-sentinel.yml restart sentinel-1 sentinel-2 sentinel-3
```

### Issue: Backend can't connect

**Symptom**: "Failed to connect to Redis" errors

**Solution**:
1. Verify sentinel URLs in `.env`
2. Check master name matches: `REDIS_MASTER_NAME=mymaster`
3. Ensure sentinels are running: `docker ps | grep sentinel`
4. Check backend logs for connection details

## Cleanup

```bash
# Stop and remove containers
docker-compose -f redis-sentinel.yml down

# Remove volumes (WARNING: deletes all data)
docker-compose -f redis-sentinel.yml down -v
```

## References

- [Redis Sentinel Documentation](https://redis.io/docs/management/sentinel/)
- [Redis Replication](https://redis.io/docs/management/replication/)
- [High Availability Best Practices](https://redis.io/docs/management/sentinel/#fundamental-things-to-know-about-sentinel-before-deploying)