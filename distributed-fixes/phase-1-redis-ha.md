# Phase 1: Redis High Availability

**Duration:** Week 1-2  
**Priority:** P0 (Critical)  
**Dependencies:** None

---

## Problem Statement

### GAP-1: Single Redis Instance = Single Point of Failure

**Current State:**
```rust
// backend/crates/api_server/src/config.rs
pub struct RedisConfig {
    pub url: String,  // ← Single connection string
}
```

**Impact:**
- Redis failure = complete service outage
- Session store, capsule cache, nonce store, flow contexts all unavailable
- No automatic failover
- Manual intervention required for recovery

**Risk Level:** **CRITICAL** - Production deployment impossible without this fix

---

## Target Architecture

### Redis Sentinel Cluster

```
┌─────────────────────────────────────────────────────────┐
│  Redis Sentinel Cluster (High Availability)             │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │ Sentinel │  │ Sentinel │  │ Sentinel │  (Quorum: 2)│
│  │    1     │  │    2     │  │    3     │             │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘             │
│       │             │             │                     │
│       └─────────────┼─────────────┘                     │
│                     │                                   │
│       ┌─────────────▼─────────────┐                     │
│       │   Monitor Master Health   │                     │
│       └─────────────┬─────────────┘                     │
│                     │                                   │
│  ┌──────────────────▼──────────────────┐               │
│  │  Redis Master (Active)              │               │
│  │  - Handles all writes               │               │
│  │  - Replicates to replicas           │               │
│  └──────────────────┬──────────────────┘               │
│                     │                                   │
│       ┌─────────────┼─────────────┐                     │
│       │             │             │                     │
│  ┌────▼─────┐  ┌───▼──────┐  ┌──▼───────┐             │
│  │ Replica  │  │ Replica  │  │ Replica  │             │
│  │    1     │  │    2     │  │    3     │             │
│  └──────────┘  └──────────┘  └──────────┘             │
│                                                          │
└─────────────────────────────────────────────────────────┘

Failover Process:
1. Master fails → Sentinels detect (5s)
2. Quorum reached (2/3 Sentinels agree)
3. Promote replica to master (< 5s)
4. Update clients with new master address
5. Total failover time: < 10s
```

---

## Implementation Steps

### Step 1: Update Redis Configuration (2 days)

**File:** `backend/crates/api_server/src/config.rs`

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RedisMode {
    Standalone,  // Dev only
    Sentinel,    // Production HA
    Cluster,     // Future: horizontal scaling
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub mode: RedisMode,
    pub urls: Vec<String>,  // Sentinel nodes or cluster endpoints
    pub master_name: Option<String>,  // For Sentinel mode
    pub sentinel_password: Option<String>,
    pub db: u8,
    pub connection_timeout_ms: u64,
    pub response_timeout_ms: u64,
}

impl RedisConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let mode = match env::var("REDIS_MODE")?.to_lowercase().as_str() {
            "standalone" => RedisMode::Standalone,
            "sentinel" => RedisMode::Sentinel,
            "cluster" => RedisMode::Cluster,
            _ => return Err(anyhow!("Invalid REDIS_MODE. Must be: standalone, sentinel, or cluster")),
        };

        let urls = env::var("REDIS_URLS")?
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();

        if urls.is_empty() {
            return Err(anyhow!("REDIS_URLS cannot be empty"));
        }

        Ok(RedisConfig {
            mode,
            urls,
            master_name: env::var("REDIS_MASTER_NAME").ok(),
            sentinel_password: env::var("REDIS_SENTINEL_PASSWORD").ok(),
            db: env::var("REDIS_DB").unwrap_or("0".into()).parse()?,
            connection_timeout_ms: env::var("REDIS_CONNECTION_TIMEOUT_MS")
                .unwrap_or("5000".into())
                .parse()?,
            response_timeout_ms: env::var("REDIS_RESPONSE_TIMEOUT_MS")
                .unwrap_or("3000".into())
                .parse()?,
        })
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        match self.mode {
            RedisMode::Sentinel => {
                if self.master_name.is_none() {
                    return Err(anyhow!("REDIS_MASTER_NAME required for Sentinel mode"));
                }
                if self.urls.len() < 3 {
                    tracing::warn!(
                        "Redis Sentinel: {} nodes configured. Recommended: 3+ for quorum",
                        self.urls.len()
                    );
                }
            }
            RedisMode::Cluster => {
                if self.urls.len() < 3 {
                    return Err(anyhow!("Redis Cluster requires at least 3 nodes"));
                }
            }
            RedisMode::Standalone => {
                if self.urls.len() != 1 {
                    return Err(anyhow!("Standalone mode requires exactly 1 URL"));
                }
            }
        }
        Ok(())
    }
}
```

### Step 2: Implement Sentinel Connection Manager (3 days)

**New File:** `backend/crates/api_server/src/redis/sentinel_manager.rs`

```rust
use redis::{Client, aio::MultiplexedConnection};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Duration;
use anyhow::{anyhow, Result};

pub struct SentinelConnectionManager {
    sentinel_clients: Vec<Client>,
    master_name: String,
    sentinel_password: Option<String>,
    current_master: Arc<RwLock<Option<Client>>>,
    db: u8,
}

impl SentinelConnectionManager {
    pub async fn new(
        sentinel_urls: Vec<String>,
        master_name: String,
        sentinel_password: Option<String>,
        db: u8,
    ) -> Result<Self> {
        // Create clients for each Sentinel node
        let sentinel_clients: Vec<Client> = sentinel_urls
            .iter()
            .map(|url| Client::open(url.as_str()))
            .collect::<Result<Vec<_>, _>>()?;

        if sentinel_clients.is_empty() {
            return Err(anyhow!("No Sentinel nodes configured"));
        }

        let manager = Self {
            sentinel_clients,
            master_name: master_name.clone(),
            sentinel_password,
            current_master: Arc::new(RwLock::new(None)),
            db,
        };

        // Discover master on startup
        manager.discover_master().await?;
        
        // Spawn background monitor for failover detection
        manager.spawn_monitor();

        tracing::info!(
            master_name = %master_name,
            sentinel_count = manager.sentinel_clients.len(),
            "Redis Sentinel connection manager initialized"
        );

        Ok(manager)
    }

    async fn discover_master(&self) -> Result<String> {
        for (idx, sentinel) in self.sentinel_clients.iter().enumerate() {
            match self.query_master(sentinel).await {
                Ok(master_addr) => {
                    tracing::info!(
                        sentinel_idx = idx,
                        master = %master_addr,
                        "Discovered Redis master via Sentinel"
                    );
                    
                    // Connect to master with DB selection
                    let master_url = if self.db > 0 {
                        format!("{}/{}", master_addr, self.db)
                    } else {
                        master_addr.clone()
                    };
                    
                    let master_client = Client::open(master_url.as_str())?;
                    *self.current_master.write().await = Some(master_client);
                    
                    return Ok(master_addr);
                }
                Err(e) => {
                    tracing::warn!(
                        sentinel_idx = idx,
                        error = %e,
                        "Sentinel query failed, trying next"
                    );
                    continue;
                }
            }
        }
        Err(anyhow!("All Sentinels unreachable - cannot discover master"))
    }

    async fn query_master(&self, sentinel: &Client) -> Result<String> {
        let mut conn = sentinel.get_connection()?;
        
        // SENTINEL get-master-addr-by-name <master-name>
        let result: Vec<String> = redis::cmd("SENTINEL")
            .arg("get-master-addr-by-name")
            .arg(&self.master_name)
            .query(&mut conn)?;
        
        if result.len() >= 2 {
            let host = &result[0];
            let port = &result[1];
            Ok(format!("redis://{}:{}", host, port))
        } else {
            Err(anyhow!("Invalid Sentinel response: {:?}", result))
        }
    }

    fn spawn_monitor(&self) {
        let sentinel_clients = self.sentinel_clients.clone();
        let master_name = self.master_name.clone();
        let current_master = self.current_master.clone();
        let db = self.db;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            let mut last_master_addr: Option<String> = None;

            loop {
                interval.tick().await;
                
                // Query Sentinels for current master
                for sentinel in &sentinel_clients {
                    if let Ok(master_addr) = Self::query_master_static(sentinel, &master_name).await {
                        // Check if master changed (failover occurred)
                        if last_master_addr.as_ref() != Some(&master_addr) {
                            tracing::warn!(
                                old_master = ?last_master_addr,
                                new_master = %master_addr,
                                "Redis master changed - failover detected"
                            );
                            
                            // Update connection to new master
                            let master_url = if db > 0 {
                                format!("{}/{}", master_addr, db)
                            } else {
                                master_addr.clone()
                            };
                            
                            if let Ok(new_client) = Client::open(master_url.as_str()) {
                                *current_master.write().await = Some(new_client);
                                last_master_addr = Some(master_addr);
                                tracing::info!("Reconnected to new Redis master");
                            }
                        }
                        break;
                    }
                }
            }
        });
    }

    async fn query_master_static(sentinel: &Client, master_name: &str) -> Result<String> {
        let mut conn = sentinel.get_connection()?;
        let result: Vec<String> = redis::cmd("SENTINEL")
            .arg("get-master-addr-by-name")
            .arg(master_name)
            .query(&mut conn)?;
        
        if result.len() >= 2 {
            Ok(format!("redis://{}:{}", result[0], result[1]))
        } else {
            Err(anyhow!("Invalid Sentinel response"))
        }
    }

    pub async fn get_connection(&self) -> Result<MultiplexedConnection> {
        let master = self.current_master.read().await;
        match master.as_ref() {
            Some(client) => {
                match client.get_multiplexed_tokio_connection().await {
                    Ok(conn) => Ok(conn),
                    Err(e) => {
                        drop(master);
                        tracing::warn!(error = %e, "Failed to connect to master, rediscovering");
                        self.discover_master().await?;
                        self.get_connection().await
                    }
                }
            }
            None => {
                drop(master);
                self.discover_master().await?;
                self.get_connection().await
            }
        }
    }
}
```

### Step 3: Update Bootstrap (1 day)

**File:** `backend/crates/api_server/src/bootstrap.rs`

```rust
use crate::redis::sentinel_manager::SentinelConnectionManager;

pub async fn create_redis_connection(config: &RedisConfig) -> Result<redis::aio::MultiplexedConnection> {
    config.validate()?;

    match config.mode {
        RedisMode::Standalone => {
            let client = redis::Client::open(config.urls[0].as_str())?;
            let conn = client.get_multiplexed_tokio_connection().await?;
            tracing::info!("Connected to Redis (standalone mode)");
            Ok(conn)
        }
        RedisMode::Sentinel => {
            let manager = SentinelConnectionManager::new(
                config.urls.clone(),
                config.master_name.clone().unwrap(),
                config.sentinel_password.clone(),
                config.db,
            ).await?;
            
            let conn = manager.get_connection().await?;
            tracing::info!("Connected to Redis (Sentinel mode)");
            Ok(conn)
        }
        RedisMode::Cluster => {
            // Future implementation
            Err(anyhow!("Redis Cluster mode not yet implemented"))
        }
    }
}
```

### Step 4: Infrastructure Setup (2 days)

#### Docker Compose (Development)

**File:** `infrastructure/docker-compose/redis-sentinel.yml`

```yaml
version: '3.8'

services:
  redis-master:
    image: redis:7-alpine
    container_name: idaas-redis-master
    command: redis-server --appendonly yes --replica-announce-ip redis-master
    ports:
      - "6379:6379"
    volumes:
      - redis_master_data:/data
    networks:
      - idaas-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  redis-replica-1:
    image: redis:7-alpine
    container_name: idaas-redis-replica-1
    command: redis-server --replicaof redis-master 6379 --replica-announce-ip redis-replica-1
    depends_on:
      - redis-master
    networks:
      - idaas-network

  redis-replica-2:
    image: redis:7-alpine
    container_name: idaas-redis-replica-2
    command: redis-server --replicaof redis-master 6379 --replica-announce-ip redis-replica-2
    depends_on:
      - redis-master
    networks:
      - idaas-network

  redis-sentinel-1:
    image: redis:7-alpine
    container_name: idaas-redis-sentinel-1
    command: >
      sh -c "echo 'sentinel monitor mymaster redis-master 6379 2
      sentinel down-after-milliseconds mymaster 5000
      sentinel parallel-syncs mymaster 1
      sentinel failover-timeout mymaster 10000' > /tmp/sentinel.conf &&
      redis-sentinel /tmp/sentinel.conf"
    depends_on:
      - redis-master
    ports:
      - "26379:26379"
    networks:
      - idaas-network

  redis-sentinel-2:
    image: redis:7-alpine
    container_name: idaas-redis-sentinel-2
    command: >
      sh -c "echo 'sentinel monitor mymaster redis-master 6379 2
      sentinel down-after-milliseconds mymaster 5000
      sentinel parallel-syncs mymaster 1
      sentinel failover-timeout mymaster 10000' > /tmp/sentinel.conf &&
      redis-sentinel /tmp/sentinel.conf"
    depends_on:
      - redis-master
    ports:
      - "26380:26379"
    networks:
      - idaas-network

  redis-sentinel-3:
    image: redis:7-alpine
    container_name: idaas-redis-sentinel-3
    command: >
      sh -c "echo 'sentinel monitor mymaster redis-master 6379 2
      sentinel down-after-milliseconds mymaster 5000
      sentinel parallel-syncs mymaster 1
      sentinel failover-timeout mymaster 10000' > /tmp/sentinel.conf &&
      redis-sentinel /tmp/sentinel.conf"
    depends_on:
      - redis-master
    ports:
      - "26381:26379"
    networks:
      - idaas-network

volumes:
  redis_master_data:

networks:
  idaas-network:
    driver: bridge
```

**Usage:**
```bash
cd infrastructure/docker-compose
docker-compose -f docker-compose.dev.yml -f redis-sentinel.yml up -d
```

#### Kubernetes (Production)

**File:** `infrastructure/kubernetes/base/redis-sentinel.yaml`

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: redis-sentinel-config
  namespace: idaas-platform
data:
  sentinel.conf: |
    sentinel monitor mymaster redis-0.redis-headless 6379 2
    sentinel down-after-milliseconds mymaster 5000
    sentinel parallel-syncs mymaster 1
    sentinel failover-timeout mymaster 10000
    sentinel auth-pass mymaster ${REDIS_PASSWORD}
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis
  namespace: idaas-platform
spec:
  serviceName: redis-headless
  replicas: 3
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command:
        - sh
        - -c
        - |
          if [ "$(hostname)" = "redis-0" ]; then
            redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
          else
            redis-server --replicaof redis-0.redis-headless 6379 --masterauth ${REDIS_PASSWORD} --requirepass ${REDIS_PASSWORD}
          fi
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: redis-secret
              key: password
        ports:
        - containerPort: 6379
          name: redis
        volumeMounts:
        - name: data
          mountPath: /data
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "200m"
      - name: sentinel
        image: redis:7-alpine
        command:
        - redis-sentinel
        - /etc/redis/sentinel.conf
        ports:
        - containerPort: 26379
          name: sentinel
        volumeMounts:
        - name: sentinel-config
          mountPath: /etc/redis
        resources:
          requests:
            memory: "128Mi"
            cpu: "50m"
          limits:
            memory: "256Mi"
            cpu: "100m"
      volumes:
      - name: sentinel-config
        configMap:
          name: redis-sentinel-config
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: redis-headless
  namespace: idaas-platform
spec:
  clusterIP: None
  selector:
    app: redis
  ports:
  - port: 6379
    name: redis
  - port: 26379
    name: sentinel
---
apiVersion: v1
kind: Service
metadata:
  name: redis-sentinel
  namespace: idaas-platform
spec:
  selector:
    app: redis
  ports:
  - port: 26379
    targetPort: 26379
    name: sentinel
  type: ClusterIP
```

### Step 5: Environment Configuration (1 day)

**File:** `backend/.env.example`

```bash
# Redis Configuration
REDIS_MODE=sentinel  # standalone | sentinel | cluster
REDIS_URLS=localhost:26379,localhost:26380,localhost:26381
REDIS_MASTER_NAME=mymaster
REDIS_SENTINEL_PASSWORD=  # Optional
REDIS_DB=0
REDIS_CONNECTION_TIMEOUT_MS=5000
REDIS_RESPONSE_TIMEOUT_MS=3000
```

**Kubernetes ConfigMap:**
```yaml
# infrastructure/kubernetes/base/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: backend-config
  namespace: idaas-platform
data:
  REDIS_MODE: "sentinel"
  REDIS_URLS: "redis-0.redis-headless:26379,redis-1.redis-headless:26379,redis-2.redis-headless:26379"
  REDIS_MASTER_NAME: "mymaster"
  REDIS_DB: "0"
```

---

## Testing & Validation

### Test 1: Master Failover
```bash
# Kill master pod
kubectl delete pod redis-0 -n idaas-platform

# Expected:
# - Sentinel detects failure within 5s
# - New master elected within 10s
# - Application reconnects automatically
# - Zero 500 errors
# - Sessions remain valid
```

### Test 2: Sentinel Failure
```bash
# Kill 1 sentinel
docker stop idaas-redis-sentinel-1

# Expected:
# - Quorum maintained (2/3 sentinels)
# - No service disruption
# - Failover still works
```

### Test 3: Network Partition
```bash
# Isolate master from sentinels
iptables -A INPUT -s <sentinel-ips> -j DROP

# Expected:
# - Sentinels detect partition
# - New master elected
# - Old master demoted to replica
```

### Test 4: Session Persistence
```bash
# Create session
curl -X POST http://localhost:3000/api/v1/sign-in

# Kill master
kubectl delete pod redis-0 -n idaas-platform

# Verify session still valid
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/v1/user

# Expected: 200 OK
```

---

## Rollback Plan

### Emergency Rollback to Standalone
```bash
kubectl set env deployment/backend \
  REDIS_MODE=standalone \
  REDIS_URLS=redis-master:6379 \
  -n idaas-platform
```

### Data Migration (if needed)
```bash
# Export from Sentinel cluster
redis-cli -h redis-master -p 6379 --rdb /tmp/dump.rdb

# Import to standalone
redis-cli -h new-redis --pipe < /tmp/dump.rdb
```

---

## Success Criteria

- [ ] Sentinel cluster deployed (3 nodes)
- [ ] Master failover < 10s
- [ ] Zero data loss during failover
- [ ] Sessions survive failover
- [ ] Cache remains accessible
- [ ] Monitoring dashboards created
- [ ] Runbook documented
- [ ] Team training completed

---

## Next Phase

Once Phase 1 is complete and validated, proceed to [Phase 2: Distributed Cache Coordination](./phase-2-cache-coordination.md).