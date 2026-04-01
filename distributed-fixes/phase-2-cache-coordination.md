# Phase 2: Distributed Cache Coordination

**Duration:** Week 2-3  
**Priority:** P0 (Critical)  
**Dependencies:** Phase 1 (Redis HA)

---

## Problem Statement

### GAP-4: Cache Invalidation Not Distributed

**Current State:**
```rust
// backend/crates/api_server/src/services/capsule_cache.rs
impl CapsuleCacheService {
    pub async fn invalidate(&self, tenant_id: Uuid, action: &str) {
        let key = format!("capsule:{}:{}", tenant_id, action);
        let _ = self.redis.del::<_, ()>(&key).await;
        // ← Only invalidates local Redis instance
        // Other API replicas still have stale cache (up to 1h TTL)
    }
}
```

**Impact:**
- Stale authorization decisions for up to 1 hour after policy changes
- Security risk: revoked permissions still active on other replicas
- EIAA compliance violation: attestations based on outdated capsules
- No way to force immediate cache refresh across all nodes

**Risk Level:** **CRITICAL** - Security and compliance issue

---

## Target Architecture

### Redis Pub/Sub for Cache Invalidation

```
┌─────────────────────────────────────────────────────────────┐
│  Cache Invalidation Bus (Redis Pub/Sub)                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  API Replica 1          API Replica 2          API Replica 3 │
│  ┌──────────┐          ┌──────────┐          ┌──────────┐   │
│  │ Capsule  │          │ Capsule  │          │ Capsule  │   │
│  │  Cache   │          │  Cache   │          │  Cache   │   │
│  └────┬─────┘          └────┬─────┘          └────┬─────┘   │
│       │                     │                     │          │
│       │ Subscribe           │ Subscribe           │ Subscribe│
│       └─────────────────────┼─────────────────────┘          │
│                             │                                │
│                    ┌────────▼────────┐                       │
│                    │  Redis Pub/Sub  │                       │
│                    │  Channel:       │                       │
│                    │  cache:invalidate│                      │
│                    └────────▲────────┘                       │
│                             │                                │
│                             │ Publish                        │
│                    ┌────────┴────────┐                       │
│                    │  Policy Update  │                       │
│                    │  (any replica)  │                       │
│                    └─────────────────┘                       │
│                                                               │
└─────────────────────────────────────────────────────────────┘

Flow:
1. Admin updates policy on Replica 1
2. Replica 1 publishes invalidation message to Redis
3. All replicas (1, 2, 3) receive message instantly
4. Each replica invalidates its local cache
5. Next request fetches fresh capsule from DB
6. Total propagation time: < 100ms
```

---

## Implementation Steps

### Step 1: Create Invalidation Message Protocol (1 day)

**New File:** `backend/crates/api_server/src/cache/invalidation.rs`

```rust
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InvalidationScope {
    /// Invalidate specific capsule
    Capsule { tenant_id: Uuid, action: String },
    
    /// Invalidate all capsules for tenant
    TenantCapsules { tenant_id: Uuid },
    
    /// Invalidate runtime public key cache
    RuntimeKey { key_id: String },
    
    /// Invalidate all caches (emergency)
    Global,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidationMessage {
    /// Unique message ID for deduplication
    pub message_id: Uuid,
    
    /// Timestamp when invalidation was triggered
    pub timestamp: SystemTime,
    
    /// Replica that triggered invalidation
    pub source_replica_id: String,
    
    /// What to invalidate
    pub scope: InvalidationScope,
    
    /// Optional reason for audit trail
    pub reason: Option<String>,
}

impl InvalidationMessage {
    pub fn new(scope: InvalidationScope, replica_id: String) -> Self {
        Self {
            message_id: Uuid::new_v4(),
            timestamp: SystemTime::now(),
            source_replica_id: replica_id,
            scope,
            reason: None,
        }
    }
    
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}
```

### Step 2: Implement Invalidation Bus (2 days)

**New File:** `backend/crates/api_server/src/cache/invalidation_bus.rs`

```rust
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use tokio::sync::broadcast;
use std::sync::Arc;
use anyhow::Result;
use super::invalidation::{InvalidationMessage, InvalidationScope};

const CHANNEL_NAME: &str = "cache:invalidate";
const DEDUP_WINDOW_SECS: u64 = 5;

pub struct InvalidationBus {
    redis: MultiplexedConnection,
    replica_id: String,
    /// Local broadcast channel for subscribers
    tx: broadcast::Sender<InvalidationMessage>,
    /// Recent message IDs for deduplication
    recent_messages: Arc<tokio::sync::RwLock<lru::LruCache<uuid::Uuid, ()>>>,
}

impl InvalidationBus {
    pub async fn new(
        redis: MultiplexedConnection,
        replica_id: String,
    ) -> Result<Self> {
        let (tx, _rx) = broadcast::channel(1000);
        let recent_messages = Arc::new(tokio::sync::RwLock::new(
            lru::LruCache::new(std::num::NonZeroUsize::new(10000).unwrap())
        ));
        
        let bus = Self {
            redis,
            replica_id,
            tx,
            recent_messages,
        };
        
        // Spawn subscriber task
        bus.spawn_subscriber();
        
        tracing::info!(
            replica_id = %bus.replica_id,
            "Cache invalidation bus initialized"
        );
        
        Ok(bus)
    }
    
    /// Publish invalidation message to all replicas
    pub async fn publish(&self, scope: InvalidationScope) -> Result<()> {
        let msg = InvalidationMessage::new(scope, self.replica_id.clone());
        
        // Add to dedup cache (don't process our own messages)
        self.recent_messages.write().await.put(msg.message_id, ());
        
        // Serialize and publish
        let payload = serde_json::to_string(&msg)?;
        let mut conn = self.redis.clone();
        conn.publish::<_, _, ()>(CHANNEL_NAME, payload).await?;
        
        tracing::debug!(
            message_id = %msg.message_id,
            scope = ?msg.scope,
            "Published cache invalidation"
        );
        
        Ok(())
    }
    
    /// Subscribe to invalidation messages
    pub fn subscribe(&self) -> broadcast::Receiver<InvalidationMessage> {
        self.tx.subscribe()
    }
    
    fn spawn_subscriber(&self) {
        let mut pubsub = self.redis.clone().into_pubsub();
        let tx = self.tx.clone();
        let recent_messages = self.recent_messages.clone();
        let replica_id = self.replica_id.clone();
        
        tokio::spawn(async move {
            if let Err(e) = pubsub.subscribe(CHANNEL_NAME).await {
                tracing::error!(error = %e, "Failed to subscribe to invalidation channel");
                return;
            }
            
            tracing::info!("Subscribed to cache invalidation channel");
            
            let mut stream = pubsub.on_message();
            while let Some(msg) = stream.next().await {
                let payload: String = match msg.get_payload() {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(error = %e, "Invalid message payload");
                        continue;
                    }
                };
                
                let inv_msg: InvalidationMessage = match serde_json::from_str(&payload) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to deserialize message");
                        continue;
                    }
                };
                
                // Deduplication check
                {
                    let mut cache = recent_messages.write().await;
                    if cache.contains(&inv_msg.message_id) {
                        // Already processed (our own message or duplicate)
                        continue;
                    }
                    cache.put(inv_msg.message_id, ());
                }
                
                tracing::info!(
                    message_id = %inv_msg.message_id,
                    source = %inv_msg.source_replica_id,
                    scope = ?inv_msg.scope,
                    "Received cache invalidation"
                );
                
                // Broadcast to local subscribers
                let _ = tx.send(inv_msg);
            }
            
            tracing::error!("Invalidation subscriber stream ended unexpectedly");
        });
    }
}
```

### Step 3: Update CapsuleCacheService (1 day)

**File:** `backend/crates/api_server/src/services/capsule_cache.rs`

```rust
use crate::cache::invalidation_bus::InvalidationBus;
use crate::cache::invalidation::InvalidationScope;

pub struct CapsuleCacheService {
    redis: MultiplexedConnection,
    pool: PgPool,
    invalidation_bus: Arc<InvalidationBus>,
}

impl CapsuleCacheService {
    pub async fn new(
        redis: MultiplexedConnection,
        pool: PgPool,
        invalidation_bus: Arc<InvalidationBus>,
    ) -> Result<Self> {
        let service = Self {
            redis: redis.clone(),
            pool,
            invalidation_bus: invalidation_bus.clone(),
        };
        
        // Subscribe to invalidation messages
        service.spawn_invalidation_handler();
        
        Ok(service)
    }
    
    /// Invalidate capsule and notify all replicas
    pub async fn invalidate(&self, tenant_id: Uuid, action: &str) -> Result<()> {
        // Local invalidation
        let key = format!("capsule:{}:{}", tenant_id, action);
        self.redis.clone().del::<_, ()>(&key).await?;
        
        // Notify other replicas
        self.invalidation_bus.publish(InvalidationScope::Capsule {
            tenant_id,
            action: action.to_string(),
        }).await?;
        
        tracing::info!(
            tenant_id = %tenant_id,
            action = %action,
            "Capsule invalidated across all replicas"
        );
        
        Ok(())
    }
    
    /// Invalidate all capsules for a tenant
    pub async fn invalidate_tenant(&self, tenant_id: Uuid) -> Result<()> {
        // Local invalidation (scan and delete)
        let pattern = format!("capsule:{}:*", tenant_id);
        let mut conn = self.redis.clone();
        let keys: Vec<String> = conn.keys(&pattern).await?;
        
        if !keys.is_empty() {
            conn.del::<_, ()>(&keys).await?;
        }
        
        // Notify other replicas
        self.invalidation_bus.publish(InvalidationScope::TenantCapsules {
            tenant_id,
        }).await?;
        
        tracing::info!(
            tenant_id = %tenant_id,
            keys_deleted = keys.len(),
            "All tenant capsules invalidated"
        );
        
        Ok(())
    }
    
    fn spawn_invalidation_handler(&self) {
        let mut rx = self.invalidation_bus.subscribe();
        let redis = self.redis.clone();
        
        tokio::spawn(async move {
            while let Ok(msg) = rx.recv().await {
                match msg.scope {
                    InvalidationScope::Capsule { tenant_id, action } => {
                        let key = format!("capsule:{}:{}", tenant_id, action);
                        if let Err(e) = redis.clone().del::<_, ()>(&key).await {
                            tracing::error!(
                                error = %e,
                                key = %key,
                                "Failed to invalidate capsule"
                            );
                        }
                    }
                    InvalidationScope::TenantCapsules { tenant_id } => {
                        let pattern = format!("capsule:{}:*", tenant_id);
                        let mut conn = redis.clone();
                        if let Ok(keys) = conn.keys::<_, Vec<String>>(&pattern).await {
                            if !keys.is_empty() {
                                let _ = conn.del::<_, ()>(&keys).await;
                            }
                        }
                    }
                    InvalidationScope::RuntimeKey { key_id } => {
                        let key = format!("runtime:key:{}", key_id);
                        let _ = redis.clone().del::<_, ()>(&key).await;
                    }
                    InvalidationScope::Global => {
                        // Flush all caches (emergency only)
                        tracing::warn!("Global cache flush triggered");
                        let _ = redis.clone().cmd("FLUSHDB").query_async::<_, ()>().await;
                    }
                }
            }
        });
    }
}
```

### Step 4: Update RuntimeKeyCache (1 day)

**File:** `backend/crates/api_server/src/services/runtime_key_cache.rs`

```rust
impl RuntimeKeyCache {
    pub async fn invalidate(&self, key_id: &str) -> Result<()> {
        // Local invalidation
        let key = format!("runtime:key:{}", key_id);
        self.redis.clone().del::<_, ()>(&key).await?;
        
        // Notify other replicas
        self.invalidation_bus.publish(InvalidationScope::RuntimeKey {
            key_id: key_id.to_string(),
        }).await?;
        
        Ok(())
    }
}
```

### Step 5: Wire Up in Bootstrap (1 day)

**File:** `backend/crates/api_server/src/bootstrap.rs`

```rust
pub async fn create_app_state(config: Config) -> Result<AppState> {
    // ... existing setup ...
    
    // Create invalidation bus
    let replica_id = format!(
        "{}:{}",
        hostname::get()?.to_string_lossy(),
        std::process::id()
    );
    
    let invalidation_bus = Arc::new(
        InvalidationBus::new(redis_conn.clone(), replica_id).await?
    );
    
    // Create services with invalidation bus
    let capsule_cache = Arc::new(
        CapsuleCacheService::new(
            redis_conn.clone(),
            pool.clone(),
            invalidation_bus.clone(),
        ).await?
    );
    
    let runtime_key_cache = Arc::new(
        RuntimeKeyCache::new(
            redis_conn.clone(),
            invalidation_bus.clone(),
        ).await?
    );
    
    Ok(AppState {
        capsule_cache,
        runtime_key_cache,
        invalidation_bus,
        // ... other fields ...
    })
}
```

### Step 6: Add Monitoring (1 day)

**New File:** `backend/crates/api_server/src/cache/metrics.rs`

```rust
use prometheus::{IntCounter, Histogram, register_int_counter, register_histogram};

lazy_static! {
    pub static ref CACHE_INVALIDATION_TOTAL: IntCounter = register_int_counter!(
        "cache_invalidation_events_total",
        "Total number of cache invalidation events"
    ).unwrap();
    
    pub static ref CACHE_INVALIDATION_LATENCY: Histogram = register_histogram!(
        "cache_invalidation_latency_seconds",
        "Time to propagate cache invalidation across replicas"
    ).unwrap();
    
    pub static ref CACHE_CONSISTENCY_ERRORS: IntCounter = register_int_counter!(
        "cache_consistency_errors_total",
        "Number of cache consistency errors detected"
    ).unwrap();
}
```

---

## Testing & Validation

### Test 1: Single Capsule Invalidation

```bash
# Terminal 1: Start replica 1
REPLICA_ID=replica-1 cargo run --bin api_server

# Terminal 2: Start replica 2
REPLICA_ID=replica-2 PORT=3001 cargo run --bin api_server

# Terminal 3: Update policy on replica 1
curl -X PUT http://localhost:3000/api/admin/v1/policies/123 \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"action": "user:read", "rules": [...]}'

# Terminal 4: Verify cache invalidated on replica 2
redis-cli KEYS "capsule:*"  # Should be empty

# Expected:
# - Invalidation propagates in < 100ms
# - Both replicas fetch fresh capsule on next request
# - No stale authorization decisions
```

### Test 2: Tenant-Wide Invalidation

```bash
# Delete all policies for tenant
curl -X DELETE http://localhost:3000/api/admin/v1/tenants/abc-123/policies \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Verify all capsules invalidated
redis-cli KEYS "capsule:abc-123:*"  # Should be empty

# Expected:
# - All tenant capsules removed from all replicas
# - Propagation time < 200ms
```

### Test 3: Network Partition Resilience

```bash
# Block Redis pub/sub temporarily
iptables -A OUTPUT -p tcp --dport 6379 -j DROP

# Update policy (should queue locally)
curl -X PUT http://localhost:3000/api/admin/v1/policies/123 ...

# Restore network
iptables -D OUTPUT -p tcp --dport 6379 -j DROP

# Expected:
# - Local cache invalidated immediately
# - Remote invalidation queued and sent when network restored
# - Eventually consistent (< 5s after network restore)
```

### Test 4: Load Test

```bash
# Generate 1000 policy updates/sec
k6 run --vus 100 --duration 60s tests/cache-invalidation-load.js

# Expected:
# - All invalidations propagate successfully
# - Latency p99 < 200ms
# - Zero dropped messages
# - Redis CPU < 50%
```

---

## Monitoring & Alerts

### Metrics Dashboard

```yaml
# Grafana dashboard queries
- cache_invalidation_events_total
- rate(cache_invalidation_events_total[5m])
- histogram_quantile(0.99, cache_invalidation_latency_seconds)
- cache_consistency_errors_total
```

### Alert Rules

```yaml
# Critical: Cache consistency errors
- alert: CacheConsistencyErrors
  expr: rate(cache_consistency_errors_total[5m]) > 0
  for: 1m
  severity: critical
  
# Warning: Slow invalidation
- alert: CacheInvalidationSlow
  expr: histogram_quantile(0.99, cache_invalidation_latency_seconds) > 1
  for: 5m
  severity: warning
  
# Warning: High invalidation rate
- alert: CacheInvalidationStorm
  expr: rate(cache_invalidation_events_total[1m]) > 100
  for: 2m
  severity: warning
```

---

## Rollback Plan

### Disable Invalidation Bus

```bash
# Feature flag rollback
kubectl set env deployment/backend \
  ENABLE_CACHE_INVALIDATION_BUS=false \
  -n idaas-platform

# Falls back to local-only invalidation
# Stale cache window returns to 1h TTL
```

---

## Success Criteria

- [ ] Invalidation propagates to all replicas in < 100ms (p99)
- [ ] Zero cache consistency errors under normal load
- [ ] Handles 1000 invalidations/sec without message loss
- [ ] Survives Redis pub/sub failures (queues locally)
- [ ] Monitoring dashboards operational
- [ ] Load tests pass
- [ ] Production deployment successful

---

## Next Phase

Once Phase 2 is complete and validated, proceed to [Phase 3: Database Connection Management](./phase-3-db-connection-mgmt.md).