# Phase 4: Audit System Resilience

**Duration:** Week 4-5  
**Priority:** P0 (Critical)  
**Dependencies:** Phase 1 (Redis HA)

---

## Problem Statement

### GAP-6: Audit Records Dropped Under Load

**Current State:**
```rust
// backend/crates/api_server/src/services/audit_writer.rs
impl AuditWriter {
    pub async fn write(&self, record: AuditRecord) -> Result<()> {
        // Async batch writer with in-memory buffer
        self.buffer.push(record).await;
        
        // If buffer full, flush to database
        if self.buffer.len() >= BATCH_SIZE {
            self.flush().await?;  // ← Can fail under load
        }
        Ok(())
    }
}
```

**Impact:**
- Audit records dropped when database is slow or unavailable
- EIAA compliance violation (every authorization decision must be audited)
- No durability guarantee for in-memory buffer
- Process crash = lost audit records

**Risk Level:** **CRITICAL** - Compliance and security issue

---

## Target Architecture

### Disk-Based Overflow Queue

```
┌─────────────────────────────────────────────────────────────┐
│  Audit System with Overflow Protection                       │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Authorization Decision                                      │
│         │                                                     │
│         ▼                                                     │
│  ┌──────────────┐                                            │
│  │ AuditWriter  │                                            │
│  │ (In-Memory)  │                                            │
│  └──────┬───────┘                                            │
│         │                                                     │
│         ├─────────────┐                                      │
│         │             │                                      │
│         ▼             ▼                                      │
│  ┌──────────┐   ┌─────────────┐                             │
│  │ Primary  │   │  Overflow   │  (Disk-based)               │
│  │  Path    │   │   Queue     │  (sled embedded KV)         │
│  │ (Fast)   │   │  (Durable)  │                             │
│  └────┬─────┘   └──────┬──────┘                             │
│       │                │                                     │
│       │ Success        │ Retry                               │
│       ▼                ▼                                     │
│  ┌────────────────────────┐                                 │
│  │   PostgreSQL           │                                 │
│  │   eiaa_executions      │                                 │
│  └────────────────────────┘                                 │
│                                                               │
└─────────────────────────────────────────────────────────────┘

Flow:
1. Try primary path (in-memory → PostgreSQL)
2. On failure, write to overflow queue (disk)
3. Background worker retries from overflow queue
4. Zero data loss guarantee
```

---

## Implementation Steps

### Step 1: Add Overflow Queue (3 days)

**File:** `backend/Cargo.toml`
```toml
[workspace.dependencies]
sled = "0.34"  # Embedded key-value store
```

**New File:** `backend/crates/api_server/src/audit/overflow_queue.rs`

```rust
use sled::{Db, IVec};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use std::path::Path;

pub struct OverflowQueue {
    db: Db,
    tree_name: &'static str,
}

impl OverflowQueue {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self {
            db,
            tree_name: "audit_overflow",
        })
    }
    
    pub fn push(&self, record: &AuditRecord) -> Result<()> {
        let tree = self.db.open_tree(self.tree_name)?;
        let key = format!("{}:{}", record.timestamp.timestamp_millis(), uuid::Uuid::new_v4());
        let value = bincode::serialize(record)?;
        tree.insert(key.as_bytes(), value)?;
        tree.flush()?;  // Ensure durability
        Ok(())
    }
    
    pub fn pop_batch(&self, limit: usize) -> Result<Vec<(IVec, AuditRecord)>> {
        let tree = self.db.open_tree(self.tree_name)?;
        let mut batch = Vec::new();
        
        for item in tree.iter().take(limit) {
            let (key, value) = item?;
            let record: AuditRecord = bincode::deserialize(&value)?;
            batch.push((key, record));
        }
        
        Ok(batch)
    }
    
    pub fn remove(&self, key: &[u8]) -> Result<()> {
        let tree = self.db.open_tree(self.tree_name)?;
        tree.remove(key)?;
        Ok(())
    }
    
    pub fn len(&self) -> Result<usize> {
        let tree = self.db.open_tree(self.tree_name)?;
        Ok(tree.len())
    }
}
```

### Step 2: Update AuditWriter (2 days)

**File:** `backend/crates/api_server/src/services/audit_writer.rs`

```rust
use crate::audit::overflow_queue::OverflowQueue;

pub struct AuditWriter {
    pool: PgPool,
    buffer: Arc<Mutex<Vec<AuditRecord>>>,
    overflow_queue: Arc<OverflowQueue>,
    metrics: AuditMetrics,
}

impl AuditWriter {
    pub async fn new(pool: PgPool, overflow_path: impl AsRef<Path>) -> Result<Self> {
        let overflow_queue = Arc::new(OverflowQueue::new(overflow_path)?);
        
        let writer = Self {
            pool,
            buffer: Arc::new(Mutex::new(Vec::new())),
            overflow_queue: overflow_queue.clone(),
            metrics: AuditMetrics::default(),
        };
        
        // Spawn overflow recovery worker
        writer.spawn_overflow_worker();
        
        Ok(writer)
    }
    
    pub async fn write(&self, record: AuditRecord) -> Result<()> {
        // Try primary path first
        match self.write_primary(record.clone()).await {
            Ok(_) => {
                self.metrics.primary_writes.inc();
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Primary audit write failed, using overflow queue"
                );
                
                // Fallback to overflow queue
                self.overflow_queue.push(&record)?;
                self.metrics.overflow_writes.inc();
                
                Ok(())  // Never fail the authorization decision
            }
        }
    }
    
    async fn write_primary(&self, record: AuditRecord) -> Result<()> {
        let mut buffer = self.buffer.lock().await;
        buffer.push(record);
        
        if buffer.len() >= BATCH_SIZE {
            let batch = std::mem::take(&mut *buffer);
            drop(buffer);  // Release lock before I/O
            
            self.flush_batch(batch).await?;
        }
        
        Ok(())
    }
    
    async fn flush_batch(&self, batch: Vec<AuditRecord>) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        
        for record in batch {
            sqlx::query!(
                r#"
                INSERT INTO eiaa_executions (
                    id, tenant_id, user_id, session_id, action,
                    decision, attestation, nonce, timestamp
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
                record.id,
                record.tenant_id,
                record.user_id,
                record.session_id,
                record.action,
                record.decision,
                record.attestation,
                record.nonce,
                record.timestamp,
            )
            .execute(&mut *tx)
            .await?;
        }
        
        tx.commit().await?;
        Ok(())
    }
    
    fn spawn_overflow_worker(&self) {
        let pool = self.pool.clone();
        let overflow_queue = self.overflow_queue.clone();
        let metrics = self.metrics.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                // Check overflow queue size
                let queue_size = match overflow_queue.len() {
                    Ok(size) => size,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to get overflow queue size");
                        continue;
                    }
                };
                
                metrics.overflow_queue_size.set(queue_size as i64);
                
                if queue_size == 0 {
                    continue;
                }
                
                tracing::info!(
                    queue_size = queue_size,
                    "Processing overflow queue"
                );
                
                // Process batch
                match overflow_queue.pop_batch(100) {
                    Ok(batch) => {
                        for (key, record) in batch {
                            match Self::write_record_to_db(&pool, &record).await {
                                Ok(_) => {
                                    let _ = overflow_queue.remove(&key);
                                    metrics.overflow_recovered.inc();
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "Failed to recover audit record, will retry"
                                    );
                                    break;  // Stop processing, retry later
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to pop from overflow queue");
                    }
                }
            }
        });
    }
    
    async fn write_record_to_db(pool: &PgPool, record: &AuditRecord) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO eiaa_executions (
                id, tenant_id, user_id, session_id, action,
                decision, attestation, nonce, timestamp
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (id) DO NOTHING
            "#,
            record.id,
            record.tenant_id,
            record.user_id,
            record.session_id,
            record.action,
            record.decision,
            record.attestation,
            record.nonce,
            record.timestamp,
        )
        .execute(pool)
        .await?;
        
        Ok(())
    }
}
```

### Step 3: Add Monitoring (1 day)

**New File:** `backend/crates/api_server/src/audit/metrics.rs`

```rust
use prometheus::{IntCounter, IntGauge, register_int_counter, register_int_gauge};

#[derive(Clone)]
pub struct AuditMetrics {
    pub primary_writes: IntCounter,
    pub overflow_writes: IntCounter,
    pub overflow_recovered: IntCounter,
    pub overflow_queue_size: IntGauge,
}

impl Default for AuditMetrics {
    fn default() -> Self {
        Self {
            primary_writes: register_int_counter!(
                "audit_writer_primary_total",
                "Audit records written via primary path"
            ).unwrap(),
            overflow_writes: register_int_counter!(
                "audit_writer_overflow_total",
                "Audit records written to overflow queue"
            ).unwrap(),
            overflow_recovered: register_int_counter!(
                "audit_writer_overflow_recovered_total",
                "Audit records recovered from overflow queue"
            ).unwrap(),
            overflow_queue_size: register_int_gauge!(
                "audit_overflow_queue_size",
                "Current size of audit overflow queue"
            ).unwrap(),
        }
    }
}
```

---

## Testing & Validation

### Test 1: Database Unavailability

```bash
# Stop PostgreSQL
kubectl scale statefulset/postgres --replicas=0 -n idaas-platform

# Generate audit records
for i in {1..1000}; do
  curl -X POST http://localhost:3000/api/v1/sign-in -d '...'
done

# Check overflow queue
ls -lh /var/lib/authstar/audit_overflow/

# Restart PostgreSQL
kubectl scale statefulset/postgres --replicas=1 -n idaas-platform

# Wait for recovery
sleep 60

# Verify all records recovered
psql -c "SELECT COUNT(*) FROM eiaa_executions WHERE timestamp > NOW() - INTERVAL '5 minutes'"

# Expected: 1000 records (zero loss)
```

### Test 2: Process Crash

```bash
# Generate records
curl -X POST http://localhost:3000/api/v1/sign-in -d '...'

# Kill process immediately
kill -9 $(pgrep api_server)

# Restart
cargo run --bin api_server

# Expected:
# - Overflow queue persists on disk
# - Records recovered on startup
# - Zero data loss
```

### Test 3: Load Test

```bash
# 10k requests/sec with database throttled
k6 run --vus 1000 --duration 5m tests/audit-load-test.js

# Monitor metrics:
# - audit_writer_overflow_total should increase
# - audit_overflow_queue_size should stay < 10000
# - audit_writer_overflow_recovered_total should increase
# - Zero audit records dropped
```

---

## Monitoring & Alerts

```yaml
# Critical: Audit records dropped
- alert: AuditRecordsDropped
  expr: rate(audit_writer_dropped_total[5m]) > 0
  for: 1m
  severity: critical
  
# Warning: Overflow queue growing
- alert: AuditOverflowQueueGrowing
  expr: audit_overflow_queue_size > 10000
  for: 5m
  severity: warning
  
# Warning: Slow overflow recovery
- alert: SlowAuditOverflowRecovery
  expr: rate(audit_writer_overflow_recovered_total[5m]) < rate(audit_writer_overflow_total[5m])
  for: 10m
  severity: warning
```

---

## Success Criteria

- [ ] Zero audit records dropped under load
- [ ] Overflow queue survives process crashes
- [ ] Recovery completes within 5 minutes
- [ ] Disk usage < 1GB for overflow queue
- [ ] Monitoring dashboards operational
- [ ] Load tests pass
- [ ] Production deployment successful

---

## Next Phase

Once Phase 4 is complete, proceed to [Phase 5: gRPC Load Balancing](./phase-5-grpc-load-balancing.md).
