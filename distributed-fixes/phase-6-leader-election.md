# Phase 6: Background Task Coordination

**Duration:** Week 6-7  
**Priority:** P1 (High)  
**Dependencies:** Phase 1 (Redis HA)

---

## Problem Statement

### GAP-7: No Leader Election for Background Tasks

**Current State:**
- Every replica runs background tasks independently
- Duplicate work (e.g., cleanup jobs run 20 times)
- Race conditions on shared resources
- Wasted CPU/memory

**Risk Level:** **HIGH** - Resource waste and potential data corruption

---

## Target Architecture

### Redis-Based Leader Election

```
┌─────────────────────────────────────────────────────────────┐
│  Leader Election (Redis-based)                               │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  API-1 (Leader)    API-2 (Follower)    API-3 (Follower)     │
│  ┌──────────┐     ┌──────────┐        ┌──────────┐         │
│  │ Cleanup  │     │  Idle    │        │  Idle    │         │
│  │  Task    │     │          │        │          │         │
│  └──────────┘     └──────────┘        └──────────┘         │
│       │                                                      │
│       │ Heartbeat every 5s                                  │
│       ▼                                                      │
│  ┌────────────────────────────────────┐                     │
│  │  Redis: leader:cleanup = API-1     │                     │
│  │  TTL: 10 seconds                   │                     │
│  └────────────────────────────────────┘                     │
│                                                               │
│  If leader dies:                                             │
│  - TTL expires                                               │
│  - Followers compete for leadership                          │
│  - New leader elected in < 10s                               │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation

### Leader Election Service

**New File:** `backend/crates/api_server/src/coordination/leader_election.rs`

```rust
use redis::AsyncCommands;
use std::time::Duration;

pub struct LeaderElection {
    redis: MultiplexedConnection,
    replica_id: String,
    task_name: String,
    ttl_seconds: u64,
}

impl LeaderElection {
    pub async fn new(
        redis: MultiplexedConnection,
        replica_id: String,
        task_name: String,
    ) -> Self {
        Self {
            redis,
            replica_id,
            task_name,
            ttl_seconds: 10,
        }
    }
    
    pub async fn try_acquire_leadership(&self) -> Result<bool> {
        let key = format!("leader:{}", self.task_name);
        
        // Try to set key with NX (only if not exists)
        let result: Option<String> = self.redis
            .clone()
            .set_nx(&key, &self.replica_id)
            .await?;
        
        if result.is_some() {
            // Set TTL
            self.redis.clone().expire(&key, self.ttl_seconds as usize).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    pub async fn renew_leadership(&self) -> Result<bool> {
        let key = format!("leader:{}", self.task_name);
        
        // Check if we're still the leader
        let current_leader: Option<String> = self.redis.clone().get(&key).await?;
        
        if current_leader.as_ref() == Some(&self.replica_id) {
            // Renew TTL
            self.redis.clone().expire(&key, self.ttl_seconds as usize).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    pub async fn release_leadership(&self) -> Result<()> {
        let key = format!("leader:{}", self.task_name);
        
        // Only delete if we're the leader
        let script = r#"
            if redis.call("get", KEYS[1]) == ARGV[1] then
                return redis.call("del", KEYS[1])
            else
                return 0
            end
        "#;
        
        self.redis.clone()
            .eval::<_, _, ()>(script, &[&key], &[&self.replica_id])
            .await?;
        
        Ok(())
    }
}
```

### Background Task Coordinator

```rust
pub async fn run_with_leader_election<F, Fut>(
    task_name: &str,
    interval: Duration,
    task: F,
) where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let election = LeaderElection::new(redis, replica_id, task_name.to_string()).await;
    
    let mut interval_timer = tokio::time::interval(interval);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    
    let mut is_leader = false;
    
    loop {
        tokio::select! {
            _ = interval_timer.tick() => {
                if is_leader {
                    if let Err(e) = task().await {
                        tracing::error!(error = %e, "Background task failed");
                    }
                }
            }
            _ = heartbeat.tick() => {
                if is_leader {
                    // Renew leadership
                    match election.renew_leadership().await {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::warn!("Lost leadership");
                            is_leader = false;
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to renew leadership");
                            is_leader = false;
                        }
                    }
                } else {
                    // Try to become leader
                    match election.try_acquire_leadership().await {
                        Ok(true) => {
                            tracing::info!("Acquired leadership for {}", task_name);
                            is_leader = true;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to acquire leadership");
                        }
                    }
                }
            }
        }
    }
}
```

---

## Success Criteria

- [ ] Only one replica runs each background task
- [ ] Failover < 10s when leader dies
- [ ] Zero duplicate task executions
- [ ] Monitoring shows active leader

---

## Next Phase

Proceed to [Phase 7: Graceful Shutdown & Health Checks](./phase-7-graceful-shutdown.md).
