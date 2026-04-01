//! Redis-based leader election for background tasks.
//!
//! Uses `SET NX EX` for atomic lock acquisition and Lua scripts for
//! safe release (only the lock holder can delete it).
//!
//! ## Protocol
//! 1. `try_acquire`: `SET leader:{task} {replica_id} NX EX {ttl}` (atomic)
//! 2. `renew`: Lua script checks holder matches, then refreshes TTL.
//! 3. `release`: Lua script checks holder matches, then deletes key.
//!
//! ## Failure handling
//! - If the leader crashes, the key expires after TTL (10s default).
//! - Another replica acquires leadership on the next heartbeat cycle.
//! - Fencing: the Lua script prevents a stale leader from releasing
//!   a key that has already been re-acquired by a new leader.

use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use anyhow::Result;
use std::time::Duration;
use std::future::Future;

/// Leader election state for a single background task.
#[derive(Clone)]
pub struct LeaderElection {
    redis: ConnectionManager,
    replica_id: String,
    task_name: String,
    ttl_seconds: u64,
}

impl LeaderElection {
    pub fn new(
        redis: ConnectionManager,
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

    fn key(&self) -> String {
        format!("leader:{}", self.task_name)
    }

    /// Attempt to acquire leadership. Returns `true` if this replica is now the leader.
    pub async fn try_acquire(&self) -> Result<bool> {
        let key = self.key();
        // SET key replica_id NX EX ttl — atomic acquire-or-fail
        let result: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(&self.replica_id)
            .arg("NX")
            .arg("EX")
            .arg(self.ttl_seconds)
            .query_async(&mut self.redis.clone())
            .await?;

        Ok(result.is_some())
    }

    /// Renew leadership TTL. Returns `true` if this replica is still the leader.
    pub async fn renew(&self) -> Result<bool> {
        let key = self.key();
        // Lua: check holder matches, then refresh TTL. Atomic.
        let script = r#"
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                redis.call("EXPIRE", KEYS[1], ARGV[2])
                return 1
            else
                return 0
            end
        "#;
        let result: i32 = redis::cmd("EVAL")
            .arg(script)
            .arg(1) // number of KEYS
            .arg(&key)
            .arg(&self.replica_id)
            .arg(self.ttl_seconds)
            .query_async(&mut self.redis.clone())
            .await?;

        Ok(result == 1)
    }

    /// Release leadership. Only succeeds if this replica is the current holder.
    pub async fn release(&self) -> Result<()> {
        let key = self.key();
        let script = r#"
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("DEL", KEYS[1])
            else
                return 0
            end
        "#;
        let _: i32 = redis::cmd("EVAL")
            .arg(script)
            .arg(1)
            .arg(&key)
            .arg(&self.replica_id)
            .query_async(&mut self.redis.clone())
            .await?;

        Ok(())
    }
}

/// Run a background task with leader election coordination.
///
/// Only the elected leader executes `task_fn`. All replicas participate
/// in heartbeats. If the leader dies, another replica takes over within
/// `ttl_seconds` (default 10s).
///
/// The `shutdown` future resolves when the process is shutting down.
pub async fn run_with_leader_election<F, Fut>(
    election: LeaderElection,
    task_interval: Duration,
    task_fn: F,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send,
{
    let mut task_timer = tokio::time::interval(task_interval);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    let mut is_leader = false;

    loop {
        tokio::select! {
            _ = task_timer.tick() => {
                if is_leader {
                    if let Err(e) = task_fn().await {
                        tracing::error!(
                            task = %election.task_name,
                            error = %e,
                            "Leader task execution failed"
                        );
                    }
                }
            }
            _ = heartbeat.tick() => {
                if is_leader {
                    match election.renew().await {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::warn!(task = %election.task_name, "Lost leadership");
                            is_leader = false;
                        }
                        Err(e) => {
                            tracing::error!(
                                task = %election.task_name,
                                error = %e,
                                "Failed to renew leadership, releasing"
                            );
                            is_leader = false;
                        }
                    }
                } else {
                    match election.try_acquire().await {
                        Ok(true) => {
                            tracing::info!(
                                task = %election.task_name,
                                replica = %election.replica_id,
                                "Acquired leadership"
                            );
                            is_leader = true;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            tracing::debug!(
                                task = %election.task_name,
                                error = %e,
                                "Failed to acquire leadership"
                            );
                        }
                    }
                }
            }
            _ = shutdown.changed() => {
                if is_leader {
                    tracing::info!(task = %election.task_name, "Releasing leadership on shutdown");
                    let _ = election.release().await;
                }
                break;
            }
        }
    }
}
