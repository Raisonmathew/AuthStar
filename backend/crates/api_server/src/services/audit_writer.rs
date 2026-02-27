//! Async Audit Writer
//!
//! High-throughput audit logging with write-behind pattern.
//! Design: Producer-Consumer with buffered channel and batch inserts.
//!
//! ## Distributed Environment Considerations
//! - Non-blocking writes for low latency
//! - Batched inserts reduce database load
//! - Graceful shutdown ensures no data loss
//! - Configurable buffer size for memory management

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;

/// Audit record for EIAA execution decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Unique decision reference
    pub decision_ref: String,
    /// Capsule hash (WASM)
    pub capsule_hash_b64: String,
    /// Capsule version
    pub capsule_version: String,
    /// Action type
    pub action: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Input digest (SHA-256 of execution inputs)
    pub input_digest: String,
    /// Nonce for replay protection
    pub nonce_b64: String,
    /// Decision result
    pub decision: AuditDecision,
    /// Attestation signature
    pub attestation_signature_b64: String,
    /// Attestation timestamp
    pub attestation_timestamp: DateTime<Utc>,
    /// Attestation hash
    pub attestation_hash_b64: Option<String>,
    /// User ID (if known)
    pub user_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditDecision {
    pub allow: bool,
    pub reason: Option<String>,
}

/// Async Audit Writer
///
/// Uses a buffered channel to collect audit records and writes them
/// in batches for high throughput.
#[derive(Clone)]
pub struct AuditWriter {
    tx: mpsc::Sender<AuditRecord>,
}

impl AuditWriter {
    /// Spawn a new audit writer with background flush task
    ///
    /// # Arguments
    /// * `db` - PostgreSQL connection pool
    /// * `batch_size` - Number of records to accumulate before flushing
    /// * `flush_interval_ms` - Maximum time to wait before flushing
    /// * `channel_size` - Size of the buffered channel
    pub fn spawn(
        db: PgPool,
        batch_size: usize,
        flush_interval_ms: u64,
        channel_size: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel(channel_size);
        
        // Spawn background flush task
        tokio::spawn(Self::flush_loop(db, rx, batch_size, flush_interval_ms));
        
        Self { tx }
    }

    /// Record an audit entry (non-blocking)
    ///
    /// If the channel is full, the record is dropped with a warning.
    /// This ensures the main request path is never blocked.
    pub fn record(&self, record: AuditRecord) {
        match self.tx.try_send(record) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("Audit writer channel full, dropping record");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::error!("Audit writer channel closed");
            }
        }
    }

    /// Background flush loop
    async fn flush_loop(
        db: PgPool,
        mut rx: mpsc::Receiver<AuditRecord>,
        batch_size: usize,
        flush_interval_ms: u64,
    ) {
        let mut buffer: Vec<AuditRecord> = Vec::with_capacity(batch_size);
        let mut flush_timer = interval(Duration::from_millis(flush_interval_ms));
        
        loop {
            tokio::select! {
                // Receive new record
                Some(record) = rx.recv() => {
                    buffer.push(record);
                    
                    // Flush if batch is full
                    if buffer.len() >= batch_size {
                        if let Err(e) = Self::flush_batch(&db, &buffer).await {
                            tracing::error!("Failed to flush audit batch: {}", e);
                        }
                        buffer.clear();
                    }
                }
                
                // Timer tick - flush whatever we have
                _ = flush_timer.tick() => {
                    if !buffer.is_empty() {
                        if let Err(e) = Self::flush_batch(&db, &buffer).await {
                            tracing::error!("Failed to flush audit batch: {}", e);
                        }
                        buffer.clear();
                    }
                }
                
                // Channel closed - flush remaining and exit
                else => {
                    if !buffer.is_empty() {
                        if let Err(e) = Self::flush_batch(&db, &buffer).await {
                            tracing::error!("Failed to flush final audit batch: {}", e);
                        }
                    }
                    tracing::info!("Audit writer shutting down");
                    break;
                }
            }
        }
    }

    /// Flush a batch of records to the database
    async fn flush_batch(db: &PgPool, records: &[AuditRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }

        let start = std::time::Instant::now();
        
        // Use a transaction for batch insert
        let mut tx = db.begin().await
            .map_err(|e| anyhow!("Failed to start transaction: {}", e))?;

        for record in records {
            let decision_json = serde_json::to_value(&record.decision)
                .map_err(|e| anyhow!("Failed to serialize decision: {}", e))?;

            sqlx::query(
                r#"
                INSERT INTO eiaa_executions (
                    decision_ref,
                    capsule_hash_b64,
                    capsule_version,
                    action,
                    tenant_id,
                    input_digest,
                    nonce_b64,
                    decision,
                    attestation_signature_b64,
                    attestation_timestamp,
                    attestation_hash_b64,
                    user_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (decision_ref) DO NOTHING
                "#,
            )
            .bind(&record.decision_ref)
            .bind(&record.capsule_hash_b64)
            .bind(&record.capsule_version)
            .bind(&record.action)
            .bind(&record.tenant_id)
            .bind(&record.input_digest)
            .bind(&record.nonce_b64)
            .bind(&decision_json)
            .bind(&record.attestation_signature_b64)
            .bind(&record.attestation_timestamp)
            .bind(&record.attestation_hash_b64)
            .bind(&record.user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow!("Failed to insert audit record: {}", e))?;
        }

        tx.commit().await
            .map_err(|e| anyhow!("Failed to commit transaction: {}", e))?;

        let elapsed = start.elapsed();
        tracing::debug!(
            "Flushed {} audit records in {:?}",
            records.len(),
            elapsed
        );

        Ok(())
    }
}

/// Builder for AuditWriter with sensible defaults
pub struct AuditWriterBuilder {
    db: PgPool,
    batch_size: usize,
    flush_interval_ms: u64,
    channel_size: usize,
}

impl AuditWriterBuilder {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            batch_size: 100,
            flush_interval_ms: 100,
            channel_size: 10_000,
        }
    }

    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    pub fn flush_interval_ms(mut self, ms: u64) -> Self {
        self.flush_interval_ms = ms;
        self
    }

    pub fn channel_size(mut self, size: usize) -> Self {
        self.channel_size = size;
        self
    }

    pub fn build(self) -> AuditWriter {
        AuditWriter::spawn(
            self.db,
            self.batch_size,
            self.flush_interval_ms,
            self.channel_size,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_record_serialization() {
        let record = AuditRecord {
            decision_ref: "dec_12345".to_string(),
            capsule_hash_b64: "abc123".to_string(),
            capsule_version: "1.0".to_string(),
            action: "login".to_string(),
            tenant_id: "org_123".to_string(),
            input_digest: "sha256_digest".to_string(),
            nonce_b64: "nonce123".to_string(),
            decision: AuditDecision {
                allow: true,
                reason: Some("authenticated".to_string()),
            },
            attestation_signature_b64: "sig123".to_string(),
            attestation_timestamp: Utc::now(),
            attestation_hash_b64: Some("hash123".to_string()),
            user_id: Some("usr_456".to_string()),
        };

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: AuditRecord = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.decision_ref, record.decision_ref);
        assert_eq!(deserialized.action, record.action);
        assert_eq!(deserialized.decision.allow, record.decision.allow);
    }

    #[test]
    fn test_audit_decision_serialization() {
        let decision = AuditDecision {
            allow: true,
            reason: Some("test reason".to_string()),
        };

        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["allow"], true);
        assert_eq!(json["reason"], "test reason");
    }
}
