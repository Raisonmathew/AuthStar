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
//!
//! ## HIGH-20 FIX: Backpressure Metrics
//! The channel has a fixed capacity (default 10,000). When full, records are dropped.
//! Without visibility into this, silent data loss goes undetected in production.
//!
//! We now track:
//! - `dropped_total`: cumulative count of dropped records (atomic counter)
//! - `channel_fill_pct`: percentage of channel capacity currently used
//!
//! A background task logs a WARNING every 10 seconds when:
//! - Channel is ≥ 80% full (backpressure warning)
//! - Any records were dropped since the last check
//!
//! The `AuditWriter` also exposes `metrics()` for the `/health/ready` endpoint.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Input digest (SHA-256 of execution inputs) — for fast integrity check
    pub input_digest: String,
    /// Full input context JSON — required for re-execution verification (CRITICAL-EIAA-4 FIX)
    ///
    /// Storing the full context (not just the hash) enables the ReExecutionService to
    /// replay the exact same inputs through the capsule and verify the decision matches.
    /// This is the cryptographic audit trail required by EIAA compliance.
    ///
    /// The context is the serialized `AuthorizationContext` struct. It is stored as a
    /// JSON string (not JSONB) to preserve exact byte-for-byte reproducibility for
    /// re-execution. The `input_digest` is the SHA-256 of this string.
    pub input_context: Option<String>,
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

/// Backpressure metrics snapshot for monitoring
#[derive(Debug, Clone, Serialize)]
pub struct AuditWriterMetrics {
    /// Total records dropped due to channel backpressure (since startup)
    pub dropped_total: u64,
    /// Current number of records waiting in the channel
    pub channel_pending: usize,
    /// Channel capacity
    pub channel_capacity: usize,
    /// Channel fill percentage (0–100)
    pub channel_fill_pct: f64,
}

/// Async Audit Writer
///
/// Uses a buffered channel to collect audit records and writes them
/// in batches for high throughput.
#[derive(Clone)]
pub struct AuditWriter {
    tx: mpsc::Sender<AuditRecord>,
    /// Cumulative count of records dropped due to channel backpressure
    dropped_total: Arc<AtomicU64>,
    /// Channel capacity (for fill % calculation)
    channel_capacity: usize,
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
        let dropped_total = Arc::new(AtomicU64::new(0));

        // Spawn background flush task
        tokio::spawn(Self::flush_loop(db, rx, batch_size, flush_interval_ms));

        // HIGH-20 FIX: Spawn backpressure monitor task.
        // Logs a WARNING every 10s when channel is ≥ 80% full or records are being dropped.
        let tx_clone = tx.clone();
        let dropped_clone = dropped_total.clone();
        tokio::spawn(Self::backpressure_monitor(tx_clone, dropped_clone, channel_size));
        
        Self { tx, dropped_total, channel_capacity: channel_size }
    }

    /// Record an audit entry (non-blocking)
    ///
    /// If the channel is full, the record is dropped and the drop counter is incremented.
    /// This ensures the main request path is never blocked.
    pub fn record(&self, record: AuditRecord) {
        match self.tx.try_send(record) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // HIGH-20 FIX: Increment drop counter for metrics visibility.
                let prev = self.dropped_total.fetch_add(1, Ordering::Relaxed);
                // Log every power-of-2 drop to avoid log spam while still being visible
                let new_count = prev + 1;
                if new_count == 1 || new_count.is_power_of_two() {
                    tracing::error!(
                        dropped_total = new_count,
                        channel_capacity = self.channel_capacity,
                        "AUDIT WRITER BACKPRESSURE: channel full, dropping audit record. \
                         This indicates the DB flush rate cannot keep up with audit volume. \
                         Consider increasing channel_size or reducing batch flush interval."
                    );
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::error!("Audit writer channel closed — audit records are being lost!");
            }
        }
    }

    /// Get current backpressure metrics (for health check / monitoring endpoints)
    pub fn metrics(&self) -> AuditWriterMetrics {
        let channel_pending = self.channel_capacity - self.tx.capacity();
        let fill_pct = (channel_pending as f64 / self.channel_capacity as f64) * 100.0;
        AuditWriterMetrics {
            dropped_total: self.dropped_total.load(Ordering::Relaxed),
            channel_pending,
            channel_capacity: self.channel_capacity,
            channel_fill_pct: fill_pct,
        }
    }

    /// Background task: periodically log backpressure warnings.
    ///
    /// Runs every 10 seconds. Logs a WARNING when:
    /// - Channel is ≥ 80% full (approaching backpressure)
    /// - Any records were dropped since the last check
    async fn backpressure_monitor(
        tx: mpsc::Sender<AuditRecord>,
        dropped_total: Arc<AtomicU64>,
        channel_capacity: usize,
    ) {
        let mut check_interval = interval(Duration::from_secs(10));
        let mut last_dropped = 0u64;
        // Threshold: warn when channel is ≥ 80% full
        let warn_threshold = (channel_capacity as f64 * 0.80) as usize;

        loop {
            check_interval.tick().await;

            let channel_pending = channel_capacity - tx.capacity();
            let current_dropped = dropped_total.load(Ordering::Relaxed);
            let new_drops = current_dropped - last_dropped;
            let fill_pct = (channel_pending as f64 / channel_capacity as f64) * 100.0;

            if channel_pending >= warn_threshold {
                tracing::warn!(
                    channel_pending = channel_pending,
                    channel_capacity = channel_capacity,
                    fill_pct = format!("{:.1}%", fill_pct),
                    dropped_since_last_check = new_drops,
                    dropped_total = current_dropped,
                    "AUDIT WRITER BACKPRESSURE WARNING: channel is {:.1}% full ({}/{}). \
                     DB flush may not be keeping up. Increase channel_size or reduce \
                     flush_interval_ms to prevent audit record loss.",
                    fill_pct, channel_pending, channel_capacity
                );
            } else if new_drops > 0 {
                tracing::warn!(
                    dropped_since_last_check = new_drops,
                    dropped_total = current_dropped,
                    "AUDIT WRITER: {} records dropped in last 10s (total dropped: {}). \
                     Channel is currently {:.1}% full.",
                    new_drops, current_dropped, fill_pct
                );
            }

            last_dropped = current_dropped;
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

            // CRITICAL-EIAA-4 FIX: Store input_context (full JSON) alongside input_digest.
            //
            // The eiaa_executions table (migration 011) has `input_digest TEXT NOT NULL`.
            // We need to also store `input_context` for re-execution verification.
            // The input_context column is added by migration 031 (see below).
            // We use ON CONFLICT DO NOTHING so existing records are not overwritten.
            //
            // If the input_context column does not exist yet (pre-migration), the INSERT
            // will fail. We handle this gracefully by falling back to the digest-only insert.
            let insert_result = sqlx::query(
                r#"
                INSERT INTO eiaa_executions (
                    decision_ref,
                    capsule_hash_b64,
                    capsule_version,
                    action,
                    tenant_id,
                    input_digest,
                    input_context,
                    nonce_b64,
                    decision,
                    attestation_signature_b64,
                    attestation_timestamp,
                    attestation_hash_b64,
                    user_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (decision_ref) DO NOTHING
                "#,
            )
            .bind(&record.decision_ref)
            .bind(&record.capsule_hash_b64)
            .bind(&record.capsule_version)
            .bind(&record.action)
            .bind(&record.tenant_id)
            .bind(&record.input_digest)
            .bind(&record.input_context)
            .bind(&record.nonce_b64)
            .bind(&decision_json)
            .bind(&record.attestation_signature_b64)
            .bind(&record.attestation_timestamp)
            .bind(&record.attestation_hash_b64)
            .bind(&record.user_id)
            .execute(&mut *tx)
            .await;

            match insert_result {
                Ok(_) => {}
                Err(e) => {
                    // If the error is PostgreSQL SQLSTATE 42703 (undefined_column), the
                    // input_context column does not exist yet (pre-migration environment).
                    // Fall back to the digest-only insert for backward compatibility.
                    //
                    // We check the stable SQLSTATE code "42703" rather than parsing the
                    // human-readable error message, which varies by PostgreSQL locale and
                    // version and would cause silent data loss if the string match fails.
                    let is_missing_column = match &e {
                        sqlx::Error::Database(db_err) => {
                            db_err.code().as_deref() == Some("42703")
                        }
                        _ => false,
                    };
                    if is_missing_column {
                        tracing::warn!(
                            "input_context column not found (SQLSTATE 42703) — falling back to \
                             digest-only insert. Apply migration \
                             033_reconcile_eiaa_schema.sql to enable full re-execution \
                             verification."
                        );
                        sqlx::query(
                            r#"
                            INSERT INTO eiaa_executions (
                                decision_ref, capsule_hash_b64, capsule_version, action,
                                tenant_id, input_digest, nonce_b64, decision,
                                attestation_signature_b64, attestation_timestamp,
                                attestation_hash_b64, user_id
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
                        .map_err(|e| anyhow!("Failed to insert audit record (fallback): {}", e))?;
                    } else {
                        return Err(anyhow!("Failed to insert audit record: {}", e));
                    }
                }
            }
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
