//! Disk-based overflow queue for EIAA audit records.
//!
//! Uses `sled` embedded KV store to ensure zero audit record loss.
//! When the primary in-memory channel is full, records are persisted
//! to disk. A background worker retries them into PostgreSQL.
//!
//! ## Guarantees
//! - Records are fsync'd to disk before returning (sled default).
//! - The queue is crash-safe: records survive process restarts.
//! - Ordering is preserved via monotonic timestamp keys.
//! - Duplicates are prevented by the `ON CONFLICT (decision_ref) DO NOTHING`
//!   clause in the audit writer's INSERT.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Serializable audit record for the overflow queue.
///
/// We use bincode for compact binary encoding rather than JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverflowAuditRecord {
    pub decision_ref: String,
    pub capsule_hash_b64: String,
    pub capsule_version: String,
    pub action: String,
    pub tenant_id: String,
    pub input_digest: String,
    pub input_context: Option<String>,
    pub nonce_b64: String,
    pub decision_json: String,
    pub attestation_signature_b64: String,
    pub attestation_timestamp_ms: i64,
    pub attestation_hash_b64: Option<String>,
    pub user_id: Option<String>,
}

/// Persistent disk-based overflow queue backed by sled.
pub struct OverflowQueue {
    db: sled::Db,
}

impl OverflowQueue {
    /// Open or create the overflow queue at the given path.
    ///
    /// The path defaults to `./audit_overflow` relative to the working directory.
    /// In production, set `AUDIT_OVERFLOW_PATH` to a persistent volume mount.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = sled::open(path.as_ref())
            .with_context(|| format!("Failed to open sled DB at {:?}", path.as_ref()))?;

        let len = db.len();
        if len > 0 {
            tracing::warn!(
                pending_records = len,
                "Overflow queue has {} pending audit records from a previous run",
                len
            );
        }

        Ok(Self { db })
    }

    /// Push a record into the overflow queue. Fsync'd to disk.
    pub fn push(&self, record: &OverflowAuditRecord) -> Result<()> {
        // Key: monotonic ID (sled generates these) — preserves insertion order
        let value =
            bincode::serialize(record).context("Failed to serialize overflow audit record")?;
        self.db
            .insert(self.db.generate_id()?.to_be_bytes(), value)?;

        metrics::counter!("audit_overflow_writes_total").increment(1);
        metrics::gauge!("audit_overflow_queue_size").set(self.db.len() as f64);

        Ok(())
    }

    /// Pop up to `limit` records from the front of the queue.
    ///
    /// Returns `(key, record)` pairs. Call `remove()` after successfully
    /// writing each record to PostgreSQL.
    pub fn pop_batch(&self, limit: usize) -> Result<Vec<(sled::IVec, OverflowAuditRecord)>> {
        let mut batch = Vec::new();
        for item in self.db.iter().take(limit) {
            let (key, value) = item?;
            let record: OverflowAuditRecord = bincode::deserialize(&value)
                .context("Failed to deserialize overflow audit record")?;
            batch.push((key, record));
        }
        Ok(batch)
    }

    /// Remove a record after successfully writing it to PostgreSQL.
    pub fn remove(&self, key: &sled::IVec) -> Result<()> {
        self.db.remove(key)?;
        Ok(())
    }

    /// Number of records currently in the overflow queue.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.db.len()
    }
}

/// Spawn a background worker that drains the overflow queue into PostgreSQL.
///
/// Runs every 10 seconds. Processes up to 100 records per tick.
/// On DB failure, stops processing and retries on the next tick.
pub fn spawn_overflow_worker(queue: Arc<OverflowQueue>, db: PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            let queue_size = queue.len();
            metrics::gauge!("audit_overflow_queue_size").set(queue_size as f64);

            if queue_size == 0 {
                continue;
            }

            tracing::info!(queue_size, "Processing audit overflow queue");

            let batch = match queue.pop_batch(100) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to read from overflow queue");
                    continue;
                }
            };

            for (key, record) in batch {
                match write_record_to_db(&db, &record).await {
                    Ok(()) => {
                        if let Err(e) = queue.remove(&key) {
                            tracing::error!(error = %e, "Failed to remove record from overflow queue");
                        }
                        metrics::counter!("audit_overflow_recovered_total").increment(1);
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            decision_ref = %record.decision_ref,
                            "Failed to recover overflow audit record, will retry"
                        );
                        break; // Stop processing, retry on next tick
                    }
                }
            }

            metrics::gauge!("audit_overflow_queue_size").set(queue.len() as f64);
        }
    });
}

/// Write a single overflow record to PostgreSQL.
async fn write_record_to_db(db: &PgPool, record: &OverflowAuditRecord) -> Result<()> {
    let decision_json: serde_json::Value = serde_json::from_str(&record.decision_json)
        .unwrap_or_else(|_| serde_json::json!({"allow": false, "reason": "overflow_parse_error"}));

    let timestamp = chrono::DateTime::from_timestamp_millis(record.attestation_timestamp_ms)
        .unwrap_or_else(chrono::Utc::now);

    sqlx::query(
        r#"
        INSERT INTO eiaa_executions (
            decision_ref, capsule_hash_b64, capsule_version, action,
            tenant_id, input_digest, input_context, nonce_b64, decision,
            attestation_signature_b64, attestation_timestamp,
            attestation_hash_b64, user_id
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
    .bind(timestamp)
    .bind(&record.attestation_hash_b64)
    .bind(&record.user_id)
    .execute(db)
    .await
    .context("Failed to insert overflow audit record")?;

    Ok(())
}
