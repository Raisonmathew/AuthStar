//! Compliance Export Service (Gap 2-A)
//!
//! Produces signed JSON bundles of EIAA execution records for SOC 2 / audit use.
//!
//! ## What a compliance bundle is
//!
//! A bundle is a JSON object with:
//!   - `tenant_id`    — scope
//!   - `generated_at` — ISO-8601 timestamp
//!   - `period_start` / `period_end` — requested date range
//!   - `executions`   — array of `StoredExecution` records within the range
//!   - `summary`      — counts by action and decision
//!   - `bundle_sig_b64` — Ed25519 signature over the canonical JSON of the above
//!
//! The signature lets an external auditor verify that the bundle was produced
//! by the tenant's key and has not been modified since export.
//!
//! ## archive_version()
//!
//! Marks a capsule version as archived (sets `archived_at = NOW()`) so it is
//! retained forever even after a newer capsule supersedes it.  Called by the
//! policy compiler's activate step.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, Signer};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;

// ─── Public types ──────────────────────────────────────────────────────────────

/// SOC 2 evidence bundle.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceBundle {
    pub tenant_id: String,
    pub generated_at: DateTime<Utc>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub executions: Vec<BundleExecution>,
    pub summary: BundleSummary,
    /// Ed25519 signature over the canonical bundle JSON (all fields except this one).
    pub bundle_sig_b64: String,
}

/// Flattened execution record included in the bundle.
#[derive(Debug, Serialize, Deserialize)]
pub struct BundleExecution {
    pub decision_ref: String,
    pub action: String,
    pub allowed: bool,
    pub reason: Option<String>,
    pub attestation_sig_b64: String,
    pub executed_at: DateTime<Utc>,
}

/// Aggregate counts by action for the summary section.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BundleSummary {
    pub total_decisions: usize,
    pub allowed: usize,
    pub denied: usize,
    /// Per-action breakdown: `{ "billing:read": { allowed: N, denied: M } }`
    pub by_action: HashMap<String, ActionCount>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ActionCount {
    pub allowed: usize,
    pub denied: usize,
}

// ─── Service ──────────────────────────────────────────────────────────────────

pub struct ComplianceExportService {
    db: PgPool,
}

impl ComplianceExportService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Generate a SOC 2 evidence bundle for `tenant_id` over `[start, end)`.
    ///
    /// Fetches all execution records in the range (up to 10 000 rows — large
    /// ranges should be split into monthly exports by the caller).
    /// Signs the bundle with the tenant's Ed25519 signing key loaded from the
    /// `tenant_signing_keys` table (created by capsule_seeder).
    pub async fn generate_bundle(
        &self,
        tenant_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<ComplianceBundle> {
        // ── 1. Load execution records ──────────────────────────────────────
        type Row = (
            String,            // decision_ref
            String,            // action
            serde_json::Value, // decision JSONB
            String,            // attestation_signature_b64
            DateTime<Utc>,     // created_at
        );

        let rows: Vec<Row> = sqlx::query_as(
            r#"
            SELECT decision_ref, action, decision,
                   attestation_signature_b64, created_at
            FROM eiaa_executions
            WHERE tenant_id  = $1
              AND created_at >= $2
              AND created_at <  $3
            ORDER BY created_at ASC
            LIMIT 10000
            "#,
        )
        .bind(tenant_id)
        .bind(start)
        .bind(end)
        .fetch_all(&self.db)
        .await
        .context("compliance_bundle: query executions")?;

        // ── 2. Build executions + summary ──────────────────────────────────
        let mut summary = BundleSummary::default();
        let executions: Vec<BundleExecution> = rows
            .into_iter()
            .map(
                |(decision_ref, action, decision_json, sig, executed_at)| {
                    let allowed = decision_json
                        .get("allow")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let reason = decision_json
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    summary.total_decisions += 1;
                    if allowed { summary.allowed += 1; } else { summary.denied += 1; }
                    let entry = summary.by_action.entry(action.clone()).or_default();
                    if allowed { entry.allowed += 1; } else { entry.denied += 1; }

                    BundleExecution {
                        decision_ref,
                        action,
                        allowed,
                        reason,
                        attestation_sig_b64: sig,
                        executed_at,
                    }
                },
            )
            .collect();

        // ── 3. Build unsigned bundle ───────────────────────────────────────
        let now = Utc::now();
        let unsigned = serde_json::json!({
            "tenant_id": tenant_id,
            "generated_at": now,
            "period_start": start,
            "period_end": end,
            "executions": executions,
            "summary": summary,
        });

        // ── 4. Load tenant signing key and sign ───────────────────────────
        // The signing key is stored as a 32-byte seed in `tenant_signing_keys`.
        // If no key exists (e.g., old tenant), we skip signing and return an
        // unsigned bundle (bundle_sig_b64 = "").
        let key_seed: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT key_bytes FROM tenant_signing_keys WHERE tenant_id = $1 AND purpose = 'compliance' LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .context("compliance_bundle: load signing key")?;

        let bundle_sig_b64 = if let Some(seed) = key_seed {
            if seed.len() == 32 {
                let seed_arr: [u8; 32] = seed.try_into().unwrap();
                let signing_key = SigningKey::from_bytes(&seed_arr);
                let canonical = serde_json::to_vec(&unsigned)
                    .context("compliance_bundle: serialize for signing")?;
                let sig = signing_key.sign(&canonical);
                URL_SAFE_NO_PAD.encode(sig.to_bytes())
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // ── 5. Re-build with signature attached ───────────────────────────
        Ok(ComplianceBundle {
            tenant_id: tenant_id.to_string(),
            generated_at: now,
            period_start: start,
            period_end: end,
            executions: serde_json::from_value(unsigned["executions"].clone())
                .context("compliance_bundle: deserialize executions")?,
            summary: serde_json::from_value(unsigned["summary"].clone())
                .context("compliance_bundle: deserialize summary")?,
            bundle_sig_b64,
        })
    }

    /// Mark a capsule version as archived (retained forever).
    ///
    /// Called by the policy compiler's activate step on the previously-active
    /// capsule so it remains queryable for re-execution of historical decisions.
    pub async fn archive_version(
        &self,
        tenant_id: &str,
        capsule_hash_b64: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE eiaa_capsules
               SET archived_at = NOW()
             WHERE tenant_id       = $1
               AND capsule_hash_b64 = $2
               AND archived_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .bind(capsule_hash_b64)
        .execute(&self.db)
        .await
        .context("archive_version: update")?;
        Ok(())
    }
}
