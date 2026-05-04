//! `CredentialStore` — thin repository over the unified `credentials` table
//! introduced by migration `053_unified_credentials.sql`.
//!
//! ## Phase 1 status
//!
//! This module is **wired into [`AppState`] but not yet called from any
//! existing flow**. It exists so that:
//!
//!   * the SQL surface is reviewable now (alongside the migration),
//!   * Phase 2 (dual-write) is a one-line opt-in inside each adapter
//!     (`if dual_write_enabled { store.insert(...).await?; }`),
//!   * Phase 3 (read switch) replaces `UserFactorService::list_factors()`'s
//!     UNION query with `CredentialStore::list_for_user()`.
//!
//! No existing read or write path is altered by this module's mere presence.
//!
//! ## Tenancy
//!
//! Every method that touches a row sets `app.current_org_id` via
//! [`TenantConn`] so the table's RLS policy (`credentials_tenant_isolation`)
//! is enforced. RLS is the defense-in-depth; the explicit `tenant_id =`
//! predicates in the SQL below are the primary boundary.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use shared_types::{AppError, Result};
use sqlx::{PgPool, Row};

use crate::middleware::tenant_conn::TenantConn;

use super::{CredentialRecord, CredentialStatus, FactorKind};

/// Inputs required to insert a brand-new credential row.
#[derive(Debug, Clone)]
pub struct NewCredential<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub tenant_id: &'a str,
    pub kind: FactorKind,
    pub status: CredentialStatus,
    pub label: Option<&'a str>,
    pub secret_material: Option<&'a str>,
    pub cipher_alg: Option<&'a str>,
    pub public_data: JsonValue,
    /// Set when migrating an existing row — preserves the old id for
    /// audit cross-reference.
    pub legacy_factor_id: Option<&'a str>,
    pub legacy_table: Option<&'a str>,
}

#[derive(Clone)]
pub struct CredentialStore {
    pool: PgPool,
}

impl CredentialStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new credential. Caller is responsible for generating the id
    /// (use `shared_types::generate_id("cred")`).
    pub async fn insert(&self, c: NewCredential<'_>) -> Result<()> {
        let mut conn = TenantConn::acquire(&self.pool, c.tenant_id).await?;

        sqlx::query(
            r#"
            INSERT INTO credentials (
                id, user_id, tenant_id, kind, status, label,
                secret_material, cipher_alg, public_data,
                legacy_factor_id, legacy_table
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(c.id)
        .bind(c.user_id)
        .bind(c.tenant_id)
        .bind(c.kind.as_str())
        .bind(status_str(c.status))
        .bind(c.label)
        .bind(c.secret_material)
        .bind(c.cipher_alg)
        .bind(c.public_data)
        .bind(c.legacy_factor_id)
        .bind(c.legacy_table)
        .execute(&mut **conn)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    /// Fetch one credential by id, scoped to the tenant.
    pub async fn find_by_id(&self, tenant_id: &str, id: &str) -> Result<Option<CredentialRecord>> {
        let mut conn = TenantConn::acquire(&self.pool, tenant_id).await?;

        let row = sqlx::query(
            r#"
            SELECT id, user_id, tenant_id, kind, status, label,
                   created_at, enrolled_at, last_used_at
            FROM credentials
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut **conn)
        .await
        .map_err(map_sqlx)?;

        Ok(row.map(row_to_record))
    }

    /// All credentials for a user in a tenant, regardless of kind.
    pub async fn list_for_user(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<Vec<CredentialRecord>> {
        let mut conn = TenantConn::acquire(&self.pool, tenant_id).await?;

        let rows = sqlx::query(
            r#"
            SELECT id, user_id, tenant_id, kind, status, label,
                   created_at, enrolled_at, last_used_at
            FROM credentials
            WHERE user_id = $1 AND tenant_id = $2 AND status <> 'disabled'
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&mut **conn)
        .await
        .map_err(map_sqlx)?;

        Ok(rows.into_iter().map(row_to_record).collect())
    }

    /// Promote pending → active and stamp `enrolled_at`/`verified_at`.
    pub async fn mark_active(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut conn = TenantConn::acquire(&self.pool, tenant_id).await?;

        sqlx::query(
            r#"
            UPDATE credentials
            SET status = 'active',
                enrolled_at = COALESCE(enrolled_at, NOW()),
                verified_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut **conn)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    /// Stamp `last_used_at = NOW()` after a successful verification.
    pub async fn touch_used(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut conn = TenantConn::acquire(&self.pool, tenant_id).await?;

        sqlx::query(
            r#"
            UPDATE credentials
            SET last_used_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut **conn)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    /// Soft-disable a credential (kept for audit; no longer usable).
    pub async fn disable(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut conn = TenantConn::acquire(&self.pool, tenant_id).await?;

        sqlx::query(
            r#"
            UPDATE credentials
            SET status = 'disabled', disabled_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status <> 'disabled'
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut **conn)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }

    /// Hard delete. Audit rows referencing this credential via
    /// `legacy_factor_id` are unaffected (they live in their own tables).
    pub async fn delete(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut conn = TenantConn::acquire(&self.pool, tenant_id).await?;

        sqlx::query(
            r#"
            DELETE FROM credentials
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut **conn)
        .await
        .map_err(map_sqlx)?;

        Ok(())
    }
}

fn row_to_record(row: sqlx::postgres::PgRow) -> CredentialRecord {
    let kind_s: String = row.get("kind");
    let status_s: String = row.get("status");
    CredentialRecord {
        id: row.get("id"),
        user_id: row.get("user_id"),
        tenant_id: row.get("tenant_id"),
        kind: parse_kind(&kind_s),
        status: parse_status(&status_s),
        created_at: row.get::<DateTime<Utc>, _>("created_at"),
        enrolled_at: row.get::<Option<DateTime<Utc>>, _>("enrolled_at"),
        last_used_at: row.get::<Option<DateTime<Utc>>, _>("last_used_at"),
        label: row.get::<Option<String>, _>("label"),
    }
}

fn parse_kind(s: &str) -> FactorKind {
    match s {
        "totp" => FactorKind::Totp,
        "passkey" => FactorKind::Passkey,
        "sms_otp" => FactorKind::SmsOtp,
        "email_otp" => FactorKind::EmailOtp,
        "backup_codes" => FactorKind::BackupCodes,
        "password" => FactorKind::Password,
        // The CHECK constraint on the column makes this branch unreachable
        // unless the schema is corrupted. Default to Password (the lowest-
        // assurance interpretation) so we never accidentally upgrade trust.
        _ => FactorKind::Password,
    }
}

fn parse_status(s: &str) -> CredentialStatus {
    match s {
        "active" => CredentialStatus::Active,
        "disabled" => CredentialStatus::Disabled,
        _ => CredentialStatus::Pending,
    }
}

fn status_str(s: CredentialStatus) -> &'static str {
    match s {
        CredentialStatus::Active => "active",
        CredentialStatus::Pending => "pending",
        CredentialStatus::Disabled => "disabled",
    }
}

fn map_sqlx(e: sqlx::Error) -> AppError {
    AppError::Internal(format!("credential store: {e}"))
}
