//! SCIM 2.0 Provisioning Service (RFC 7643 / RFC 7644)
//!
//! Inbound SCIM: enterprise IdPs push User and Group records into AuthStar.
//! Each tenant has its own SCIM token(s); the SCIM endpoint is isolated by
//! tenant via RLS (`app.current_org_id`).
//!
//! ## EIAA invariant
//! SCIM only modifies identity data (users, group membership). Authorization
//! to **act** as a provisioned user still flows through the EIAA capsule as
//! normal. Provisioning here cannot grant permissions or bypass policy.
//!
//! ## SQLx note
//! Dynamic (non-macro) query forms are used throughout so that the service
//! compiles before `058_scim_provisioning.sql` has been applied to the dev
//! database. Compile-time SQL verification is deferred to CI (DATABASE_URL
//! pointing at a migrated schema).

use crate::middleware::org_context::set_rls_context_on_conn;
use chrono::{DateTime, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use shared_types::{generate_id, AppError, Result};
use sqlx::PgPool;

// ─── Token types ─────────────────────────────────────────────────────────────

/// A SCIM API token (read-back representation — never includes the raw token).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScimToken {
    pub id: String,
    pub tenant_id: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub created_by: Option<String>,
}

/// Returned once on token creation; `token` is the raw Bearer value.
#[derive(Debug, serde::Serialize)]
pub struct CreatedScimToken {
    pub id: String,
    pub tenant_id: String,
    pub description: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Raw bearer token — returned exactly once, never persisted, never returned again.
    pub token: String,
}

// ─── User types ──────────────────────────────────────────────────────────────

/// Full SCIM User resource (RFC 7643 §4.1).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScimUser {
    pub id: String,
    pub tenant_id: String,
    pub local_user_id: Option<String>,
    pub external_id: Option<String>,
    pub user_name: String,
    pub formatted_name: Option<String>,
    pub family_name: Option<String>,
    pub given_name: Option<String>,
    pub primary_email: Option<String>,
    pub active: bool,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ScimUserWrite {
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub name: Option<ScimNameWrite>,
    pub emails: Option<Vec<ScimEmailWrite>>,
    pub active: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ScimNameWrite {
    pub formatted: Option<String>,
    #[serde(rename = "familyName")]
    pub family_name: Option<String>,
    #[serde(rename = "givenName")]
    pub given_name: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ScimEmailWrite {
    pub value: String,
    pub primary: Option<bool>,
}

// ─── Group types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScimGroup {
    pub id: String,
    pub tenant_id: String,
    pub external_id: Option<String>,
    pub display_name: String,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ScimGroupWrite {
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub members: Option<Vec<ScimGroupMemberWrite>>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ScimGroupMemberWrite {
    pub value: String, // SCIM user id
}

// ─── Pagination ──────────────────────────────────────────────────────────────

#[derive(Debug, Default, serde::Deserialize)]
pub struct ScimListQuery {
    #[serde(rename = "startIndex")]
    pub start_index: Option<i64>,
    pub count: Option<i64>,
    pub filter: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct ScimListResponse<T> {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: i64,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

// ─── Token generation / hashing ──────────────────────────────────────────────

fn generate_scim_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    format!("scim_{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn hash_token(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    hex::encode(digest)
}

// ─── Row helpers (sqlx FromRow for dynamic queries) ──────────────────────────

#[derive(sqlx::FromRow)]
struct ScimUserRow {
    id: String,
    tenant_id: String,
    local_user_id: Option<String>,
    external_id: Option<String>,
    user_name: String,
    formatted_name: Option<String>,
    family_name: Option<String>,
    given_name: Option<String>,
    primary_email: Option<String>,
    active: bool,
    version: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<ScimUserRow> for ScimUser {
    fn from(r: ScimUserRow) -> Self {
        ScimUser {
            id: r.id,
            tenant_id: r.tenant_id,
            local_user_id: r.local_user_id,
            external_id: r.external_id,
            user_name: r.user_name,
            formatted_name: r.formatted_name,
            family_name: r.family_name,
            given_name: r.given_name,
            primary_email: r.primary_email,
            active: r.active,
            version: r.version,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ScimGroupRow {
    id: String,
    tenant_id: String,
    external_id: Option<String>,
    display_name: String,
    version: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<ScimGroupRow> for ScimGroup {
    fn from(r: ScimGroupRow) -> Self {
        ScimGroup {
            id: r.id,
            tenant_id: r.tenant_id,
            external_id: r.external_id,
            display_name: r.display_name,
            version: r.version,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct ScimTokenRow {
    id: String,
    tenant_id: String,
    description: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked: bool,
    created_by: Option<String>,
}

// ─── Service ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScimService {
    db: PgPool,
}

impl ScimService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    // ── helper ────────────────────────────────────────────────────────────

    async fn conn(&self, tenant_id: &str) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        let mut conn = self.db.acquire().await.map_err(AppError::from)?;
        set_rls_context_on_conn(&mut conn, tenant_id)
            .await
            .map_err(|_| AppError::Internal("Set SCIM RLS context".into()))?;
        Ok(conn)
    }

    // ── SCIM Token CRUD ───────────────────────────────────────────────────

    /// Create a new SCIM Bearer token for `tenant_id`. Returns the raw token
    /// exactly once; only the SHA-256 hash is persisted.
    pub async fn create_token(
        &self,
        tenant_id: &str,
        description: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
        created_by: Option<&str>,
    ) -> Result<CreatedScimToken> {
        let raw = generate_scim_token();
        let hash = hash_token(&raw);
        let id = generate_id("sctk");
        let now = Utc::now();
        let mut conn = self.conn(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO scim_tokens (id, tenant_id, token_hash, description, expires_at, created_by, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(&hash)
        .bind(description)
        .bind(expires_at)
        .bind(created_by)
        .bind(now)
        .execute(&mut *conn)
        .await
        .map_err(AppError::from)?;

        Ok(CreatedScimToken {
            id,
            tenant_id: tenant_id.to_string(),
            description: description.map(|s| s.to_string()),
            expires_at,
            created_at: now,
            token: raw,
        })
    }

    /// List all non-revoked tokens for a tenant (hashes are NOT returned).
    pub async fn list_tokens(&self, tenant_id: &str) -> Result<Vec<ScimToken>> {
        let mut conn = self.conn(tenant_id).await?;
        let rows: Vec<ScimTokenRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, description, created_at, expires_at, revoked, created_by
            FROM scim_tokens
            WHERE tenant_id = $1 AND revoked = FALSE
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::from)?;

        Ok(rows
            .into_iter()
            .map(|r| ScimToken {
                id: r.id,
                tenant_id: r.tenant_id,
                description: r.description,
                created_at: r.created_at,
                expires_at: r.expires_at,
                revoked: r.revoked,
                created_by: r.created_by,
            })
            .collect())
    }

    /// Revoke a token by id.
    pub async fn revoke_token(&self, tenant_id: &str, token_id: &str) -> Result<()> {
        let mut conn = self.conn(tenant_id).await?;
        let result =
            sqlx::query("UPDATE scim_tokens SET revoked = TRUE WHERE id = $1 AND tenant_id = $2")
                .bind(token_id)
                .bind(tenant_id)
                .execute(&mut *conn)
                .await
                .map_err(AppError::from)?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("SCIM token not found".to_string()));
        }
        Ok(())
    }

    /// Revoke all active tokens for a tenant (used by disable/rotate-token).
    pub async fn revoke_all_tokens(&self, tenant_id: &str) -> Result<()> {
        let mut conn = self.conn(tenant_id).await?;
        sqlx::query(
            "UPDATE scim_tokens SET revoked = TRUE WHERE tenant_id = $1 AND revoked = FALSE",
        )
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::from)?;
        Ok(())
    }

    /// Validate a raw Bearer token; returns the tenant_id if valid.
    pub async fn validate_token(&self, raw_token: &str) -> Result<String> {
        let hash = hash_token(raw_token);
        let now = Utc::now();
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT tenant_id
            FROM scim_tokens
            WHERE token_hash = $1
              AND revoked = FALSE
              AND (expires_at IS NULL OR expires_at > $2)
            LIMIT 1
            "#,
        )
        .bind(&hash)
        .bind(now)
        .fetch_optional(&self.db)
        .await
        .map_err(AppError::from)?;

        match row {
            Some((tenant_id,)) => Ok(tenant_id),
            None => Err(AppError::Unauthorized(
                "Invalid or expired SCIM token".to_string(),
            )),
        }
    }

    // ── SCIM Users ────────────────────────────────────────────────────────

    /// List SCIM users for a tenant with optional simple `userName` filter.
    pub async fn list_users(
        &self,
        tenant_id: &str,
        query: &ScimListQuery,
    ) -> Result<ScimListResponse<ScimUser>> {
        let start = query.start_index.unwrap_or(1).max(1);
        let limit = query.count.unwrap_or(100).min(200).max(1);
        let offset = start - 1;
        let mut conn = self.conn(tenant_id).await?;

        // Simple filter: userName eq "value" (RFC 7644 §3.4.2.2)
        let username_filter: Option<String> = query.filter.as_deref().and_then(|f| {
            let f = f.trim();
            if f.to_lowercase().starts_with("username eq ") {
                Some(f[12..].trim().trim_matches('"').to_string())
            } else {
                None
            }
        });

        let (total, rows): (i64, Vec<ScimUserRow>) = if let Some(ref uname) = username_filter {
            let cnt: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM scim_users WHERE tenant_id = $1 AND user_name = $2",
            )
            .bind(tenant_id)
            .bind(uname)
            .fetch_one(&mut *conn)
            .await
            .map_err(AppError::from)?;

            let rows: Vec<ScimUserRow> = sqlx::query_as(
                r#"
                SELECT id, tenant_id, local_user_id, external_id, user_name,
                       formatted_name, family_name, given_name, primary_email,
                       active, version, created_at, updated_at
                FROM scim_users
                WHERE tenant_id = $1 AND user_name = $2
                ORDER BY created_at
                LIMIT $3 OFFSET $4
                "#,
            )
            .bind(tenant_id)
            .bind(uname)
            .bind(limit)
            .bind(offset)
            .fetch_all(&mut *conn)
            .await
            .map_err(AppError::from)?;
            (cnt.0, rows)
        } else {
            let cnt: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM scim_users WHERE tenant_id = $1")
                    .bind(tenant_id)
                    .fetch_one(&mut *conn)
                    .await
                    .map_err(AppError::from)?;

            let rows: Vec<ScimUserRow> = sqlx::query_as(
                r#"
                SELECT id, tenant_id, local_user_id, external_id, user_name,
                       formatted_name, family_name, given_name, primary_email,
                       active, version, created_at, updated_at
                FROM scim_users
                WHERE tenant_id = $1
                ORDER BY created_at
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&mut *conn)
            .await
            .map_err(AppError::from)?;
            (cnt.0, rows)
        };

        let resources: Vec<ScimUser> = rows.into_iter().map(ScimUser::from).collect();
        Ok(ScimListResponse {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
            total_results: total,
            start_index: start,
            items_per_page: resources.len() as i64,
            resources,
        })
    }

    pub async fn get_user(&self, tenant_id: &str, scim_user_id: &str) -> Result<ScimUser> {
        let mut conn = self.conn(tenant_id).await?;
        let row: Option<ScimUserRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, local_user_id, external_id, user_name,
                   formatted_name, family_name, given_name, primary_email,
                   active, version, created_at, updated_at
            FROM scim_users
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(scim_user_id)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::from)?;

        row.map(ScimUser::from)
            .ok_or_else(|| AppError::NotFound("SCIM user not found".to_string()))
    }

    /// Create a SCIM user. If a matching `identities` row exists (same email
    /// in this tenant), links to the local user.
    pub async fn create_user(&self, tenant_id: &str, body: &ScimUserWrite) -> Result<ScimUser> {
        let id = generate_id("scu");
        let now = Utc::now();
        let primary_email = extract_primary_email(&body.emails);
        let (formatted, family, given) = extract_name(&body.name);
        let active = body.active.unwrap_or(true);

        // Try to find an existing local user by email via the identities table.
        // The identities table uses `type = 'email'` and `identifier` for the address.
        let local_user_id: Option<String> = if let Some(ref email) = primary_email {
            sqlx::query_as::<_, (String,)>(
                r#"
                SELECT u.id FROM users u
                JOIN identities i ON i.user_id = u.id
                WHERE i.type = 'email'
                  AND i.identifier = $1
                  AND u.tenant_id = $2
                LIMIT 1
                "#,
            )
            .bind(email)
            .bind(tenant_id)
            .fetch_optional(&self.db)
            .await
            .map_err(AppError::from)?
            .map(|(uid,)| uid)
        } else {
            None
        };

        let mut conn = self.conn(tenant_id).await?;
        sqlx::query(
            r#"
            INSERT INTO scim_users (
                id, tenant_id, local_user_id, external_id, user_name,
                formatted_name, family_name, given_name, primary_email,
                active, version, created_at, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)
            "#,
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(&local_user_id)
        .bind(&body.external_id)
        .bind(&body.user_name)
        .bind(&formatted)
        .bind(&family)
        .bind(&given)
        .bind(&primary_email)
        .bind(active)
        .bind("1")
        .bind(now)
        .execute(&mut *conn)
        .await
        .map_err(AppError::from)?;

        drop(conn);
        self.get_user(tenant_id, &id).await
    }

    /// Full replace (PUT) of a SCIM user.
    pub async fn replace_user(
        &self,
        tenant_id: &str,
        scim_user_id: &str,
        body: &ScimUserWrite,
    ) -> Result<ScimUser> {
        let now = Utc::now();
        let primary_email = extract_primary_email(&body.emails);
        let (formatted, family, given) = extract_name(&body.name);
        let active = body.active.unwrap_or(true);

        let current = self.get_user(tenant_id, scim_user_id).await?;
        let new_version = (current.version.parse::<u64>().unwrap_or(0) + 1).to_string();

        let mut conn = self.conn(tenant_id).await?;
        let result = sqlx::query(
            r#"
            UPDATE scim_users SET
                external_id = $3,
                user_name = $4,
                formatted_name = $5,
                family_name = $6,
                given_name = $7,
                primary_email = $8,
                active = $9,
                version = $10,
                updated_at = $11
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(scim_user_id)
        .bind(tenant_id)
        .bind(&body.external_id)
        .bind(&body.user_name)
        .bind(&formatted)
        .bind(&family)
        .bind(&given)
        .bind(&primary_email)
        .bind(active)
        .bind(&new_version)
        .bind(now)
        .execute(&mut *conn)
        .await
        .map_err(AppError::from)?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("SCIM user not found".to_string()));
        }

        drop(conn);
        self.get_user(tenant_id, scim_user_id).await
    }

    /// Soft-delete (deprovision) a SCIM user: sets `active = FALSE`.
    pub async fn delete_user(&self, tenant_id: &str, scim_user_id: &str) -> Result<()> {
        let mut conn = self.conn(tenant_id).await?;
        let result = sqlx::query(
            "UPDATE scim_users SET active = FALSE, updated_at = NOW() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(scim_user_id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::from)?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("SCIM user not found".to_string()));
        }
        Ok(())
    }

    // ── SCIM Groups ───────────────────────────────────────────────────────

    pub async fn list_groups(
        &self,
        tenant_id: &str,
        query: &ScimListQuery,
    ) -> Result<ScimListResponse<ScimGroup>> {
        let start = query.start_index.unwrap_or(1).max(1);
        let limit = query.count.unwrap_or(100).min(200).max(1);
        let offset = start - 1;
        let mut conn = self.conn(tenant_id).await?;

        let cnt: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM scim_groups WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(AppError::from)?;

        let rows: Vec<ScimGroupRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, external_id, display_name, version, created_at, updated_at
            FROM scim_groups
            WHERE tenant_id = $1
            ORDER BY created_at
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::from)?;

        let resources: Vec<ScimGroup> = rows.into_iter().map(ScimGroup::from).collect();
        Ok(ScimListResponse {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
            total_results: cnt.0,
            start_index: start,
            items_per_page: resources.len() as i64,
            resources,
        })
    }

    pub async fn get_group(&self, tenant_id: &str, group_id: &str) -> Result<ScimGroup> {
        let mut conn = self.conn(tenant_id).await?;
        let row: Option<ScimGroupRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, external_id, display_name, version, created_at, updated_at
            FROM scim_groups
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(group_id)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::from)?;

        row.map(ScimGroup::from)
            .ok_or_else(|| AppError::NotFound("SCIM group not found".to_string()))
    }

    pub async fn create_group(&self, tenant_id: &str, body: &ScimGroupWrite) -> Result<ScimGroup> {
        let id = generate_id("scg");
        let now = Utc::now();
        let mut conn = self.conn(tenant_id).await?;

        sqlx::query(
            r#"
            INSERT INTO scim_groups (id, tenant_id, external_id, display_name, version, created_at, updated_at)
            VALUES ($1, $2, $3, $4, '1', $5, $5)
            "#,
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(&body.external_id)
        .bind(&body.display_name)
        .bind(now)
        .execute(&mut *conn)
        .await
        .map_err(AppError::from)?;

        if let Some(ref members) = body.members {
            self.set_group_members_conn(&mut conn, &id, members).await?;
        }

        drop(conn);
        self.get_group(tenant_id, &id).await
    }

    pub async fn replace_group(
        &self,
        tenant_id: &str,
        group_id: &str,
        body: &ScimGroupWrite,
    ) -> Result<ScimGroup> {
        let current = self.get_group(tenant_id, group_id).await?;
        let new_version = (current.version.parse::<u64>().unwrap_or(0) + 1).to_string();
        let now = Utc::now();
        let mut conn = self.conn(tenant_id).await?;

        let result = sqlx::query(
            r#"
            UPDATE scim_groups
            SET external_id = $3, display_name = $4, version = $5, updated_at = $6
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(group_id)
        .bind(tenant_id)
        .bind(&body.external_id)
        .bind(&body.display_name)
        .bind(&new_version)
        .bind(now)
        .execute(&mut *conn)
        .await
        .map_err(AppError::from)?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("SCIM group not found".to_string()));
        }

        sqlx::query("DELETE FROM scim_group_members WHERE group_id = $1")
            .bind(group_id)
            .execute(&mut *conn)
            .await
            .map_err(AppError::from)?;

        if let Some(ref members) = body.members {
            self.set_group_members_conn(&mut conn, group_id, members)
                .await?;
        }

        drop(conn);
        self.get_group(tenant_id, group_id).await
    }

    pub async fn delete_group(&self, tenant_id: &str, group_id: &str) -> Result<()> {
        let mut conn = self.conn(tenant_id).await?;
        let result = sqlx::query("DELETE FROM scim_groups WHERE id = $1 AND tenant_id = $2")
            .bind(group_id)
            .bind(tenant_id)
            .execute(&mut *conn)
            .await
            .map_err(AppError::from)?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("SCIM group not found".to_string()));
        }
        Ok(())
    }

    // ── private helpers ───────────────────────────────────────────────────

    async fn set_group_members_conn(
        &self,
        conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
        group_id: &str,
        members: &[ScimGroupMemberWrite],
    ) -> Result<()> {
        for m in members {
            sqlx::query(
                r#"
                INSERT INTO scim_group_members (group_id, user_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                "#,
            )
            .bind(group_id)
            .bind(&m.value)
            .execute(&mut **conn)
            .await
            .map_err(AppError::from)?;
        }
        Ok(())
    }
}

// ─── Helper functions ─────────────────────────────────────────────────────────

fn extract_primary_email(emails: &Option<Vec<ScimEmailWrite>>) -> Option<String> {
    let list = emails.as_ref()?;
    list.iter()
        .find(|e| e.primary == Some(true))
        .or_else(|| list.first())
        .map(|e| e.value.to_lowercase())
}

fn extract_name(name: &Option<ScimNameWrite>) -> (Option<String>, Option<String>, Option<String>) {
    match name {
        None => (None, None, None),
        Some(n) => (
            n.formatted.clone(),
            n.family_name.clone(),
            n.given_name.clone(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email(value: &str, primary: bool) -> ScimEmailWrite {
        ScimEmailWrite {
            value: value.to_string(),
            primary: Some(primary),
        }
    }

    // T3 SCIM — token hashing is deterministic
    #[test]
    fn test_scim_token_hash_deterministic() {
        let raw = "scim_abc123xyz";
        let h1 = hash_token(raw);
        let h2 = hash_token(raw);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }

    // T3 SCIM — generated tokens have scim_ prefix
    #[test]
    fn test_scim_token_format() {
        let tok = generate_scim_token();
        assert!(tok.starts_with("scim_"));
        assert!(tok.len() > 10);
    }

    // T3 SCIM — different tokens produce different hashes
    #[test]
    fn test_scim_token_hash_unique() {
        let t1 = generate_scim_token();
        let t2 = generate_scim_token();
        assert_ne!(t1, t2);
        assert_ne!(hash_token(&t1), hash_token(&t2));
    }

    // T3 SCIM — extract_primary_email: None on empty
    #[test]
    fn test_extract_primary_email_none() {
        assert_eq!(extract_primary_email(&None), None);
        assert_eq!(extract_primary_email(&Some(vec![])), None);
    }

    // T3 SCIM — extract_primary_email: single entry lowercased
    #[test]
    fn test_extract_primary_email_single() {
        let emails = Some(vec![email("Alice@Example.COM", false)]);
        assert_eq!(
            extract_primary_email(&emails),
            Some("alice@example.com".to_string())
        );
    }

    // T3 SCIM — extract_primary_email: prefers primary:true
    #[test]
    fn test_extract_primary_email_prefers_primary() {
        let emails = Some(vec![
            email("secondary@example.com", false),
            email("primary@example.com", true),
        ]);
        assert_eq!(
            extract_primary_email(&emails),
            Some("primary@example.com".to_string())
        );
    }

    // T3 SCIM — extract_name: None produces (None, None, None)
    #[test]
    fn test_extract_name_none() {
        let (f, fam, giv) = extract_name(&None);
        assert!(f.is_none());
        assert!(fam.is_none());
        assert!(giv.is_none());
    }

    // T3 SCIM — extract_name: fields forwarded correctly
    #[test]
    fn test_extract_name_fields() {
        let name = ScimNameWrite {
            formatted: Some("John Doe".to_string()),
            family_name: Some("Doe".to_string()),
            given_name: Some("John".to_string()),
        };
        let (f, fam, giv) = extract_name(&Some(name));
        assert_eq!(f, Some("John Doe".to_string()));
        assert_eq!(fam, Some("Doe".to_string()));
        assert_eq!(giv, Some("John".to_string()));
    }

    // T3 SCIM — version bumping
    #[test]
    fn test_version_bump() {
        let v: u64 = "1".parse().unwrap_or(0) + 1;
        assert_eq!(v.to_string(), "2");
    }
}
