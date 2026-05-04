//! T2.8 — Client Scope service (Repository pattern over Postgres).
//!
//! Reusable per-tenant scope objects + per-client default/optional mappings.
//! Sits *beside* the legacy `applications.allowed_scopes` JSON array — the
//! latter is still read by `OAuthAsService::resolve_scopes` for back-compat.
//! New behaviour: the AS may also call [`ClientScopeService::resolve_with_mappings`]
//! to layer in defaults + optional-by-request semantics on top.
//!
//! ## EIAA invariant
//! Scopes remain **hints**. The capsule still decides authorization. Nothing
//! in this module produces tokens; it only shapes the requested-scope set
//! that the AS forwards as `RuntimeContext.requested_scope`.

use crate::middleware::org_context::set_rls_context_on_conn;
use shared_types::{generate_id, AppError, Result};
use sqlx::PgPool;

/// Default vs optional mapping kind, mirroring the SQL CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Default,
    Optional,
}

impl ScopeKind {
    fn as_str(self) -> &'static str {
        match self {
            ScopeKind::Default => "default",
            ScopeKind::Optional => "optional",
        }
    }
}

/// A reusable per-tenant scope definition.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ClientScope {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub protocol: String,
    pub include_in_new_clients: bool,
}

#[derive(Debug, Clone)]
pub struct ClientScopeService {
    db: PgPool,
}

impl ClientScopeService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    async fn tenant_conn(
        &self,
        tenant_id: &str,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        let mut conn = self
            .db
            .acquire()
            .await
            .map_err(|e| AppError::Internal(format!("DB pool acquire failed: {e}")))?;
        set_rls_context_on_conn(&mut conn, tenant_id)
            .await
            .map_err(|e| AppError::Internal(format!("RLS context set failed: {e}")))?;
        Ok(conn)
    }

    // ─── CRUD on ClientScope ────────────────────────────────────────────────

    pub async fn create_scope(
        &self,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
        include_in_new_clients: bool,
    ) -> Result<ClientScope> {
        let id = generate_id("cs");
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO client_scopes
                   (id, tenant_id, name, description, protocol, include_in_new_clients)
               VALUES ($1, $2, $3, $4, 'oauth2', $5)"#,
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(name)
        .bind(description)
        .bind(include_in_new_clients)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("create_scope failed: {e}")))?;
        Ok(ClientScope {
            id,
            tenant_id: tenant_id.to_string(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            protocol: "oauth2".to_string(),
            include_in_new_clients,
        })
    }

    pub async fn list_scopes(&self, tenant_id: &str) -> Result<Vec<ClientScope>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, ClientScope>(
            r#"SELECT id, tenant_id, name, description, protocol, include_in_new_clients
                 FROM client_scopes
                WHERE tenant_id = $1
             ORDER BY name"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("list_scopes failed: {e}")))?;
        Ok(rows)
    }

    pub async fn delete_scope(&self, tenant_id: &str, name: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        // Mappings reference by scope_name; remove them first so we don't
        // leave orphans (no FK between the two tables — by design, since
        // mappings can predate the scope row in import scenarios).
        sqlx::query(
            r#"DELETE FROM client_scope_mappings
                WHERE tenant_id = $1 AND scope_name = $2"#,
        )
        .bind(tenant_id)
        .bind(name)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("delete mappings failed: {e}")))?;
        sqlx::query(r#"DELETE FROM client_scopes WHERE tenant_id = $1 AND name = $2"#)
            .bind(tenant_id)
            .bind(name)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Internal(format!("delete_scope failed: {e}")))?;
        Ok(())
    }

    // ─── Per-client mapping ────────────────────────────────────────────────

    pub async fn assign(
        &self,
        tenant_id: &str,
        client_id: &str,
        scope_name: &str,
        kind: ScopeKind,
    ) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"INSERT INTO client_scope_mappings
                   (client_id, tenant_id, scope_name, kind)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (client_id, scope_name)
               DO UPDATE SET kind = EXCLUDED.kind"#,
        )
        .bind(client_id)
        .bind(tenant_id)
        .bind(scope_name)
        .bind(kind.as_str())
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("assign mapping failed: {e}")))?;
        Ok(())
    }

    pub async fn unassign(&self, tenant_id: &str, client_id: &str, scope_name: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"DELETE FROM client_scope_mappings
                WHERE tenant_id = $1 AND client_id = $2 AND scope_name = $3"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(scope_name)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("unassign failed: {e}")))?;
        Ok(())
    }

    /// Returns (defaults, optionals) for a client in this tenant.
    pub async fn mappings_for_client(
        &self,
        tenant_id: &str,
        client_id: &str,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows: Vec<(String, String)> = sqlx::query_as(
            r#"SELECT scope_name, kind
                 FROM client_scope_mappings
                WHERE tenant_id = $1 AND client_id = $2"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("mappings_for_client failed: {e}")))?;
        let mut defaults = Vec::new();
        let mut optionals = Vec::new();
        for (name, kind) in rows {
            match kind.as_str() {
                "default" => defaults.push(name),
                "optional" => optionals.push(name),
                // unknown kind — ignore (fail-closed: do not grant)
                _ => {}
            }
        }
        Ok((defaults, optionals))
    }

    /// Layer client-scope defaults + optional-by-request semantics on top of
    /// the per-app `allowed_scopes` filter.
    ///
    /// Algorithm:
    ///   1. Start with `app_allowed`: the result of the legacy
    ///      `OAuthAsService::resolve_scopes` (already intersected against the
    ///      app-level allow-list).
    ///   2. UNION every `default` scope mapped to this client (always
    ///      granted, even if the client did not request it).
    ///   3. INTERSECT every `optional` scope with `requested` — only grant
    ///      those that the client both has mapped *and* asked for.
    ///   4. Deduplicate; preserve insertion order so `openid` (commonly the
    ///      first default) stays first when present.
    pub async fn resolve_with_mappings(
        &self,
        tenant_id: &str,
        client_id: &str,
        requested: &str,
        app_allowed: &str,
    ) -> Result<String> {
        let (defaults, optionals) = self
            .mappings_for_client(tenant_id, client_id)
            .await
            .unwrap_or_else(|err| {
                // Fail-closed: if the lookup fails, do not extend the allow set.
                tracing::warn!(error = %err, client_id, "client_scope lookup failed; falling back to app_allowed only");
                (Vec::new(), Vec::new())
            });
        let requested_set: std::collections::HashSet<&str> = requested.split_whitespace().collect();
        let mut out: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        // 1) Defaults first — always granted.
        for s in &defaults {
            if seen.insert(s.clone()) {
                out.push(s.clone());
            }
        }
        // 2) App-allowed (already intersected with request) — append.
        for s in app_allowed.split_whitespace() {
            if seen.insert(s.to_string()) {
                out.push(s.to_string());
            }
        }
        // 3) Optionals — only when explicitly requested.
        for s in &optionals {
            if requested_set.contains(s.as_str()) && seen.insert(s.clone()) {
                out.push(s.clone());
            }
        }
        Ok(out.join(" "))
    }
}
