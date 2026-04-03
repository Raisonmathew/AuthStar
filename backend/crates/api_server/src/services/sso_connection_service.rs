use shared_types::AppError;
use sqlx::{PgPool, Row};
use crate::services::sso_encryption::SsoEncryption;

/// Validate that a string looks like a valid URL (has a scheme + authority).
fn is_valid_url(s: &str) -> bool {
    let s = s.trim();
    (s.starts_with("https://") || s.starts_with("http://")) && s.len() > 10
}

/// Tenant-scoped SSO connection data model.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SsoConnection {
    pub id: String,
    pub tenant_id: String,
    pub r#type: String,
    pub provider: String,
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub discovery_url: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scope: Option<String>,
    pub enabled: bool,
    pub config: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateConnectionParams {
    pub r#type: String,
    pub provider: String,
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub discovery_url: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scope: Option<String>,
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateConnectionParams {
    pub name: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub discovery_url: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scope: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<serde_json::Value>,
}

#[derive(Clone)]
pub struct SsoConnectionService {
    db: PgPool,
}

impl SsoConnectionService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// List all SSO connections for a tenant. Client secrets are redacted.
    pub async fn list(&self, tenant_id: &str) -> Result<Vec<SsoConnection>, AppError> {
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, type, provider, name, client_id, client_secret,
                   redirect_uri, discovery_url, authorization_url, token_url, userinfo_url,
                   scope, enabled, config, created_at
            FROM sso_connections
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(rows.into_iter().map(|row| Self::row_to_connection_redacted(&row)).collect())
    }

    /// Get a single SSO connection by ID, scoped to tenant. Secret redacted.
    pub async fn get(&self, id: &str, tenant_id: &str) -> Result<SsoConnection, AppError> {
        let row = sqlx::query(
            "SELECT * FROM sso_connections WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::NotFound("Connection not found".into()))?;

        Ok(Self::row_to_connection_redacted(&row))
    }

    /// Create an SSO connection. Client secret is encrypted before storage.
    pub async fn create(
        &self,
        tenant_id: &str,
        params: &CreateConnectionParams,
    ) -> Result<SsoConnection, AppError> {
        if !["oauth", "oidc", "saml"].contains(&params.r#type.as_str()) {
            return Err(AppError::Validation(
                "Invalid type. Must be oauth, oidc, or saml".into(),
            ));
        }

        // Validate required fields
        if params.client_id.trim().is_empty() {
            return Err(AppError::Validation("client_id must not be empty".into()));
        }
        if params.name.trim().is_empty() {
            return Err(AppError::Validation("name must not be empty".into()));
        }

        // Validate redirect_uri is a valid URL
        if !params.redirect_uri.trim().is_empty() {
            if !is_valid_url(&params.redirect_uri) {
                return Err(AppError::Validation("redirect_uri must be a valid URL".into()));
            }
        }

        // Validate optional URL fields
        let validate_optional_url = |url: &Option<String>, field: &str| -> Result<(), AppError> {
            if let Some(ref u) = url {
                if !u.trim().is_empty() && !is_valid_url(u) {
                    return Err(AppError::Validation(format!("{field} must be a valid URL")));
                }
            }
            Ok(())
        };
        validate_optional_url(&params.discovery_url, "discovery_url")?;
        validate_optional_url(&params.authorization_url, "authorization_url")?;
        validate_optional_url(&params.token_url, "token_url")?;
        validate_optional_url(&params.userinfo_url, "userinfo_url")?;

        // For SAML type, validate certificate in config if provided
        if params.r#type == "saml" {
            if let Some(ref config) = params.config {
                if let Some(cert) = config.get("idp_certificate").and_then(|c| c.as_str()) {
                    if !cert.contains("BEGIN CERTIFICATE") || !cert.contains("END CERTIFICATE") {
                        return Err(AppError::Validation(
                            "SAML idp_certificate must be a valid PEM-encoded X.509 certificate".into(),
                        ));
                    }
                }
            }
        }

        let id = shared_types::id_generator::generate_id("sso");
        let config_json = params.config.clone().unwrap_or(serde_json::json!({}));

        let enc = SsoEncryption::from_env();
        let encrypted_secret = enc
            .encrypt(&params.client_secret)
            .map_err(|e| AppError::Internal(format!("Failed to encrypt SSO secret: {e}")))?;

        sqlx::query(
            r#"
            INSERT INTO sso_connections (
                id, tenant_id, type, provider, name, client_id, client_secret,
                redirect_uri, discovery_url, authorization_url, token_url, userinfo_url,
                scope, config
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(&params.r#type)
        .bind(&params.provider)
        .bind(&params.name)
        .bind(&params.client_id)
        .bind(&encrypted_secret)
        .bind(&params.redirect_uri)
        .bind(&params.discovery_url)
        .bind(&params.authorization_url)
        .bind(&params.token_url)
        .bind(&params.userinfo_url)
        .bind(&params.scope)
        .bind(&config_json)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

        Ok(SsoConnection {
            id,
            tenant_id: tenant_id.to_string(),
            r#type: params.r#type.clone(),
            provider: params.provider.clone(),
            name: params.name.clone(),
            client_id: params.client_id.clone(),
            client_secret: "***configured***".to_string(),
            redirect_uri: params.redirect_uri.clone(),
            discovery_url: params.discovery_url.clone(),
            authorization_url: params.authorization_url.clone(),
            token_url: params.token_url.clone(),
            userinfo_url: params.userinfo_url.clone(),
            scope: params.scope.clone(),
            enabled: true,
            config: Some(config_json),
            created_at: chrono::Utc::now(),
        })
    }

    /// Update an SSO connection with a single dynamic query.
    /// All fields are optional — only provided fields are updated.
    pub async fn update(
        &self,
        id: &str,
        tenant_id: &str,
        params: &UpdateConnectionParams,
    ) -> Result<(), AppError> {
        // Build dynamic SET clause — only include fields that are Some
        let mut set_clauses: Vec<String> = Vec::new();
        let mut bind_idx: u32 = 1;

        // We collect bind values as trait objects for dynamic binding
        // Using a simple approach: build the SQL string, then bind in order
        macro_rules! push_field {
            ($field:expr, $col:expr) => {
                if $field.is_some() {
                    set_clauses.push(format!("{} = ${}", $col, bind_idx));
                    bind_idx += 1;
                }
            };
        }

        push_field!(&params.name, "name");
        push_field!(&params.client_id, "client_id");
        push_field!(&params.client_secret, "client_secret");
        push_field!(&params.redirect_uri, "redirect_uri");
        push_field!(&params.discovery_url, "discovery_url");
        push_field!(&params.authorization_url, "authorization_url");
        push_field!(&params.token_url, "token_url");
        push_field!(&params.userinfo_url, "userinfo_url");
        push_field!(&params.scope, "scope");
        push_field!(&params.enabled, "enabled");
        push_field!(&params.config, "config");

        if set_clauses.is_empty() {
            return Ok(());
        }

        let id_idx = bind_idx;
        let tenant_idx = bind_idx + 1;
        let sql = format!(
            "UPDATE sso_connections SET {} WHERE id = ${} AND tenant_id = ${}",
            set_clauses.join(", "),
            id_idx,
            tenant_idx
        );

        // Encrypt client_secret if provided
        let encrypted_secret = if let Some(ref secret) = params.client_secret {
            let enc = SsoEncryption::from_env();
            Some(
                enc.encrypt(secret)
                    .map_err(|e| AppError::Internal(format!("Failed to encrypt SSO secret: {e}")))?,
            )
        } else {
            None
        };

        // Build query and bind values in the same order as set_clauses
        let mut query = sqlx::query(&sql);

        if let Some(ref v) = params.name {
            query = query.bind(v);
        }
        if let Some(ref v) = params.client_id {
            query = query.bind(v);
        }
        if let Some(ref _v) = params.client_secret {
            let enc = encrypted_secret.as_ref()
                .ok_or_else(|| AppError::Internal("Encryption produced None for client_secret".into()))?;
            query = query.bind(enc);
        }
        if let Some(ref v) = params.redirect_uri {
            query = query.bind(v);
        }
        if let Some(ref v) = params.discovery_url {
            query = query.bind(v);
        }
        if let Some(ref v) = params.authorization_url {
            query = query.bind(v);
        }
        if let Some(ref v) = params.token_url {
            query = query.bind(v);
        }
        if let Some(ref v) = params.userinfo_url {
            query = query.bind(v);
        }
        if let Some(ref v) = params.scope {
            query = query.bind(v);
        }
        if let Some(ref v) = params.enabled {
            query = query.bind(v);
        }
        if let Some(ref v) = params.config {
            query = query.bind(v);
        }

        // Bind WHERE clause params
        query = query.bind(id);
        query = query.bind(tenant_id);

        let result = query
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Connection not found".into()));
        }

        Ok(())
    }

    /// Delete an SSO connection, scoped to tenant.
    pub async fn delete(&self, id: &str, tenant_id: &str) -> Result<(), AppError> {
        let result =
            sqlx::query("DELETE FROM sso_connections WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_id)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Connection not found".into()));
        }

        Ok(())
    }

    /// Map a database row to `SsoConnection` with client_secret redacted.
    fn row_to_connection_redacted(row: &sqlx::postgres::PgRow) -> SsoConnection {
        let stored_secret: String = row.get("client_secret");
        let secret_display = if stored_secret.is_empty() {
            String::new()
        } else {
            "***configured***".to_string()
        };

        SsoConnection {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            r#type: row.get("type"),
            provider: row.get("provider"),
            name: row.get("name"),
            client_id: row.get("client_id"),
            client_secret: secret_display,
            redirect_uri: row.get("redirect_uri"),
            discovery_url: row.get("discovery_url"),
            authorization_url: row.get("authorization_url"),
            token_url: row.get("token_url"),
            userinfo_url: row.get("userinfo_url"),
            scope: row.get("scope"),
            enabled: row.get("enabled"),
            config: row.get("config"),
            created_at: row.get("created_at"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_valid_url ──────────────────────────────────────────────────────

    #[test]
    fn valid_https_url() {
        assert!(is_valid_url("https://example.com"));
    }

    #[test]
    fn valid_http_url() {
        assert!(is_valid_url("http://example.com"));
    }

    #[test]
    fn rejects_empty_string() {
        assert!(!is_valid_url(""));
    }

    #[test]
    fn rejects_no_scheme() {
        assert!(!is_valid_url("example.com"));
    }

    #[test]
    fn rejects_ftp_scheme() {
        assert!(!is_valid_url("ftp://example.com"));
    }

    #[test]
    fn rejects_too_short_url() {
        // "http://a.b" is exactly 10 chars — boundary condition (needs > 10)
        assert!(!is_valid_url("http://a.b"));
    }

    #[test]
    fn accepts_url_with_path() {
        assert!(is_valid_url("https://idp.example.com/.well-known/openid-configuration"));
    }

    #[test]
    fn trims_whitespace() {
        assert!(is_valid_url("  https://example.com  "));
    }

    // ── CreateConnectionParams validation (via create()) ─────────────────
    // These tests validate the pure validation logic in create().
    // Since create() requires a DB pool, we test indirectly by verifying
    // that validation errors are returned before any DB access.

    fn make_params(overrides: impl FnOnce(&mut CreateConnectionParams)) -> CreateConnectionParams {
        let mut p = CreateConnectionParams {
            r#type: "oidc".into(),
            provider: "test-provider".into(),
            name: "My Connection".into(),
            client_id: "client_123".into(),
            client_secret: "secret_456".into(),
            redirect_uri: "https://app.example.com/callback".into(),
            discovery_url: None,
            authorization_url: None,
            token_url: None,
            userinfo_url: None,
            scope: Some("openid profile email".into()),
            config: None,
        };
        overrides(&mut p);
        p
    }

    /// Validation rejects invalid connection type before touching DB.
    #[tokio::test]
    async fn test_create_rejects_invalid_type() {
        // We create a service with a dummy pool that will never be used
        // because validation fails before any DB call.
        let pool = PgPool::connect_lazy("postgres://invalid:5432/fake").unwrap();
        let svc = SsoConnectionService::new(pool);
        let params = make_params(|p| p.r#type = "ldap".into());

        let err = svc.create("tenant_1", &params).await.unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("Invalid type"), "got: {msg}"),
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_create_rejects_empty_client_id() {
        let pool = PgPool::connect_lazy("postgres://invalid:5432/fake").unwrap();
        let svc = SsoConnectionService::new(pool);
        let params = make_params(|p| p.client_id = "  ".into());

        let err = svc.create("tenant_1", &params).await.unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("client_id"), "got: {msg}"),
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_create_rejects_empty_name() {
        let pool = PgPool::connect_lazy("postgres://invalid:5432/fake").unwrap();
        let svc = SsoConnectionService::new(pool);
        let params = make_params(|p| p.name = "".into());

        let err = svc.create("tenant_1", &params).await.unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("name"), "got: {msg}"),
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_create_rejects_invalid_redirect_uri() {
        let pool = PgPool::connect_lazy("postgres://invalid:5432/fake").unwrap();
        let svc = SsoConnectionService::new(pool);
        let params = make_params(|p| p.redirect_uri = "not-a-url".into());

        let err = svc.create("tenant_1", &params).await.unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("redirect_uri"), "got: {msg}"),
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_create_rejects_invalid_optional_url() {
        let pool = PgPool::connect_lazy("postgres://invalid:5432/fake").unwrap();
        let svc = SsoConnectionService::new(pool);
        let params = make_params(|p| p.discovery_url = Some("bad".into()));

        let err = svc.create("tenant_1", &params).await.unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("discovery_url"), "got: {msg}"),
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_create_rejects_invalid_saml_certificate() {
        let pool = PgPool::connect_lazy("postgres://invalid:5432/fake").unwrap();
        let svc = SsoConnectionService::new(pool);
        let params = make_params(|p| {
            p.r#type = "saml".into();
            p.config = Some(serde_json::json!({
                "idp_certificate": "this is not a PEM cert"
            }));
        });

        let err = svc.create("tenant_1", &params).await.unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("PEM"), "got: {msg}"),
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_create_accepts_valid_saml_certificate() {
        let pool = PgPool::connect_lazy("postgres://invalid:5432/fake").unwrap();
        let svc = SsoConnectionService::new(pool);
        let params = make_params(|p| {
            p.r#type = "saml".into();
            p.config = Some(serde_json::json!({
                "idp_certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
            }));
        });

        // This will fail at the DB/encryption stage, not at validation
        let err = svc.create("tenant_1", &params).await.unwrap_err();
        // Should NOT be a Validation error — validation passed
        match err {
            AppError::Validation(_) => panic!("Should not fail validation with valid PEM cert"),
            _ => {} // Internal/DB error expected — that's fine
        }
    }

    #[tokio::test]
    async fn test_create_allows_empty_redirect_uri() {
        let pool = PgPool::connect_lazy("postgres://invalid:5432/fake").unwrap();
        let svc = SsoConnectionService::new(pool);
        let params = make_params(|p| p.redirect_uri = "".into());

        let err = svc.create("tenant_1", &params).await.unwrap_err();
        // Should not be a redirect_uri validation error
        match err {
            AppError::Validation(msg) if msg.contains("redirect_uri") => {
                panic!("Empty redirect_uri should be allowed, got: {msg}")
            }
            _ => {} // DB/encryption error expected
        }
    }
}
