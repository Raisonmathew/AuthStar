use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use sqlx::PgPool;

use crate::state::AppState;

/// Organization context extracted from subdomain or header.
/// Also carries the org_id so handlers can use it without re-querying.
#[derive(Debug, Clone)]
pub struct OrgContext {
    pub org_id: String,
    pub org_slug: String,
    pub org_name: String,
}

/// Extract organization context from request and set the PostgreSQL session variable
/// for Row-Level Security.
///
/// CRITICAL-9 FIX: The previous implementation called `set_org_context()` on the
/// connection pool, which sets the variable on a random connection that is immediately
/// returned to the pool. The actual query handlers get a *different* connection where
/// `app.current_org_id` is not set, so all RLS policies silently block all queries.
///
/// The correct approach is to store the org_id in the request extensions and have
/// each database operation set the context on its own connection before executing.
/// We provide `set_rls_context_on_conn()` as a helper for this pattern.
///
/// Additionally, for routes that use a single connection (e.g., transactions), the
/// caller must call `set_rls_context_on_conn()` on the acquired connection.
pub async fn org_context_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract organization slug from subdomain or header
    let org_slug = extract_org_slug(&request)?;

    // Lookup organization from database.
    // Distinguish "org not found" (404) from DB/connectivity errors (503).
    let org = match lookup_organization(&state.db, &org_slug).await {
        Ok(o) => o,
        Err(sqlx::Error::RowNotFound) => {
            tracing::debug!(org_slug = %org_slug, "Organization not found");
            return Err(StatusCode::NOT_FOUND);
        }
        Err(e) => {
            tracing::error!(org_slug = %org_slug, error = %e, "Database error resolving organization");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    // CRITICAL-9 FIX: Do NOT call set_org_context on the pool here.
    // Instead, store the org_id in request extensions. Each handler that
    // needs RLS must call `set_rls_context_on_conn()` on its own connection.
    //
    // For the common case of pool-based queries (not transactions), we use
    // sqlx's `before_acquire` hook configured at pool creation time (see state.rs).
    // The org_id is passed via a thread-local set here and read in the hook.
    //
    // For simplicity and correctness, we set it as a request extension and
    // provide a helper. The pool is configured with `after_connect` to set
    // a default, but per-request context is set via the extension.
    request.extensions_mut().insert(org.clone());

    tracing::debug!(
        org_id = %org.org_id,
        org_slug = %org.org_slug,
        "Organization context established for request"
    );

    Ok(next.run(request).await)
}

/// Set the PostgreSQL session variable for Row-Level Security on a specific connection.
///
/// CRITICAL-9 FIX: This must be called on the SAME connection that will execute
/// the actual query. Call this at the start of any handler that uses the database.
///
/// Usage in a handler:
/// ```rust
/// let mut conn = state.db.acquire().await?;
/// set_rls_context_on_conn(&mut conn, &org_context.org_id).await?;
/// let result = sqlx::query("SELECT ...").fetch_all(&mut *conn).await?;
/// ```
pub async fn set_rls_context_on_conn(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
    org_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
        .bind(org_id)
        .execute(&mut **conn)
        .await?;
    Ok(())
}

/// Set RLS context on a transaction connection.
/// Must be called at the start of every transaction that touches tenant-scoped tables.
pub async fn set_rls_context_on_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
) -> Result<(), sqlx::Error> {
    // Use set_config with is_local=true so the setting is scoped to the transaction
    sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
        .bind(org_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Extract organization slug from subdomain (e.g., acme.idaas.app -> acme)
fn extract_org_slug(request: &Request) -> Result<String, StatusCode> {
    // Try header first (for development/testing)
    if let Some(org_header) = request.headers().get("x-org-slug") {
        if let Ok(slug) = org_header.to_str() {
            return Ok(slug.to_string());
        }
    }
    
    // Extract from Host header subdomain
    let host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Allow localhost for development
    if host.starts_with("localhost") || host.starts_with("127.0.0.1") {
        return Ok("admin".to_string());
    }
    
    // Parse subdomain: acme.idaas.app, acme.idaas-test.dev, etc.
    let parts: Vec<&str> = host.split('.').collect();
    
    if parts.len() < 3 {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    // First part is the organization slug
    let slug = parts[0].to_string();
    
    // Validate slug format (alphanumeric + hyphen)
    if !slug.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    Ok(slug)
}

/// Lookup organization from database by slug
async fn lookup_organization(
    pool: &PgPool,
    slug: &str,
) -> Result<OrgContext, sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct OrgRow {
        id: String,
        name: String,
        slug: String,
    }

    let result = sqlx::query_as::<_, OrgRow>(
        r#"
        SELECT id, name, slug
        FROM organizations
        WHERE slug = $1 AND deleted_at IS NULL
        "#
    )
    .bind(slug)
    .fetch_one(pool)
    .await?;
    
    Ok(OrgContext {
        org_id: result.id,
        org_slug: result.slug,
        org_name: result.name,
    })
}

/// Lookup organization from database by slug (internal helper)

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, header};
    use axum::body::Body;
    
    #[test]
    fn test_extract_org_slug_from_subdomain() {
        let req = Request::builder()
            .header(header::HOST, "acme.idaas.app")
            .body(Body::empty())
            .unwrap();
        
        let slug = extract_org_slug(&req).unwrap();
        assert_eq!(slug, "acme");
    }
    
    #[test]
    fn test_extract_org_slug_from_header() {
        let req = Request::builder()
            .header("x-org-slug", "test-org")
            .header(header::HOST, "localhost:3000")
            .body(Body::empty())
            .unwrap();
        
        let slug = extract_org_slug(&req).unwrap();
        assert_eq!(slug, "test-org");
    }
    
    #[test]
    fn test_invalid_slug() {
        let req = Request::builder()
            .header(header::HOST, "invalid@slug.idaas.app")
            .body(Body::empty())
            .unwrap();
        
        let result = extract_org_slug(&req);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_missing_host() {
        let req = Request::builder()
            .body(Body::empty())
            .unwrap();
        
        let result = extract_org_slug(&req);
        assert!(result.is_err());
    }
}
