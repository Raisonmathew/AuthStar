use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use sqlx::PgPool;

use crate::state::AppState;

/// Organization context extracted from subdomain or header
#[derive(Debug, Clone)]
pub struct OrgContext {
    pub org_id: String,
    pub org_slug: String,
    pub org_name: String,
}

/// Extract organization context from request and set database context
pub async fn org_context_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract organization slug from subdomain or header
    let org_slug = extract_org_slug(&request)?;
    
    // Lookup organization from database
    let org = lookup_organization(&state.db, &org_slug).await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    
    //Set database context for row-level security
    set_database_context(&state.db, &org.org_id).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Add org context to request extensions
    request.extensions_mut().insert(org.clone());

    tracing::debug!(
        org_id = %org.org_id,
        org_slug = %org.org_slug,
        org_name = %org.org_name,
        "Organization context established"
    );
    
    Ok(next.run(request).await)
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

/// Set database context for row-level security
async fn set_database_context(
    pool: &PgPool,
    org_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_org_context($1)")
        .bind(org_id)
        .execute(pool)
        .await?;
    
    Ok(())
}

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
