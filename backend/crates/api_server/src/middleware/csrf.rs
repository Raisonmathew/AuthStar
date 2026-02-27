//! CSRF Protection Middleware
//!
//! Protects state-changing routes from Cross-Site Request Forgery attacks.
//!
//! Strategy:
//! - Double-submit cookie: `__csrf` cookie + `X-CSRF-Token` header must match
//! - Origin/Referer verification against `ALLOWED_ORIGINS`
//! - Bypass for API key / Bearer token auth (server SDK mode)
//!
//! Apply after auth middleware on state-changing routes.

use axum::{
    extract::Request,
    http::{header, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use tracing;

/// CSRF verification middleware.
///
/// Skips verification for:
/// - Safe methods (GET, HEAD, OPTIONS)
/// - Requests with `Authorization: Bearer` header (server SDK, not browser)
///
/// For browser requests (cookie-based auth), requires:
/// 1. `X-CSRF-Token` header matches `__csrf` cookie value
/// 2. `Origin` or `Referer` header is in the allowed origins list
pub async fn csrf_protection(
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Safe methods are exempt
    if matches!(req.method(), &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        return Ok(next.run(req).await);
    }

    // Server SDK mode: Bearer token auth bypasses CSRF
    // (Not vulnerable to CSRF since the token must be explicitly set)
    if let Some(auth) = req.headers().get(header::AUTHORIZATION) {
        if auth.to_str().unwrap_or("").starts_with("Bearer ") {
            return Ok(next.run(req).await);
        }
    }

    // Browser mode: Verify CSRF token
    let csrf_cookie = extract_cookie_value(req.headers(), "__csrf");
    let csrf_header = req.headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match (csrf_cookie, csrf_header) {
        (Some(cookie_val), Some(header_val)) => {
            if !constant_time_eq(cookie_val.as_bytes(), header_val.as_bytes()) {
                tracing::warn!("CSRF token mismatch");
                return Err(StatusCode::FORBIDDEN);
            }
        }
        _ => {
            tracing::warn!("Missing CSRF token (cookie or header)");
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Verify Origin/Referer
    if !verify_origin(&req) {
        tracing::warn!("Origin/Referer verification failed");
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(req).await)
}

/// Extract a specific cookie value from the Cookie header.
fn extract_cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?;
    let cookies = cookie_header.to_str().ok()?;
    let prefix = format!("{}=", name);

    for cookie in cookies.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&prefix) {
            return Some(value.to_string());
        }
    }
    None
}

/// Verify that the Origin or Referer header matches allowed origins.
fn verify_origin(req: &Request) -> bool {
    // Get allowed origins from env (same config as CORS)
    let allowed_origins = std::env::var("ALLOWED_ORIGINS").unwrap_or_default();

    // If no origins configured (dev mode), allow all
    if allowed_origins.is_empty() {
        return true;
    }

    let allowed: Vec<&str> = allowed_origins.split(',').map(|s| s.trim()).collect();

    // Check Origin header first
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        if let Ok(origin_str) = origin.to_str() {
            return allowed.iter().any(|a| *a == origin_str);
        }
    }

    // Fall back to Referer header
    if let Some(referer) = req.headers().get(header::REFERER) {
        if let Ok(referer_str) = referer.to_str() {
            // Extract origin from referer URL (scheme + host)
            if let Some(origin) = extract_origin_from_url(referer_str) {
                return allowed.iter().any(|a| *a == origin);
            }
        }
    }

    // No Origin or Referer — reject (browser always sends one for cross-origin POST)
    false
}

/// Extract origin (scheme://host[:port]) from a full URL.
fn extract_origin_from_url(url: &str) -> Option<String> {
    // Find the end of "scheme://host:port" by looking for the third "/"
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        if let Some(path_start) = rest.find('/') {
            return Some(url[..scheme_end + 3 + path_start].to_string());
        }
        // No path — URL is just origin
        return Some(url.to_string());
    }
    None
}

/// Constant-time comparison to prevent timing attacks on CSRF tokens.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Generate a new CSRF token for a session.
pub fn generate_csrf_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

/// Build the `__csrf` Set-Cookie header value.
pub fn csrf_cookie_header(token: &str) -> String {
    format!(
        "__csrf={}; SameSite=Strict; Path=/; Max-Age=86400",
        token
    )
}

/// Build the `__session` httpOnly Set-Cookie header value.
pub fn session_cookie_header(token: &str, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "__session={}; HttpOnly{} ; SameSite=Lax; Path=/; Max-Age=86400",
        token, secure_flag
    )
}

/// Build a cookie header that clears the session (for logout).
pub fn clear_session_cookie() -> String {
    "__session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_origin_from_url() {
        assert_eq!(
            extract_origin_from_url("https://app.example.com/path"),
            Some("https://app.example.com".to_string())
        );
        assert_eq!(
            extract_origin_from_url("http://localhost:3000/"),
            Some("http://localhost:3000".to_string())
        );
        assert_eq!(
            extract_origin_from_url("https://example.com"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"abc123", b"abc123"));
        assert!(!constant_time_eq(b"abc123", b"abc124"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn test_extract_cookie_value() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "__session=tok123; __csrf=csrf456; other=val".parse().unwrap(),
        );

        assert_eq!(
            extract_cookie_value(&headers, "__csrf"),
            Some("csrf456".to_string())
        );
        assert_eq!(
            extract_cookie_value(&headers, "__session"),
            Some("tok123".to_string())
        );
        assert_eq!(extract_cookie_value(&headers, "missing"), None);
    }

    #[test]
    fn test_csrf_cookie_header() {
        let header = csrf_cookie_header("abc123");
        assert!(header.contains("__csrf=abc123"));
        assert!(header.contains("SameSite=Strict"));
    }

    #[test]
    fn test_session_cookie_header() {
        let header = session_cookie_header("tok123", true);
        assert!(header.contains("__session=tok123"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
    }
}
