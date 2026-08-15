//! Token extraction utilities
//!
//! Shared token extraction logic to avoid duplication across middleware.
//! Issue #2 fix from code review.

use axum::extract::Request;
use axum::http::header;

/// Extract bearer token from request — header-first, cookie fallback.
///
/// Priority order:
/// 1. `Authorization: Bearer <token>` header (server SDKs, API keys, explicit auth)
/// 2. `__session` httpOnly cookie (browser clients — implicit session)
///
/// The Authorization header takes explicit priority: when a caller supplies a
/// Bearer token in the header they are explicitly choosing which credential to
/// use. Giving the cookie priority would silently ignore the supplied token and
/// use the browser session instead — a violation of RFC 6750 §2.1 which states
/// the Authorization header is the preferred method.
///
/// This is the canonical token extraction implementation used by all
/// authentication middleware (`auth.rs`, `eiaa_authz.rs`, etc.).
pub fn extract_bearer_token(req: &Request) -> Option<String> {
    // 1. Authorization header (server SDK, explicit Bearer auth) — takes priority.
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(header_str) = auth_header.to_str() {
            if let Some(token) = header_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    // 2. Fall back to httpOnly cookie (browser clients)
    if let Some(cookie_header) = req.headers().get(header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix("__session=") {
                    let token = token.trim();
                    if !token.is_empty() {
                        return Some(token.to_string());
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{HeaderValue, Request};

    #[test]
    fn test_extract_from_cookie() {
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();

        req.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("__session=test_token_123"),
        );

        let token = extract_bearer_token(&req);
        assert_eq!(token, Some("test_token_123".to_string()));
    }

    #[test]
    fn test_extract_from_authorization_header() {
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();

        req.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test_token_456"),
        );

        let token = extract_bearer_token(&req);
        assert_eq!(token, Some("test_token_456".to_string()));
    }

    #[test]
    fn test_bearer_header_takes_precedence_over_cookie() {
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();

        req.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("__session=cookie_token"),
        );
        req.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header_token"),
        );

        // Authorization header must win over the cookie (RFC 6750 §2.1)
        let token = extract_bearer_token(&req);
        assert_eq!(token, Some("header_token".to_string()));
    }

    #[test]
    fn test_no_token_returns_none() {
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let token = extract_bearer_token(&req);
        assert_eq!(token, None);
    }

    #[test]
    fn test_empty_cookie_value_ignored() {
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();

        req.headers_mut()
            .insert(header::COOKIE, HeaderValue::from_static("__session="));

        let token = extract_bearer_token(&req);
        assert_eq!(token, None);
    }

    #[test]
    fn test_multiple_cookies() {
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();

        req.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("other=value; __session=my_token; another=value"),
        );

        let token = extract_bearer_token(&req);
        assert_eq!(token, Some("my_token".to_string()));
    }
}

// Made with Bob
