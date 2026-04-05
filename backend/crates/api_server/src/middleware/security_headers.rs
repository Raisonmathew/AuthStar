//! Security Headers Middleware
//!
//! Adds standard security headers to all responses.

use axum::{
    body::Body,
    http::{header, HeaderName, HeaderValue, Request, Response},
    middleware::Next,
};

/// Add security headers to all responses
pub async fn security_headers(request: Request<Body>, next: Next) -> Response<Body> {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Prevent MIME-sniffing
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    // Prevent clickjacking
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    // XSS protection (legacy but still useful)
    headers.insert(
        HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("1; mode=block"),
    );

    // Strict Transport Security (HTTPS only)
    // Only enable in production when HTTPS is configured
    #[cfg(not(debug_assertions))]
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    // Content Security Policy
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'")
    );

    // Referrer Policy
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Permissions Policy (formerly Feature-Policy)
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use tower::ServiceExt;

    async fn handler() -> &'static str {
        "OK"
    }

    #[tokio::test]
    async fn test_security_headers() {
        let app = Router::new()
            .route("/", get(handler))
            .layer(axum::middleware::from_fn(security_headers));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert!(response
            .headers()
            .contains_key(header::X_CONTENT_TYPE_OPTIONS));
        assert!(response.headers().contains_key(header::X_FRAME_OPTIONS));
        assert!(response
            .headers()
            .contains_key(header::CONTENT_SECURITY_POLICY));
    }
}
