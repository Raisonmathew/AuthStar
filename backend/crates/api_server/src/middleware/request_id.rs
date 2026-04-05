//! Request ID Middleware (D-1)
//!
//! Generates a unique `X-Request-ID` for every incoming request and propagates
//! it through the tracing span so all log lines for a request share the same ID.
//!
//! - If the client sends an `X-Request-ID` header, it is validated and reused
//!   (allows end-to-end correlation from frontend → backend → logs).
//! - If no header is present, a new UUID v4 is generated.
//! - The request ID is always echoed back in the response `X-Request-ID` header
//!   so the frontend can correlate errors with backend logs.
//!
//! ## Usage
//!
//! Apply globally in `main.rs` before all other middleware:
//! ```rust,ignore
//! .layer(axum::middleware::from_fn(request_id::request_id_middleware))
//! ```

use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, Request, Response},
    middleware::Next,
};
use uuid::Uuid;

static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Maximum length for a client-supplied request ID (prevents log injection).
const MAX_REQUEST_ID_LEN: usize = 64;

/// Request ID middleware.
///
/// Reads or generates a request ID, injects it into the tracing span,
/// and echoes it in the response header.
pub async fn request_id_middleware(mut request: Request<Body>, next: Next) -> Response<Body> {
    // 1. Extract or generate request ID
    let request_id = request
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| {
            // Validate: non-empty, max length, ASCII printable only (prevent log injection)
            !s.is_empty()
                && s.len() <= MAX_REQUEST_ID_LEN
                && s.chars().all(|c| c.is_ascii_graphic())
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // 2. Inject into tracing span so all log lines for this request include it
    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        method = %request.method(),
        path = %request.uri().path(),
    );
    let _enter = span.enter();

    // 3. Store in request extensions so handlers can read it if needed
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    // 4. Run the handler
    let mut response = next.run(request).await;

    // 5. Echo the request ID in the response header for client-side correlation
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(X_REQUEST_ID.clone(), value);
    }

    response
}

/// Newtype wrapper so handlers can extract the request ID via `Extension<RequestId>`.
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Made with Bob
