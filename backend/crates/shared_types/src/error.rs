use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Payment required: {0}")]
    PaymentRequired(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("External service error: {0}")]
    External(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Validation error: {0}")]
    Validation(String),

    /// C-2: Database connection pool exhausted — return 503 so load balancers
    /// can retry on another instance rather than surfacing a 500 to the client.
    #[error("Service temporarily unavailable: {0}")]
    ServiceUnavailable(String),

    /// C-1: Authentication flow has expired (expires_at <= NOW()).
    /// Returns 410 Gone so the frontend can show "session expired, start over"
    /// and redirect to /init rather than retrying the same request.
    #[error("Flow expired: {0}")]
    FlowExpired(String),
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Database(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::BadRequest(_) | Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::PaymentRequired(_) => StatusCode::PAYMENT_REQUIRED,
            Self::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::External(_) => StatusCode::BAD_GATEWAY,
            // C-2: Pool exhaustion → 503 so load balancers can retry elsewhere
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            // C-1: Flow expired → 410 Gone (existed but is no longer available)
            Self::FlowExpired(_) => StatusCode::GONE,
        }
    }

    pub fn error_code(&self) -> &str {
        match self {
            Self::Database(_) => "DATABASE_ERROR",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::Conflict(_) => "CONFLICT",
            Self::PaymentRequired(_) => "PAYMENT_REQUIRED",
            Self::TooManyRequests(_) => "RATE_LIMIT_EXCEEDED",
            Self::External(_) => "EXTERNAL_SERVICE_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::Validation(_) => "VALIDATION_ERROR",
            Self::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            Self::FlowExpired(_) => "FLOW_EXPIRED",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();

        // Sanitize internal error details before sending to client.
        // Log the real error for operators, return a generic message to the caller.
        let client_message = match &self {
            Self::Database(_) => {
                tracing::error!(internal_error = %self, "Database error");
                "An internal error occurred".to_string()
            }
            Self::Internal(_) => {
                tracing::error!(internal_error = %self, "Internal error");
                "An internal error occurred".to_string()
            }
            Self::External(_) => {
                tracing::error!(internal_error = %self, "External service error");
                "An upstream service error occurred".to_string()
            }
            other => other.to_string(),
        };

        let body = Json(ErrorResponse {
            error: self.error_code().to_string(),
            message: client_message,
            details: None,
        });

        (status, body).into_response()
    }
}

// Convert sqlx errors
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => Self::NotFound("Resource not found".to_string()),
            sqlx::Error::Database(db_err) => {
                if let Some(constraint) = db_err.constraint() {
                    Self::Conflict(format!("Constraint violation: {constraint}"))
                } else {
                    Self::Database(db_err.message().to_string())
                }
            }
            // C-2: Pool exhaustion → 503 Service Unavailable.
            // This allows load balancers (nginx, k8s ingress) to retry the request
            // on another healthy instance rather than surfacing a 500 to the client.
            // The acquire_timeout in PgPoolOptions controls how long we wait before
            // this error is returned (default: 5 seconds via DB_ACQUIRE_TIMEOUT_SECS).
            sqlx::Error::PoolTimedOut => Self::ServiceUnavailable(
                "Database connection pool exhausted — please retry".to_string(),
            ),
            sqlx::Error::PoolClosed => Self::ServiceUnavailable(
                "Database connection pool is closed — server is shutting down".to_string(),
            ),
            _ => Self::Database(err.to_string()),
        }
    }
}

// Convert serde_json errors
impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        Self::BadRequest(format!("JSON error: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_error_sanitized() {
        let err = AppError::Database("relation \"users\" does not exist at line 3".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_internal_error_sanitized() {
        let err = AppError::Internal("thread pool panicked at /src/db.rs:42".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_external_error_sanitized() {
        let err = AppError::External("Stripe API key invalid: sk_live_xxx".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_client_errors_preserve_status() {
        assert_eq!(
            AppError::BadRequest("bad".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::NotFound("nf".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::Unauthorized("u".into()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::Conflict("c".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AppError::TooManyRequests("t".into()).status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            AppError::ServiceUnavailable("s".into()).status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            AppError::FlowExpired("f".into()).status_code(),
            StatusCode::GONE
        );
    }

    #[test]
    fn test_error_codes_correct() {
        assert_eq!(
            AppError::Database("x".into()).error_code(),
            "DATABASE_ERROR"
        );
        assert_eq!(
            AppError::Internal("x".into()).error_code(),
            "INTERNAL_ERROR"
        );
        assert_eq!(
            AppError::External("x".into()).error_code(),
            "EXTERNAL_SERVICE_ERROR"
        );
        assert_eq!(AppError::NotFound("x".into()).error_code(), "NOT_FOUND");
        assert_eq!(
            AppError::Unauthorized("x".into()).error_code(),
            "UNAUTHORIZED"
        );
        assert_eq!(
            AppError::TooManyRequests("x".into()).error_code(),
            "RATE_LIMIT_EXCEEDED"
        );
    }

    #[test]
    fn test_sqlx_row_not_found_maps_to_404() {
        let err: AppError = sqlx::Error::RowNotFound.into();
        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_sqlx_pool_timeout_maps_to_503() {
        let err: AppError = sqlx::Error::PoolTimedOut.into();
        assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_sqlx_pool_closed_maps_to_503() {
        let err: AppError = sqlx::Error::PoolClosed.into();
        assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
