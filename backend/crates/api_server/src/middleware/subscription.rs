//! Subscription Enforcement Middleware (HIGH-5)
//!
//! Checks that the organization extracted from the JWT has an active subscription
//! before allowing access to premium routes. Returns HTTP 402 Payment Required
//! if the subscription is expired, cancelled, or missing.
//!
//! Usage in router.rs:
//! ```rust
//! .layer(middleware::from_fn_with_state(
//!     state.clone(),
//!     require_active_subscription,
//! ))
//! ```
//!
//! The middleware reads the `OrgContext` extension set by `org_context_middleware`
//! and queries the `subscriptions` table. Results are cached in Redis for 60 seconds
//! to avoid a DB hit on every request.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use redis::AsyncCommands;
use crate::state::AppState;
use crate::middleware::org_context::OrgContext;

/// Cache TTL for subscription status (seconds).
/// Short enough to pick up cancellations within 1 minute.
const SUBSCRIPTION_CACHE_TTL: u64 = 60;

/// Redis key prefix for subscription status cache.
const CACHE_KEY_PREFIX: &str = "sub_status:";

/// Axum middleware: require an active subscription for the current org.
///
/// Reads `OrgContext` from request extensions (set by `org_context_middleware`).
/// If the org has no active subscription, returns 402 with a JSON error body.
///
/// System org (`__system__`) is always allowed through (provider admin routes).
pub async fn require_active_subscription(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Extract org context set by org_context_middleware
    let org_id = match request.extensions().get::<OrgContext>() {
        Some(ctx) => ctx.org_id.clone(),
        None => {
            // No org context — let the auth middleware handle this
            return next.run(request).await;
        }
    };

    // System org always has access (provider admin)
    if org_id == "__system__" || org_id == "system" {
        return next.run(request).await;
    }

    // Check subscription status (with Redis cache)
    match check_subscription_active(&state, &org_id).await {
        Ok(true) => next.run(request).await,
        Ok(false) => {
            tracing::warn!(
                org_id = %org_id,
                "Request blocked: no active subscription"
            );
            (
                StatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({
                    "error": "subscription_required",
                    "message": "An active subscription is required to access this resource. Please upgrade your plan.",
                    "upgrade_url": "/billing"
                })),
            ).into_response()
        }
        Err(e) => {
            // On DB/Redis error, fail open with a warning (availability > strict enforcement)
            // In a stricter posture, change this to fail closed (return 503).
            tracing::error!(
                org_id = %org_id,
                error = %e,
                "Failed to check subscription status — failing open"
            );
            next.run(request).await
        }
    }
}

/// Check if the org has an active subscription.
/// Results are cached in Redis for `SUBSCRIPTION_CACHE_TTL` seconds.
async fn check_subscription_active(state: &AppState, org_id: &str) -> anyhow::Result<bool> {
    let cache_key = format!("{}{}", CACHE_KEY_PREFIX, org_id);

    // 1. Try Redis cache first
    let mut redis = state.redis.clone();
    let cached: Option<String> = redis.get(&cache_key).await.unwrap_or(None);

    if let Some(val) = cached {
        return Ok(val == "1");
    }

    // 2. Query database
    let active: Option<bool> = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM subscriptions
            WHERE organization_id = $1
              AND status = 'active'
              AND (current_period_end IS NULL OR current_period_end > NOW())
        )
        "#
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await?;

    let is_active = active.unwrap_or(false);

    // 3. Cache result
    let cache_val = if is_active { "1" } else { "0" };
    let _: () = redis
        .set_ex(&cache_key, cache_val, SUBSCRIPTION_CACHE_TTL)
        .await
        .unwrap_or(()); // Cache failure is non-fatal

    Ok(is_active)
}

/// Invalidate the subscription cache for an org.
/// Call this from the billing webhook handler when subscription status changes.
pub async fn invalidate_subscription_cache(
    redis: &mut redis::aio::ConnectionManager,
    org_id: &str,
) {
    let cache_key = format!("{}{}", CACHE_KEY_PREFIX, org_id);
    let _: () = redis.del(&cache_key).await.unwrap_or(());
    tracing::debug!(org_id = %org_id, "Subscription cache invalidated");
}

// Made with Bob
