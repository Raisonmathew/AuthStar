use axum::{
    routing::{get, post},
    Router,
    middleware,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tower_http::cors::{CorsLayer, Any, AllowOrigin};
use axum::http::HeaderValue;
use crate::state::AppState;
use crate::routes::eiaa as eiaa_routes;
use crate::routes::billing as billing_routes;
use crate::routes::admin as admin_routes;
use crate::routes::org_config;
use crate::routes::roles as roles_routes;
use crate::routes::hosted as hosted_routes;
use crate::routes::signup as signup_routes;
use crate::routes::auth as auth_routes;
use crate::routes::decisions as decisions_routes;
use crate::routes::mfa as mfa_routes;
use crate::routes::sso as sso_routes;
use crate::routes::passkeys as passkey_routes;
use crate::routes::domains as domains_routes;
use crate::routes::auth_flow;
use crate::routes::policy_builder as policy_builder_routes;
use crate::routes::metrics as metrics_routes;
use crate::routes::api_keys as api_keys_routes;
use crate::middleware::auth::require_auth_ext;
use crate::middleware::api_key_auth::api_key_auth_middleware;
use crate::middleware::security_headers;
use crate::middleware::org_context::org_context_middleware;
use crate::middleware::{EiaaAuthzLayer, EiaaAuthzConfig};
use crate::middleware::subscription::require_active_subscription;
use crate::middleware::rate_limit::{rate_limit_auth_flow, rate_limit_api, rate_limit_auth_flow_submit, rate_limit_password_auth};
use crate::middleware::request_id_middleware;
use crate::middleware::track_metrics;

/// Create EIAA authorization config with caching, verification, and audit
fn eiaa_config(state: &AppState) -> EiaaAuthzConfig {
    EiaaAuthzConfig {
        runtime_addr: state.config.eiaa.runtime_grpc_addr.clone(),
        cache: Some(state.capsule_cache.clone()),
        audit_writer: Some(state.audit_writer.clone()),
        key_cache: Some(state.runtime_key_cache.clone()),
        verifier: Some(state.attestation_verifier.clone()),
        flow_service: Some(state.eiaa_flow_service.clone()),
        risk_engine: Some(state.risk_engine.clone()),
        decision_cache: Some(state.decision_cache.clone()),
        fail_open: false, // Fail closed in production
        skip_verification: false, // Always verify in production
        risk_threshold: 80.0, // Block requests with risk score > 80
        allow_provisional: false,
        jwt_service: Some(state.jwt_service.clone()),
        db: Some(state.db.clone()),
        // HIGH-EIAA-3 FIX: Wire the persistent NonceStore into every EIAA-protected route.
        nonce_store: Some(state.nonce_store.clone()),
        // GAP-1 FIX: Wire the shared singleton runtime client so the circuit breaker
        // state is shared across all concurrent requests. Previously this was None,
        // causing a fresh EiaaRuntimeClient (and fresh circuit breaker) to be created
        // on every authorization request — the breaker could never trip.
        runtime_client: Some(state.runtime_client.clone()),
    }
}

fn eiaa_config_allow_provisional(state: &AppState) -> EiaaAuthzConfig {
    let mut config = eiaa_config(state);
    config.allow_provisional = true;
    config
}

pub fn create_router(state: AppState) -> Router {
    // Health check routes (no rate limiting)
    let health_routes = Router::new()
        .route("/health", get(health_check))
        .route("/health/ready", get(readiness_check).with_state(state.clone()));

    // D-2: Prometheus metrics scrape endpoint.
    // Intentionally unauthenticated — protected at the network layer
    // (Kubernetes NetworkPolicy / nginx allow directive for Prometheus scraper only).
    // The PrometheusHandle is injected as an Extension by main.rs.
    let metrics_route = Router::new()
        .route("/metrics", get(metrics_routes::metrics_handler));

    // Auth routes with strict rate limiting (10/min per IP) - PUBLIC, NO JWT REQUIRED
    // HIGH-7: rate_limit_auth_flow applies 10 req/min per IP to flow creation endpoint
    let auth_routes_with_limit = Router::new()
        .nest("/api/v1", auth_routes::public_router(state.clone()))
        .nest("/api/auth/sso", sso_routes::router().with_state(state.clone()))
        .nest("/api/signup", signup_routes::router().with_state(state.clone()))
        .nest("/api/hosted", hosted_routes::router().with_state(state.clone()))
        // Auth flow: init/get/complete — 10 req/min per IP (HIGH-7)
        .nest("/api/auth/flow", auth_flow::router()
            .layer(middleware::from_fn_with_state(state.clone(), rate_limit_auth_flow))
            .with_state(state.clone()))
        // A-2: submit — 5 req/min per (IP, flow_id) — tighter brute-force protection
        .nest("/api/auth/flow", auth_flow::submit_router()
            .layer(middleware::from_fn_with_state(state.clone(), rate_limit_auth_flow_submit))
            .with_state(state.clone()))
        // A-2: identify — 5 req/min per IP — prevents account enumeration / targeted lockout
        .nest("/api/auth/flow", auth_flow::identify_router()
            .layer(middleware::from_fn_with_state(state.clone(), rate_limit_password_auth))
            .with_state(state.clone()));

    // === PROTECTED ROUTES: Require auth + EIAA authorization ===
    // Each route applies EiaaAuthzLayer, then we apply require_auth_ext at the group level
    // require_auth_ext reads AppState from Extension (injected at final router level)
    let protected_routes = Router::new()
        // EIAA management routes: eiaa:manage action
        .nest("/api/eiaa/v1", eiaa_routes::manage_router()
            .layer(EiaaAuthzLayer::new("eiaa:manage", eiaa_config(&state)))
            .with_state(state.clone()))
        // Runtime key fetch: runtime:keys:read action
        .nest("/api/eiaa/v1", eiaa_routes::runtime_keys_router()
            .layer(EiaaAuthzLayer::new("runtime:keys:read", eiaa_config(&state)))
            .with_state(state.clone()))
        // Admin routes: admin:manage action
        .nest("/api/admin/v1", admin_routes::router()
            .layer(EiaaAuthzLayer::new("admin:manage", eiaa_config(&state)))
            .with_state(state.clone()))
        // Org config: protected write routes (org:config action)
        .merge(org_config::write_routes()
            .layer(EiaaAuthzLayer::new("org:config", eiaa_config(&state)))
            .with_state(state.clone()))
        // Billing read routes: billing:read action
        .nest("/api/billing/v1", billing_routes::read_routes()
            .layer(EiaaAuthzLayer::new("billing:read", eiaa_config(&state)))
            .with_state(state.clone()))
        // Billing write routes: billing:write action
        .merge(Router::new().nest("/api/billing/v1", billing_routes::write_routes()
            .layer(EiaaAuthzLayer::new("billing:write", eiaa_config(&state)))
            .with_state(state.clone())))
        // Roles read routes: org:read action
        .nest("/api/v1/organizations/:id", roles_routes::read_routes()
            .layer(EiaaAuthzLayer::new("org:read", eiaa_config(&state)))
            .with_state(state.clone()))
        // Roles write routes: roles:manage action
        .merge(Router::new().nest("/api/v1/organizations/:id", roles_routes::roles_write_routes()
            .layer(EiaaAuthzLayer::new("roles:manage", eiaa_config(&state)))
            .with_state(state.clone())))
        // Members write routes: members:manage action
        .merge(Router::new().nest("/api/v1/organizations/:id", roles_routes::members_write_routes()
            .layer(EiaaAuthzLayer::new("members:manage", eiaa_config(&state)))
            .with_state(state.clone())))
        // MFA routes: mfa:manage action
        .nest("/api/mfa", mfa_routes::router()
            .layer(EiaaAuthzLayer::new("mfa:manage", eiaa_config(&state)))
            .with_state(state.clone()))
        // Passkeys management: passkeys:manage action
        .nest("/api/passkeys", passkey_routes::management_routes()
            .layer(EiaaAuthzLayer::new("passkeys:manage", eiaa_config(&state)))
            .with_state(state.clone()))
        // Domains routes: domains:manage action
        .nest("/api/domains", domains_routes::router()
            .layer(EiaaAuthzLayer::new("domains:manage", eiaa_config(&state)))
            .with_state(state.clone()))
        // EIAA Re-Execution Verification API: audit:verify action
        .nest("/api/v1/audit/reexecution", crate::routes::reexecution::router()
            .layer(EiaaAuthzLayer::new("audit:verify", eiaa_config(&state)))
            .with_state(state.clone()))
        // User Factors API: user:manage_factors action
        .nest("/api/v1/user", crate::routes::user::factors::router()
            .layer(EiaaAuthzLayer::new("user:manage_factors", eiaa_config(&state)))
            .with_state(state.clone()))
        // Decisions routes: audit:read action (tenant-scoped)
        .nest("/api/decisions", decisions_routes::router()
            .layer(EiaaAuthzLayer::new("audit:read", eiaa_config(&state)))
            .with_state(state.clone()))
        // B-4: API Keys management — create, list, revoke developer API keys
        // Uses "apikeys:manage" EIAA action; requires active session (JWT or API key auth)
        .nest("/api/v1/api-keys", api_keys_routes::router()
            .layer(EiaaAuthzLayer::new("apikeys:manage", eiaa_config(&state)))
            .with_state(state.clone()))
        // Policy Builder — Okta/Auth0-style no-code policy configuration
        // Tenant admins configure policies via templates without writing AST/WASM.
        // Uses "policies:manage" EIAA action (same as raw policy management).
        .nest("/api/v1/policy-builder", policy_builder_routes::router()
            .layer(EiaaAuthzLayer::new("policies:manage", eiaa_config(&state)))
            .with_state(state.clone()));

    let session_logout_routes = Router::new()
        .nest("/api/v1", auth_routes::logout_router(state.clone()))
        .layer(EiaaAuthzLayer::new("session:logout", eiaa_config(&state)));

    let session_refresh_routes = Router::new()
        .nest("/api/v1", auth_routes::refresh_router(state.clone()))
        .layer(EiaaAuthzLayer::new("session:refresh", eiaa_config(&state)));

    let step_up_routes = Router::new()
        .nest("/api/v1", auth_routes::step_up_router(state.clone()))
        .layer(EiaaAuthzLayer::new("auth:step_up", eiaa_config_allow_provisional(&state)));

    let user_routes = Router::new()
        .route("/api/v1/user", get(auth_routes::get_current_user))
        .layer(EiaaAuthzLayer::new("user:read", eiaa_config(&state)))
        .with_state(state.clone());

    // User profile management: update display name, change password
    // Uses "user:manage_profile" EIAA action — any authenticated end-user can manage their own profile.
    let user_profile_routes = Router::new()
        .nest("/api/v1/user", crate::routes::user::profile::router()
            .layer(EiaaAuthzLayer::new("user:manage_factors", eiaa_config(&state)))
            .with_state(state.clone()));

    let org_routes = Router::new()
        .route("/api/v1/organizations", get(auth_routes::get_user_organizations))
        .layer(EiaaAuthzLayer::new("org:read", eiaa_config(&state)))
        .with_state(state.clone());

    // B-6: Create organization — authenticated users can create new orgs.
    // Uses org:create EIAA action; creator is automatically made admin.
    let org_create_routes = Router::new()
        .route("/api/v1/organizations", post(auth_routes::create_organization))
        .layer(EiaaAuthzLayer::new("org:create", eiaa_config(&state)))
        .with_state(state.clone());

    // === MIXED ROUTES: Some public, some protected ===
    let mixed_routes = Router::new()
        // Org config: public read routes (for hosted pages) - NO auth
        .merge(org_config::public_routes().with_state(state.clone()))
        // Billing webhook: no auth (Stripe signature verified internally)
        .merge(Router::new().nest("/api/billing/v1", billing_routes::webhook_route().with_state(state.clone())))
        // Passkeys authentication (public - used for login)
        .nest("/api/passkeys/authenticate", passkey_routes::auth_routes().with_state(state.clone()));

    // === FINAL ROUTER ===
    Router::new()
        .merge(health_routes)
        .merge(metrics_route)
        .merge(auth_routes_with_limit)
        // HIGH-5: Subscription enforcement on all protected routes.
        // Applied AFTER auth/org context so we have the org_id available.
        // Billing webhook and public auth routes are excluded (merged separately below).
        .merge(protected_routes
            .layer(middleware::from_fn_with_state(state.clone(), require_active_subscription)))
        .merge(session_logout_routes)
        .merge(session_refresh_routes)
        .merge(step_up_routes)
        .merge(user_routes)
        .merge(user_profile_routes)
        .merge(org_routes)
        .merge(org_create_routes)
        .merge(mixed_routes)
        // CSRF token endpoint (browser clients call this to get a CSRF token)
        .route("/api/csrf-token", get(csrf_token_handler))
        // CSRF protection on mutating routes (POST/PUT/PATCH/DELETE)
        .layer(middleware::from_fn(crate::middleware::csrf::csrf_protection))
        // B-4: API key authentication — resolves "Bearer ask_..." tokens to Claims.
        // Must run BEFORE require_auth_ext (which checks for Claims extension).
        // Is a no-op for JWT requests (passes through unchanged).
        .layer(middleware::from_fn_with_state(state.clone(), api_key_auth_middleware))
        // Inject AppState as Extension for require_auth_ext and org_context_middleware
        .layer(Extension(state.clone()))
        // Org context middleware for all API routes
        .layer(middleware::from_fn_with_state(state.clone(), org_context_middleware))
        // MEDIUM-15: General API rate limiting (1000 req/min per org)
        // Applied globally — individual route groups have tighter limits above
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit_api))
        // Security headers on all responses
        .layer(middleware::from_fn(security_headers))
        // MEDIUM-9 FIX: Require ALLOWED_ORIGINS in production.
        // Without this, a misconfigured production deployment would silently fall back
        // to `Access-Control-Allow-Origin: *`, which combined with `allow_credentials(true)`
        // is rejected by browsers (CORS spec §3.2) AND exposes the API to any origin.
        //
        // We detect production by checking APP_ENV=production (set in K8s configmap).
        // In dev/staging, we fall back to Any for convenience.
        .layer({
            let is_production = std::env::var("APP_ENV")
                .map(|v| v.to_lowercase() == "production")
                .unwrap_or(false);

            if is_production && state.config.allowed_origins.is_empty() {
                // Hard fail at startup — do not serve requests with wildcard CORS in production.
                // This will panic during router construction (called from main), which is
                // intentional: a misconfigured production server should not start.
                panic!(
                    "FATAL: APP_ENV=production but ALLOWED_ORIGINS is not set. \
                     Set ALLOWED_ORIGINS to a comma-separated list of allowed frontend origins \
                     (e.g. https://app.example.com). \
                     Refusing to start with wildcard CORS in production."
                );
            }

            let cors = CorsLayer::new()
                .allow_methods(vec![
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::PATCH,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers(vec![
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::ACCEPT,
                    axum::http::header::CONTENT_TYPE,
                    // Required for our CSRF validation
                    axum::http::header::HeaderName::from_static("x-csrf-token"),
                ])
                .allow_credentials(true); // Required for httpOnly cookie auth

            if state.config.allowed_origins.is_empty() {
                // Dev/staging mode: allow all origins.
                // Note: allow_credentials + Any origin is rejected by browsers per CORS spec,
                // but is acceptable for local development where credentials are not used.
                tracing::warn!(
                    "CORS: ALLOWED_ORIGINS not set — allowing all origins (dev mode only). \
                     Set APP_ENV=production to enforce strict origin validation."
                );
                cors.allow_origin(Any)
            } else {
                let origins: Vec<HeaderValue> = state.config.allowed_origins.iter()
                    .filter_map(|o| {
                        match o.parse::<HeaderValue>() {
                            Ok(v) => Some(v),
                            Err(e) => {
                                tracing::warn!("CORS: Skipping invalid origin {:?}: {}", o, e);
                                None
                            }
                        }
                    })
                    .collect();
                if origins.is_empty() {
                    panic!(
                        "FATAL: ALLOWED_ORIGINS is set but contains no valid HTTP origins. \
                         Check the format (e.g. https://app.example.com)."
                    );
                }
                tracing::info!("CORS: Allowing {} configured origins", origins.len());
                cors.allow_origin(AllowOrigin::list(origins))
            }
        })
        // D-2: HTTP metrics middleware — records request counts, latencies, and in-flight
        // requests for all routes. Applied inside request_id so the request ID is available
        // in the tracing span when metrics are recorded.
        .layer(middleware::from_fn(track_metrics))
        // D-1: Request ID middleware — outermost layer so every request (including health
        // checks, CORS preflight, and error responses) gets a unique X-Request-ID header.
        // The ID is injected into the tracing span for log correlation across all layers.
        .layer(middleware::from_fn(request_id_middleware))
}


async fn health_check() -> &'static str {
    "OK"
}

/// Readiness check: verify DB, Redis, and audit writer are healthy.
///
/// ## GAP-2 FIX: Audit Writer Health
///
/// The readiness check now includes the audit writer backpressure state.
/// A Kubernetes liveness/readiness probe hitting this endpoint will see
/// `503 Service Unavailable` if:
/// - The DB is unreachable (existing check)
/// - Redis is unreachable (existing check)
/// - The audit writer channel is ≥ 95% full (new: imminent data loss)
/// - Any audit records have been dropped since startup (new: data loss already occurring)
///
/// The 95% threshold is intentionally conservative — at 95% full the channel
/// will saturate within seconds under normal load. Kubernetes will stop routing
/// new traffic to this pod, giving the flush loop time to drain the backlog.
async fn readiness_check(
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Check Postgres
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();

    // Check Redis
    let redis_ok = match redis::Client::open(state.config.redis.url.as_str()) {
        Ok(client) => {
            match client.get_async_connection().await {
                Ok(mut conn) => {
                    redis::cmd("PING")
                        .query_async::<_, String>(&mut conn)
                        .await
                        .is_ok()
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    };

    // GAP-2 FIX: Check audit writer backpressure.
    // Fail readiness if the channel is critically full (≥ 95%) or records are being dropped.
    // This prevents Kubernetes from routing new traffic to a pod that is already losing
    // audit records — a compliance violation for EIAA-regulated workloads.
    let audit_metrics = state.audit_writer.metrics();
    let audit_ok = audit_metrics.dropped_total == 0 && audit_metrics.channel_fill_pct < 95.0;

    if !audit_ok {
        tracing::warn!(
            dropped_total = audit_metrics.dropped_total,
            channel_fill_pct = audit_metrics.channel_fill_pct,
            channel_pending = audit_metrics.channel_pending,
            channel_capacity = audit_metrics.channel_capacity,
            "Readiness check: audit writer unhealthy — {} records dropped, channel {:.1}% full",
            audit_metrics.dropped_total,
            audit_metrics.channel_fill_pct,
        );
    }

    if db_ok && redis_ok && audit_ok {
        (StatusCode::OK, "Ready").into_response()
    } else {
        let msg = format!(
            "Not ready: db={}, redis={}, audit_writer_ok={} (dropped={}, fill={:.1}%)",
            db_ok, redis_ok, audit_ok,
            audit_metrics.dropped_total,
            audit_metrics.channel_fill_pct,
        );
        tracing::warn!("{}", msg);
        (StatusCode::SERVICE_UNAVAILABLE, msg).into_response()
    }
}

/// GET /api/csrf-token — Returns a CSRF token and sets the __csrf cookie.
/// Browser clients call this before making state-changing requests.
async fn csrf_token_handler(
    Extension(state): Extension<AppState>,
) -> impl IntoResponse {
    let token = crate::middleware::csrf::generate_csrf_token();
    let is_secure = !state.config.frontend_url.starts_with("http://localhost");
    let cookie = crate::middleware::csrf::csrf_cookie_header(&token, is_secure);

    (
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(serde_json::json!({ "csrf_token": token })),
    )
}
