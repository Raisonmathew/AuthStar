use axum::{
    routing::get,
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
use crate::routes::policies as policies_routes;
use crate::middleware::auth::require_auth_ext;
use crate::middleware::security_headers;
use crate::middleware::org_context::org_context_middleware;
use crate::middleware::{EiaaAuthzLayer, EiaaAuthzConfig};

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

    // Auth routes with strict rate limiting (10/min) - PUBLIC, NO JWT REQUIRED
    let auth_routes_with_limit = Router::new()
        .nest("/api/v1", auth_routes::public_router(state.clone())) 
        .nest("/api/auth/sso", sso_routes::router().with_state(state.clone()))
        .nest("/api/signup", signup_routes::router().with_state(state.clone()))
        .nest("/api/hosted", hosted_routes::router().with_state(state.clone()))
        .nest("/api/auth/flow", auth_flow::router().with_state(state.clone()));

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
        // EIAA Policy Management API: policies:manage action
        .nest("/api/v1/policies", policies_routes::router()
            .layer(EiaaAuthzLayer::new("policies:manage", eiaa_config(&state)))
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

    let org_routes = Router::new()
        .route("/api/v1/organizations", get(auth_routes::get_user_organizations))
        .layer(EiaaAuthzLayer::new("org:read", eiaa_config(&state)))
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
        .merge(auth_routes_with_limit)
        .merge(protected_routes)
        .merge(session_logout_routes)
        .merge(session_refresh_routes)
        .merge(step_up_routes)
        .merge(user_routes)
        .merge(org_routes)
        .merge(mixed_routes)
        // CSRF token endpoint (browser clients call this to get a CSRF token)
        .route("/api/csrf-token", get(csrf_token_handler))
        // CSRF protection on mutating routes (POST/PUT/PATCH/DELETE)
        .layer(middleware::from_fn(crate::middleware::csrf::csrf_protection))
        // Inject AppState as Extension for require_auth_ext and org_context_middleware
        .layer(Extension(state.clone()))
        // Org context middleware for all API routes
        .layer(middleware::from_fn_with_state(state.clone(), org_context_middleware))
        // Security headers on all responses
        .layer(middleware::from_fn(security_headers))
        // CORS — use strict origin list if configured, fall back to Any for dev
        .layer({
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
                // Dev mode: allow all origins (note: allow_credentials + Any origin
                // may require specific Origin echo — browser enforces this)
                cors.allow_origin(Any)
            } else {
                let origins: Vec<HeaderValue> = state.config.allowed_origins.iter()
                    .filter_map(|o| o.parse::<HeaderValue>().ok())
                    .collect();
                cors.allow_origin(AllowOrigin::list(origins))
            }
        })
}


async fn health_check() -> &'static str {
    "OK"
}

/// Readiness check: verify DB and Redis are reachable
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

    if db_ok && redis_ok {
        (StatusCode::OK, "Ready").into_response()
    } else {
        let msg = format!("Not ready: db={}, redis={}", db_ok, redis_ok);
        tracing::warn!("{}", msg);
        (StatusCode::SERVICE_UNAVAILABLE, msg).into_response()
    }
}

/// GET /api/csrf-token — Returns a CSRF token and sets the __csrf cookie.
/// Browser clients call this before making state-changing requests.
async fn csrf_token_handler() -> impl IntoResponse {
    let token = crate::middleware::csrf::generate_csrf_token();
    let cookie = crate::middleware::csrf::csrf_cookie_header(&token);

    (
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(serde_json::json!({ "csrf_token": token })),
    )
}
