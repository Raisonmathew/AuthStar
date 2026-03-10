#![allow(dead_code)]
use axum::{
    extract::Extension,
    routing::post,
    Json, Router,
    http::HeaderMap,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};
use validator::Validate;
use crate::state::AppState;
// GAP-1 FIX: EiaaRuntimeClient no longer used directly in signin — we use
// state.runtime_client (SharedRuntimeClient) instead.
use capsule_compiler::ast::{Program, Step, IdentitySource};
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};

use shared_types::{AppError, Result, AssuranceLevel, SessionRestriction};
use auth_core::jwt::Claims;
use identity_engine::models::UserResponse;
use risk_engine::{WebDeviceInput, RequestContext, NetworkInput, SubjectContext};
use std::net::IpAddr;
use std::str::FromStr;


#[derive(Deserialize, Validate)]
pub struct HelperSignupRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
    #[serde(rename = "deviceSignals")]
    pub device_signals: Option<WebDeviceInput>,
}

#[derive(Serialize)]
pub struct HelperSignupResponse {
    #[serde(rename = "ticketId")]
    pub ticket_id: String,
    pub status: String,
    #[serde(rename = "requiresVerification")]
    pub requires_verification: bool,
}

#[derive(Deserialize, Validate)]
pub struct HelperSigninRequest {
    pub identifier: String,
    pub password: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: Option<String>,
    #[serde(rename = "deviceSignals")]
    pub device_signals: Option<WebDeviceInput>,
}

#[derive(Serialize)]
pub struct HelperSigninResponse {
    pub user: UserResponse,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub jwt: String,
    #[serde(rename = "decisionRef")]
    pub decision_ref: String, // EIAA decision reference for audit
}

#[derive(Serialize)]
pub struct HelperRefreshResponse {
    pub jwt: String,
    pub user: identity_engine::models::UserResponse,
}

pub mod step_up;

pub fn router(state: AppState) -> Router {
    public_router(state)
}

pub fn public_router(state: AppState) -> Router {
    Router::new()
        .route("/sign-up", post(signup))
        .route("/sign-in", post(signin))
        // Use Extension to inject state for handlers
        .layer(Extension(state))
}

pub fn logout_router(state: AppState) -> Router {
    Router::new()
        .route("/logout", post(logout))
        .layer(Extension(state))
}

pub fn refresh_router(state: AppState) -> Router {
    Router::new()
        .route("/token/refresh", post(refresh_token))
        .layer(Extension(state))
}

pub fn step_up_router(state: AppState) -> Router {
    step_up::router(state)
}

/// Simple organization response for dashboard
#[derive(Serialize)]
pub struct OrganizationListItem {
    pub id: String,
    pub name: String,
    pub slug: String,
}

/// Get Organizations for Current User
///
/// Returns the list of organizations the authenticated user belongs to.
/// NEW-1 FIX: Uses Extension(claims) injected by upstream EiaaAuthzLayer
/// instead of manually extracting and re-verifying the JWT.
pub(crate) async fn get_user_organizations(
    Extension(state): Extension<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<OrganizationListItem>>> {
    // Query organizations the authenticated user is a member of
    let orgs: Vec<OrganizationListItem> = sqlx::query_as::<_, (String, String, String)>(
        r#"SELECT o.id, o.name, o.slug FROM organizations o
           JOIN memberships m ON o.id = m.organization_id
           WHERE m.user_id = $1 AND o.deleted_at IS NULL ORDER BY o.name LIMIT 50"#
    )
    .bind(&claims.sub)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Database error: {}", e)))?
    .into_iter()
    .map(|(id, name, slug)| OrganizationListItem { id, name, slug })
    .collect();

    tracing::debug!(user_id = %claims.sub, org_count = orgs.len(), "Fetched organizations for user");

    Ok(Json(orgs))
}

/// Create Organization
///
/// Creates a new organization and makes the authenticated user its admin.
/// The slug is auto-generated from the name if not provided.
/// Returns 409 Conflict if the slug is already taken.
/// NEW-1 FIX: Uses Extension(claims) from EiaaAuthzLayer.
pub(crate) async fn create_organization(
    Extension(state): Extension<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateOrganizationRequest>,
) -> Result<Json<OrganizationListItem>> {
    let org = state.organization_service
        .create_organization(&claims.sub, &req.name, req.slug.as_deref())
        .await?;

    tracing::info!(
        user_id = %claims.sub,
        org_id = %org.id,
        org_name = %org.name,
        "Organization created"
    );

    Ok(Json(OrganizationListItem {
        id: org.id,
        name: org.name,
        slug: org.slug,
    }))
}

#[derive(Deserialize, Validate)]
pub struct CreateOrganizationRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    #[validate(length(min = 1, max = 63))]
    pub slug: Option<String>,
}

/// Get Current User
///
/// Returns the current authenticated user based on the verified JWT claims.
/// NEW-1 FIX: Uses Extension(claims) from EiaaAuthzLayer — no manual
/// token extraction or JWT verification. The middleware already validated
/// the token, checked session status, and injected Claims.
pub(crate) async fn get_current_user(
    Extension(state): Extension<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<UserResponse>> {
    // Fetch the user from database
    let user = state.user_service.get_user(&claims.sub).await?;

    // Convert to response format
    let user_resp = state.user_service.to_user_response(&user).await?;

    Ok(Json(user_resp))
}

async fn signup(
    Extension(state): Extension<AppState>,
    _headers: HeaderMap,
    Json(payload): Json<HelperSignupRequest>,

) -> Result<Json<HelperSignupResponse>> {
    let password_hash = auth_core::hash_password(&payload.password)?;

    let ticket = state.verification_service
        .create_signup_ticket(
            &payload.email,
            &password_hash,
            payload.first_name.as_deref(),
            payload.last_name.as_deref(),
            None, // decision_ref: populated by EIAA capsule execution path (MEDIUM-EIAA-9)
        )
        .await?;

    state.verification_service.send_verification_email(ticket.email.as_deref().unwrap_or_default(), ticket.verification_code.as_deref().unwrap_or_default()).await?;

    Ok(Json(HelperSignupResponse {
        ticket_id: ticket.id,
        status: ticket.status,
        requires_verification: true,
    }))
}

/// EIAA-Compliant Sign-In
/// 
/// This route executes a login capsule to authenticate the user.
/// Steps:
/// 1. Lookup user by email
/// 2. Build login capsule with org policy
/// 3. Execute capsule with password verification context
/// 4. Verify decision artifact
/// 5. Create session with decision_ref
/// 6. Issue EIAA-compliant JWT
async fn signin(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<HelperSigninRequest>,
) -> Result<(CookieJar, Json<HelperSigninResponse>)> {
    // 0. Build Request/Network Context for Risk Engine
    let user_agent = headers.get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // In a real deployment, we'd extract IP from X-Forwarded-For or ConnectInfo
    // For now, defaulting to 127.0.0.1 if not found
    let remote_ip = headers.get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| IpAddr::from_str(s.trim()).ok())
        .unwrap_or_else(|| IpAddr::from_str("127.0.0.1").unwrap());

    let network_input = NetworkInput {
        remote_ip,
        x_forwarded_for: headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
        user_agent: user_agent.clone(),
        accept_language: headers.get("accept-language").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
        timestamp: chrono::Utc::now(),
    };

    let request_context = RequestContext {
        network: network_input,
        device: payload.device_signals.clone(),
    };
    
    // 1. Get user by email
    let user = state.user_service.get_user_by_email(&payload.identifier).await?;
    
    // 2. Verify password (pre-check before capsule execution)
    // This is checked before capsule to avoid wasting compute on invalid passwords
    if !state.user_service.verify_user_password(&user.id, &payload.password).await? {
        return Err(AppError::Unauthorized("Invalid credentials".to_string()));
    }

    // 3. Determine Tenant ID
    // Priority: Requested Tenant -> First Active Membership -> Platform (Fallback)
    let tenant_id = match payload.tenant_id.as_deref() {
        Some(t) => {
            // Validate membership if a specific tenant is requested
            let is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM memberships WHERE user_id = $1 AND organization_id = $2)"
            )
            .bind(&user.id)
            .bind(t)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("Membership check failed: {}", e)))?;

            if !is_member {
                 return Err(AppError::Unauthorized("Not a member of the requested organization".into()));
            }
            t.to_string()
        },
        None => {
            // Default to their first active organization
            let default_org: Option<String> = sqlx::query_scalar(
                r#"
                SELECT organization_id FROM memberships m
                JOIN organizations o ON m.organization_id = o.id
                WHERE m.user_id = $1 AND o.deleted_at IS NULL
                ORDER BY m.created_at ASC
                LIMIT 1
                "#
            )
            .bind(&user.id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("Default org lookup failed: {}", e)))?;

            default_org.unwrap_or_else(|| "platform".to_string())
        }
    };

    // 4 & 5. Resolve capsule: Redis cache -> compile fallback -> write-back
    let cache = &state.capsule_cache;
    let capsule_action = "auth:login";

    let (capsule, from_cache, policy_version) = if let Some(cached) = cache.get(&tenant_id, capsule_action).await {
        use prost::Message;
        match grpc_api::eiaa::runtime::CapsuleSigned::decode(cached.capsule_bytes.as_slice()) {
            Ok(c) => (c, true, cached.version),
            Err(_) => {
                tracing::warn!("Failed to decode cached capsule for {}, recompiling", capsule_action);
                let (ast, ver) = build_login_policy_ast(&tenant_id, &state.db).await?;
                let c = compile_login_policy(&ast, &tenant_id, &state).await
                    .map_err(|e| AppError::Internal(format!("Capsule compilation failed: {}", e)))?;
                (c, false, ver)
            }
        }
    } else {
        tracing::debug!("No capsule cached for action '{}', compiling fallback policy", capsule_action);
        let (ast, ver) = build_login_policy_ast(&tenant_id, &state.db).await?;
        let c = compile_login_policy(&ast, &tenant_id, &state).await
            .map_err(|e| AppError::Internal(format!("Capsule compilation failed: {}", e)))?;
        (c, false, ver)
    };

    if !from_cache {
        use prost::Message;
        let mut capsule_bytes = Vec::new();
        if capsule.encode(&mut capsule_bytes).is_ok() {
            let cached = crate::services::capsule_cache::CachedCapsule {
                tenant_id: tenant_id.clone(),
                action: capsule_action.to_string(),
                version: policy_version,
                ast_hash: capsule.ast_hash_b64.clone(),
                wasm_hash: capsule.wasm_hash_b64.clone(),
                capsule_bytes,
                cached_at: chrono::Utc::now().timestamp(),
            };
            if let Err(e) = cache.set(&cached).await {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    action = %capsule_action,
                    policy_version = %policy_version,
                    error = %e,
                    "Login: failed to write compiled capsule to cache (non-fatal)"
                );
            } else {
                tracing::debug!(
                    tenant_id = %tenant_id,
                    action = %capsule_action,
                    policy_version = %policy_version,
                    "Login: compiled capsule written to cache"
                );
            }
        }
    }

    // 5.5. Evaluate Risk
    let risk_eval = state.risk_engine.evaluate(
        &request_context,
        Some(&SubjectContext {
            subject_id: user.id.clone(),
            org_id: tenant_id.clone(),
        }),
        Some("login"),
    ).await;

    // 6. Build input context
    let input = serde_json::json!({
        // RuntimeContext required fields
        "subject_id": 1,
        "risk_score": risk_eval.risk.total_score(),
        "factors_satisfied": [],
        "authz_decision": 1,

        "user_id": user.id,
        "email": payload.identifier,
        "password_verified": true,
        "auth_method": "password",
        "tenant_id": tenant_id,
    });
    let input_json = serde_json::to_string(&input)?;

    // 7. Execute via gRPC — GAP-1 FIX: use shared singleton client
    // The SharedRuntimeClient has a process-wide circuit breaker. If the runtime
    // pod is down, the breaker opens after 5 failures and subsequent signin
    // attempts immediately return an error without waiting for the gRPC timeout.
    let nonce = crate::services::audit_writer::AuditWriter::generate_nonce();
    let response = state.runtime_client
        .execute_capsule(capsule.clone(), input_json.clone(), nonce.clone())
        .await
        .map_err(|e| AppError::Internal(format!("Capsule execution failed: {}", e)))?;

    // 8. Verify decision
    let decision = response.decision
        .ok_or_else(|| AppError::Internal("No decision returned from capsule".into()))?;

    if !decision.allow {
        return Err(AppError::Unauthorized(format!("Login denied: {}", decision.reason)));
    }

    // 9. Generate decision reference and store attestation
    let decision_ref = shared_types::id_generator::generate_id("dec_login");
    
        if let Some(attestation) = response.attestation {
            state.audit_writer.store_attestation(
                &decision_ref,
                &capsule,
                &decision,
                attestation,
                &nonce,
                "login",
                "login_capsule_v1",
                &tenant_id,
                Some(&user.id),
            )?;
        }

    // 10. Create session with decision_ref (EIAA-compliant)
    let session_id = shared_types::id_generator::generate_id("sess");
    
    // Determine AAL based on authentication flow
    // For password-only login, this is AAL1
    let achieved_aal = AssuranceLevel::AAL1;
    let required_aal = risk_eval.constraints.required_assurance;
    let restricted = risk_eval.constraints.session_restrictions.iter().any(|r| {
        matches!(r, SessionRestriction::Provisional | SessionRestriction::EnrollmentOnly | SessionRestriction::ReadOnly)
    });
    let is_provisional = achieved_aal < required_aal || restricted;

    let assurance_level = "aal1";
    let verified_capabilities = serde_json::json!(["password"]);
    
    // Extract device_id from risk evaluation if available (populated by signal collector)
    // Extract device_id from input signals
    let device_id_to_store = payload.device_signals.as_ref().and_then(|ds| ds.device_cookie_id.clone());

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, expires_at, tenant_id, session_type, decision_ref, assurance_level, verified_capabilities, is_provisional, device_id)
        VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3, 'end_user', $4, $5, $6, $7, $8)
        "#
    )
    .bind(&session_id)
    .bind(&user.id)
    .bind(&tenant_id)
    .bind(&decision_ref)
    .bind(assurance_level)
    .bind(&verified_capabilities)
    .bind(is_provisional)
    .bind(&device_id_to_store)
    .execute(&state.db)
    .await?;

    // 10.5. Record Successful Auth and Device Verification
    if let Some(did) = &device_id_to_store {
        if let Some(signals) = &payload.device_signals {
             state.risk_engine.on_device_verified(did, &user.id, signals).await;
        }
    }
    // Record successful auth for risk stability
    // Assuming AAL1 for password
    state.risk_engine.on_successful_auth(&user.id, shared_types::AssuranceLevel::AAL1).await;


    // 11. Generate EIAA-compliant JWT (identity only)
    // Access Token (short-lived, e.g. 5-15 mins)
    let access_token = state.jwt_service.generate_token(
        &user.id,
        &session_id,
        &tenant_id,
        auth_core::jwt::session_types::END_USER,
    )?;

    // Refresh Token (long-lived, matches session expiry, e.g. 24h)
    let refresh_token_str = state.jwt_service.generate_token_with_expiry(
        &user.id,
        &session_id,
        &tenant_id,
        auth_core::jwt::session_types::END_USER,
        24 * 60 * 60, // 24 hours
    )?;

    // 12. Set Cookies
    let is_secure = !state.config.frontend_url.starts_with("http://localhost");
    let refresh_cookie = Cookie::build(("refresh_token", refresh_token_str))
        .http_only(true)
        .secure(is_secure)
        .path("/")
        .same_site(if is_secure { SameSite::Strict } else { SameSite::Lax })
        .build();
    let jar = jar.add(refresh_cookie);

    let session_cookie = Cookie::build(("__session", access_token.clone()))
        .http_only(true)
        .secure(is_secure)
        .path("/")
        .same_site(if is_secure { SameSite::Strict } else { SameSite::Lax })
        // Access token expiry is short, let user rely on refresh token or extend
        .build();
    let jar = jar.add(session_cookie);

    // Also set CSRF token proactively on login
    let csrf_val = crate::middleware::csrf::generate_csrf_token();
    let csrf_cookie = Cookie::build(("__csrf", csrf_val))
        .secure(is_secure)
        .path("/")
        .same_site(if is_secure { SameSite::Strict } else { SameSite::Lax })
        .build();
    let jar = jar.add(csrf_cookie);

    // 13. Return response with decision reference
    let user_resp = state.user_service.to_user_response(&user).await?;
    
    tracing::info!(
        user_id = %user.id,
        tenant_id = %tenant_id,
        decision_ref = %decision_ref,
        "Login successful via EIAA capsule"
    );

    Ok((jar, Json(HelperSigninResponse {
        user: user_resp,
        session_id: session_id,
        jwt: access_token,
        decision_ref: decision_ref,
    })))
}

async fn refresh_token(
    Extension(state): Extension<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<HelperRefreshResponse>)> {
    tracing::info!("Refresh token endpoint called");
    
    let token = jar
        .get("refresh_token")
        .map(|c| c.value().to_string());

    if token.is_none() {
        tracing::warn!("No refresh token cookie found in request");
        return Err(AppError::Unauthorized("No refresh token found".into()));
    }
    let token = token.unwrap();

    // Verify the refresh token (check signature and expiry)
    let claims = state.jwt_service.verify_token(&token).map_err(|e| {
        tracing::warn!("Token verification failed: {}", e);
        e
    })?;

    tracing::info!("Token verified for user: {}", claims.sub);

    // Verify session in database (ensure not revoked) — scoped to tenant
    let session_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sessions WHERE id = $1 AND tenant_id = $2 AND expires_at > NOW())"
    )
    .bind(&claims.sid)
    .bind(&claims.tenant_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Session check failed: {}", e)))?;

    if !session_exists {
        tracing::warn!("Session expired or revoked for sid: {}", claims.sid);
        return Err(AppError::Unauthorized("Session expired or revoked".into()));
    }

    // Issue new Access Token (short-lived)
    let new_access_token = state.jwt_service.generate_token(
        &claims.sub,
        &claims.sid,
        &claims.tenant_id,
        &claims.session_type,
    )?;

    // FIX-FUNC-1: Fetch user so the frontend can restore full auth state on page reload.
    // Previously this endpoint returned only { jwt }, causing silentRefresh() to call
    // setAuth(jwt, undefined) → user was null → UserLayout rendered blank after every reload.
    let user = state.user_service.get_user(&claims.sub).await?;
    let user_resp = state.user_service.to_user_response(&user).await?;

    // Set __session cookie
    let is_secure = !state.config.frontend_url.starts_with("http://localhost");
    let session_cookie = Cookie::build(("__session", new_access_token.clone()))
        .http_only(true)
        .secure(is_secure)
        .path("/")
        .same_site(if is_secure { SameSite::Strict } else { SameSite::Lax })
        .build();
    let jar = jar.add(session_cookie);

    Ok((jar, Json(HelperRefreshResponse {
        jwt: new_access_token,
        user: user_resp,
    })))
}

/// NEW-3 FIX: Logout now invalidates the server-side session.
///
/// Previously, logout only cleared browser cookies. A stolen JWT (or a JWT
/// captured before logout) would remain valid until its natural expiry.
///
/// Now we:
///   1. Expire the session row in the DB (`expires_at = NOW()`)
///   2. Clear all auth cookies (session, refresh, CSRF)
///
/// The EiaaAuthzLayer on this route (action: "session:logout") already
/// verified the JWT and injected Claims, so we just extract them.
async fn logout(
    Extension(state): Extension<AppState>,
    Extension(claims): Extension<Claims>,
) -> impl axum::response::IntoResponse {
    // 1. Invalidate the server-side session — immediate revocation
    let result = sqlx::query(
        "UPDATE sessions SET expires_at = NOW() WHERE id = $1 AND user_id = $2"
    )
    .bind(&claims.sid)
    .bind(&claims.sub)
    .execute(&state.db)
    .await;

    match &result {
        Ok(r) => {
            tracing::info!(
                session_id = %claims.sid,
                user_id = %claims.sub,
                rows_affected = r.rows_affected(),
                "Session invalidated on logout"
            );
        }
        Err(e) => {
            // Log but don't fail — still clear cookies so the user isn't stuck
            tracing::error!(
                session_id = %claims.sid,
                user_id = %claims.sub,
                error = %e,
                "Failed to invalidate session on logout (cookies will still be cleared)"
            );
        }
    }

    // 2. Clear all auth cookies
    let mut headers = axum::http::HeaderMap::new();
    let is_secure = !state.config.frontend_url.starts_with("http://localhost");
    let secure_flag = if is_secure { "; Secure" } else { "" };
    
    let session_clear = format!("__session=; HttpOnly{}; SameSite=Lax; Path=/; Max-Age=0", secure_flag);
    let refresh_clear = format!("refresh_token=; HttpOnly{}; SameSite=Lax; Path=/; Max-Age=0", secure_flag);
    let csrf_clear = format!("__csrf=;{}; SameSite=Lax; Path=/; Max-Age=0", secure_flag);

    headers.append(axum::http::header::SET_COOKIE, session_clear.parse().unwrap());
    headers.append(axum::http::header::SET_COOKIE, refresh_clear.parse().unwrap());
    headers.append(axum::http::header::SET_COOKIE, csrf_clear.parse().unwrap());

    (headers, Json(serde_json::json!({"success": true})))
}

// --- Helper Functions ---

async fn build_login_policy_ast(tenant_id: &str, db: &sqlx::PgPool) -> Result<(Program, i32)> {
    // Try to fetch custom policy for this tenant
    let row: Option<(i32, serde_json::Value)> = sqlx::query_as(
        "SELECT version, spec FROM eiaa_policies WHERE tenant_id = $1 AND action = 'auth:login' ORDER BY version DESC LIMIT 1"
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await?;

    if let Some((version, json)) = row {
        if let Ok(program) = serde_json::from_value::<Program>(json) {
            return Ok((program, version));
        }
    }

    // Default policy: verify identity (simple allow after password verified)
    Ok((Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::AuthorizeAction {
                action: "auth:login".to_string(),
                resource: tenant_id.to_string(),
            },
            Step::Allow(true),
        ],
    }, 0))
}

async fn compile_login_policy(
    policy: &Program,
    tenant_id: &str,
    state: &AppState,
) -> anyhow::Result<CapsuleSigned> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    
    let compiled = capsule_compiler::compile(
        policy.clone(),
        tenant_id.to_string(),
        "auth:login".to_string(),
        now,
        now + 300, // 5 minute validity
        &state.ks,
        &state.compiler_kid,
    )?;

    Ok(CapsuleSigned {
        meta: Some(CapsuleMeta {
            tenant_id: compiled.meta.tenant_id,
            action: compiled.meta.action,
            not_before_unix: compiled.meta.not_before_unix,
            not_after_unix: compiled.meta.not_after_unix,
            policy_hash_b64: compiled.meta.ast_hash_b64,
        }),
        ast_bytes: compiled.ast_bytes,
        capsule_hash_b64: compiled.ast_hash.clone(),
        compiler_kid: compiled.compiler_kid,
        compiler_sig_b64: compiled.compiler_sig_b64,
        ast_hash_b64: compiled.ast_hash,
        wasm_hash_b64: compiled.wasm_hash,
        lowering_version: compiled.lowering_version,
        wasm_bytes: compiled.wasm_bytes,
    })
}




#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use validator::Validate;

    #[test]
    fn test_helper_signup_request_deserialization() {
        // Test camelCase to snake_case mapping
        let json_input = json!({
            "email": "test@example.com",
            "password": "password123",
            "firstName": "John",
            "lastName": "Doe"
        });

        let req: HelperSignupRequest = serde_json::from_value(json_input).expect("Failed to deserialize");
        
        assert_eq!(req.email, "test@example.com");
        assert_eq!(req.password, "password123");
        assert_eq!(req.first_name, Some("John".to_string()));
        assert_eq!(req.last_name, Some("Doe".to_string()));
    }

    #[test]
    fn test_helper_signup_request_validation() {
        // Test invalid email
        let invalid_email = HelperSignupRequest {
            email: "invalid-email".to_string(),
            password: "password123".to_string(),
            first_name: None,
            last_name: None,
            device_signals: None,
        };
        assert!(invalid_email.validate().is_err());

        // Test short password
        let short_password = HelperSignupRequest {
            email: "test@example.com".to_string(),
            password: "short".to_string(),
            first_name: None,
            last_name: None,
            device_signals: None,
        };
        assert!(short_password.validate().is_err());
    }

    #[test]
    fn test_helper_signup_response_serialization() {
        // Test snake_case to camelCase mapping
        let resp = HelperSignupResponse {
            ticket_id: "ticket_123".to_string(),
            status: "pending".to_string(),
            requires_verification: true,
        };

        let json_output = serde_json::to_value(&resp).expect("Failed to serialize");
        
        assert_eq!(json_output["ticketId"], "ticket_123");
        assert_eq!(json_output["status"], "pending");
        assert_eq!(json_output["requiresVerification"], true);
    }
}

