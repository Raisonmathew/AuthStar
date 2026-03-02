use axum::{
    extract::{State, Extension},
    routing::{get, post},
    Json, Router,
    http::{HeaderMap, header},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};
use validator::Validate;
use crate::state::AppState;
// GAP-1 FIX: EiaaRuntimeClient no longer used directly in signin — we use
// state.runtime_client (SharedRuntimeClient) instead.
use capsule_compiler::ast::{Program, Step, IdentitySource};
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use shared_types::{AppError, Result, AssuranceLevel, SessionRestriction};
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
pub(crate) async fn get_user_organizations(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<OrganizationListItem>>> {
    let token = extract_token(&headers)?;

    // Verify the JWT
    let claims = state.jwt_service.verify_token(&token)?;

    // Query organizations the authenticated user is a member of
    let orgs: Vec<OrganizationListItem> = sqlx::query_as::<_, (String, String, String)>(
        r#"SELECT o.id, o.name, o.slug FROM organizations o
           JOIN memberships m ON o.id = m.organization_id
           WHERE m.user_id = $1 AND o.deleted_at IS NULL ORDER BY o.name LIMIT 50"#
    )
    .bind(&claims.sub)  // User ID from verified JWT
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
pub(crate) async fn create_organization(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateOrganizationRequest>,
) -> Result<Json<OrganizationListItem>> {
    let token = extract_token(&headers)?;
    let claims = state.jwt_service.verify_token(&token)?;

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
/// Returns the current authenticated user based on the JWT in the Authorization header.
pub(crate) async fn get_current_user(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserResponse>> {
    let token = extract_token(&headers)?;

    // Verify the JWT
    let claims = state.jwt_service.verify_token(&token)?;

    // Fetch the user from database
    let user = state.user_service.get_user(&claims.sub).await?;

    // Convert to response format
    let user_resp = state.user_service.to_user_response(&user).await?;

    Ok(Json(user_resp))
}

/// Extract auth token from cookie first, then Authorization header.
fn extract_token(headers: &HeaderMap) -> Result<String> {
    // 1. Try httpOnly session cookie
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix("__session=") {
                    let token = token.trim();
                    if !token.is_empty() {
                        return Ok(token.to_string());
                    }
                }
            }
        }
    }

    // 2. Fall back to Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".into()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header format".into()))?;

    Ok(token.to_string())
}

async fn signup(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
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

    // 4. Build login policy AST
    let policy_ast = build_login_policy_ast(&tenant_id, &state.db).await?;

    // 5. Compile to capsule
    let capsule = compile_login_policy(&policy_ast, &tenant_id, &state).await
        .map_err(|e| AppError::Internal(format!("Capsule compilation failed: {}", e)))?;

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
    let nonce = generate_nonce();
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
            store_login_attestation(
                &state.audit_writer,
                &decision_ref,
                &capsule,
                &decision,
                attestation,
                &nonce,
                &tenant_id,
                &user.id,
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

async fn logout() -> impl axum::response::IntoResponse {
    let mut headers = axum::http::HeaderMap::new();
    let is_secure = !std::env::var("FRONTEND_URL").unwrap_or_default().starts_with("http://localhost");
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

async fn build_login_policy_ast(tenant_id: &str, db: &sqlx::PgPool) -> Result<Program> {
    // Try to fetch custom policy for this tenant
    let policy_json: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT spec FROM eiaa_policies WHERE tenant_id = $1 AND action = 'auth:login' ORDER BY version DESC LIMIT 1"
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await?;

    if let Some(json) = policy_json {
        if let Ok(program) = serde_json::from_value::<Program>(json) {
            return Ok(program);
        }
    }

    // Default policy: verify identity (simple allow after password verified)
    Ok(Program {
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
    })
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

fn generate_nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn store_login_attestation(
    audit_writer: &crate::services::audit_writer::AuditWriter,
    decision_ref: &str,
    capsule: &CapsuleSigned,
    decision: &grpc_api::eiaa::runtime::Decision,
    attestation: grpc_api::eiaa::runtime::Attestation,
    nonce: &str,
    tenant_id: &str,
    user_id: &str,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    // Hash full context for input_digest (not just nonce) - EIAA compliance
    let mut hasher = Sha256::new();
    hasher.update(capsule.capsule_hash_b64.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(b"login");
    let input_digest = URL_SAFE_NO_PAD.encode(hasher.finalize());

    // Get decision hash from attestation body
    let attestation_body = attestation.body.as_ref()
        .ok_or_else(|| AppError::Internal("Attestation body missing".into()))?;
    let attestation_hash_b64 = {
        let body_json = serde_json::to_vec(attestation_body)
            .map_err(|e| AppError::Internal(format!("Attestation body json: {}", e)))?;
        let mut hasher = Sha256::new();
        hasher.update(&body_json);
        Some(URL_SAFE_NO_PAD.encode(hasher.finalize()))
    };

    audit_writer.record(crate::services::audit_writer::AuditRecord {
        decision_ref: decision_ref.to_string(),
        capsule_hash_b64: capsule.capsule_hash_b64.clone(),
        capsule_version: "login_capsule_v1".to_string(),
        action: "login".to_string(),
        tenant_id: tenant_id.to_string(),
        input_digest,
        nonce_b64: nonce.to_string(),
        decision: crate::services::audit_writer::AuditDecision {
            allow: decision.allow,
            reason: if decision.reason.is_empty() { None } else { Some(decision.reason.clone()) },
        },
        attestation_signature_b64: attestation.signature_b64.clone(),
        attestation_timestamp: chrono::Utc::now(),
        attestation_hash_b64,
        user_id: Some(user_id.to_string()),
    });

    tracing::info!("Queued login attestation for decision: {}", decision_ref);
    Ok(())
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

