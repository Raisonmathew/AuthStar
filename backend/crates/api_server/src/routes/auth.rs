use crate::services::audit_event_service::{event_types, RecordEventParams};
use crate::services::StoreAttestationParams;
use crate::state::AppState;
use axum::{extract::Extension, http::HeaderMap, routing::post, Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};
use validator::Validate;
// GAP-1 FIX: EiaaRuntimeClient no longer used directly in signin — we use
// state.runtime_client (SharedRuntimeClient) instead.
use crate::capsules::login_capsule::{compile_login_capsule, load_login_policy};

use crate::services::FactorKind;
use auth_core::jwt::Claims;
use identity_engine::models::UserResponse;
use risk_engine::{NetworkInput, RequestContext, SubjectContext, WebDeviceInput};
use shared_types::{AppError, Result, SessionRestriction};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Escape special characters in an LDAP filter value (RFC 4515).
fn ldap_escape_filter_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

/// Helper: extract client IP from headers.
fn extract_ip(headers: &HeaderMap) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| IpAddr::from_str(s.trim()).ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// Helper: extract user-agent from headers.
fn extract_ua(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

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
    #[allow(dead_code)]
    // deserialized from request; consumed when device fingerprinting is wired
    pub device_signals: Option<WebDeviceInput>,
    pub org_slug: Option<String>,
}

#[derive(Serialize)]
pub struct HelperSignupResponse {
    #[serde(rename = "ticketId")]
    pub ticket_id: String,
    pub status: String,
    #[serde(rename = "requiresVerification")]
    pub requires_verification: bool,
    /// True when the verification email was successfully delivered.
    /// False when SMTP is unavailable (non-production only). Tests can then
    /// call POST /api/test/verification-code to retrieve the raw code.
    #[serde(rename = "emailSent")]
    pub email_sent: bool,
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
    #[serde(
        rename = "requiredActions",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub required_actions: Vec<String>,
}

#[derive(Serialize)]
pub struct HelperRefreshResponse {
    pub jwt: String,
    pub user: identity_engine::models::UserResponse,
}

pub mod step_up;

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
    pub role: String,
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
    let orgs: Vec<OrganizationListItem> = sqlx::query_as::<_, (String, String, String, String)>(
        r#"SELECT o.id, o.name, o.slug, m.role FROM organizations o
           JOIN memberships m ON o.id = m.organization_id
           WHERE m.user_id = $1 AND o.deleted_at IS NULL ORDER BY o.name LIMIT 50"#,
    )
    .bind(&claims.sub)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Database error: {e}")))?
    .into_iter()
    .map(|(id, name, slug, role)| OrganizationListItem {
        id,
        name,
        slug,
        role,
    })
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
    let org = state
        .organization_service
        .create_organization(&claims.sub, &req.name, req.slug.as_deref())
        .await?;

    tracing::info!(
        user_id = %claims.sub,
        org_id = %org.id,
        org_name = %org.name,
        "Organization created"
    );

    // Audit: organization created
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: org.id.clone(),
            event_type: event_types::ORG_CREATED,
            actor_id: Some(claims.sub.clone()),
            actor_email: None,
            target_type: Some("organization"),
            target_id: Some(org.id.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({"name": org.name, "slug": org.slug}),
        })
        .await;

    Ok(Json(OrganizationListItem {
        id: org.id,
        name: org.name,
        slug: org.slug,
        role: "admin".to_string(),
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

// ─── Switch Organization ─────────────────────────────────────────────────────

#[derive(Deserialize, Validate)]
pub struct SwitchOrgRequest {
    #[validate(length(min = 1, max = 100))]
    pub organization_id: String,
}

#[derive(Serialize)]
pub struct SwitchOrgResponse {
    pub jwt: String,
    pub user: UserResponse,
    pub organization: OrganizationListItem,
}

/// Switch the authenticated user's active organization.
///
/// Validates membership, creates a new session scoped to the target org,
/// issues new JWT + cookies with the new `tenant_id`, and expires the old session.
pub(crate) async fn switch_organization(
    Extension(state): Extension<AppState>,
    Extension(claims): Extension<Claims>,
    jar: CookieJar,
    Json(req): Json<SwitchOrgRequest>,
) -> Result<(CookieJar, Json<SwitchOrgResponse>)> {
    let user_id = &claims.sub;
    let target_org_id = &req.organization_id;

    // 1. Verify user is a member of the target organization
    let membership: Option<(String, String, String, String)> = sqlx::query_as(
        r#"SELECT o.id, o.name, o.slug, m.role FROM organizations o
           JOIN memberships m ON o.id = m.organization_id
           WHERE m.user_id = $1 AND o.id = $2 AND o.deleted_at IS NULL"#,
    )
    .bind(user_id)
    .bind(target_org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Database error: {e}")))?;

    let (org_id, org_name, org_slug, org_role) = membership
        .ok_or_else(|| AppError::Forbidden("Not a member of this organization".into()))?;

    // 2. Short-circuit if already in the target org
    if claims.tenant_id == org_id {
        let user = state.user_service.get_user(user_id).await?;
        let user_resp = state.user_service.to_user_response(&user).await?;
        // Re-issue current token (no session change needed)
        let jwt = state.jwt_service.generate_token(
            user_id,
            &claims.sid,
            &claims.tenant_id,
            &claims.session_type,
        )?;
        return Ok((
            jar,
            Json(SwitchOrgResponse {
                jwt,
                user: user_resp,
                organization: OrganizationListItem {
                    id: org_id,
                    name: org_name,
                    slug: org_slug,
                    role: org_role,
                },
            }),
        ));
    }

    // 3. Expire the current session
    sqlx::query("UPDATE sessions SET expires_at = NOW() WHERE id = $1 AND user_id = $2")
        .bind(&claims.sid)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to expire old session: {e}")))?;

    // 4. Create a new session scoped to the target org
    let new_session_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        r#"INSERT INTO sessions (id, user_id, tenant_id, session_type, ip_address, user_agent, expires_at)
           VALUES ($1, $2, $3, $4, '0.0.0.0', 'org-switch', NOW() + INTERVAL '24 hours')"#,
    )
    .bind(&new_session_id)
    .bind(user_id)
    .bind(&org_id)
    .bind(&claims.session_type)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Failed to create new session: {e}")))?;

    // 5. Issue new JWT with the target org's tenant_id
    let access_token = state.jwt_service.generate_token(
        user_id,
        &new_session_id,
        &org_id,
        &claims.session_type,
    )?;
    let refresh_token_str = state.jwt_service.generate_token_with_expiry(
        user_id,
        &new_session_id,
        &org_id,
        &claims.session_type,
        86400,
    )?;

    // 6. Fetch user for response
    let user = state.user_service.get_user(user_id).await?;
    let user_resp = state.user_service.to_user_response(&user).await?;

    // 7. Set cookies
    let is_secure = !state.config.frontend_url.starts_with("http://localhost");
    let same_site = if is_secure {
        SameSite::Strict
    } else {
        SameSite::Lax
    };

    let session_cookie = Cookie::build(("__session", access_token.clone()))
        .http_only(true)
        .secure(is_secure)
        .path("/")
        .same_site(same_site)
        .build();
    let refresh_cookie = Cookie::build(("refresh_token", refresh_token_str))
        .http_only(true)
        .secure(is_secure)
        .path("/api/v1/token")
        .same_site(same_site)
        .build();
    let jar = jar.add(session_cookie).add(refresh_cookie);

    tracing::info!(
        user_id = %user_id,
        from_org = %claims.tenant_id,
        to_org = %org_id,
        session_id = %new_session_id,
        "Organization switched"
    );

    // Audit: organization switched
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: org_id.clone(),
            event_type: event_types::ORG_SWITCHED,
            actor_id: Some(user_id.to_string()),
            actor_email: None,
            target_type: Some("organization"),
            target_id: Some(org_id.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({"from_org": claims.tenant_id, "to_org": org_id}),
        })
        .await;

    Ok((
        jar,
        Json(SwitchOrgResponse {
            jwt: access_token,
            user: user_resp,
            organization: OrganizationListItem {
                id: org_id,
                name: org_name,
                slug: org_slug,
                role: org_role,
            },
        }),
    ))
}

async fn signup(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    Json(payload): Json<HelperSignupRequest>,
) -> Result<Json<HelperSignupResponse>> {
    let password_hash = auth_core::hash_password(&payload.password)?;

    // Resolve org_slug to org_id if provided
    let org_id: Option<String> = if let Some(ref slug) = payload.org_slug {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT id FROM organizations WHERE slug = $1 AND deleted_at IS NULL")
                .bind(slug)
                .fetch_optional(&state.db)
                .await?;
        row.map(|(id,)| id)
    } else {
        None
    };

    let ticket = state
        .verification_service
        .create_signup_ticket(
            &payload.email,
            &password_hash,
            payload.first_name.as_deref(),
            payload.last_name.as_deref(),
            None, // decision_ref: populated by EIAA capsule execution path (MEDIUM-EIAA-9)
            org_id.as_deref(),
        )
        .await?;

    let email = ticket
        .email
        .as_deref()
        .ok_or_else(|| AppError::Internal("Signup ticket missing email".into()))?;
    let code = ticket
        .verification_code
        .as_deref()
        .ok_or_else(|| AppError::Internal("Signup ticket missing verification code".into()))?;

    let email_sent = state
        .verification_service
        .send_verification_email(email, code)
        .await
        .is_ok();

    // Audit: signup initiated
    let tenant_for_audit = org_id.clone().unwrap_or_else(|| "platform".into());
    let remote_ip = extract_ip(&headers);
    let ua = extract_ua(&headers);
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: tenant_for_audit,
            event_type: event_types::USER_SIGNUP,
            actor_id: None,
            actor_email: Some(payload.email.clone()),
            target_type: Some("user"),
            target_id: Some(ticket.id.clone()),
            ip_address: Some(remote_ip),
            user_agent: Some(ua),
            metadata: serde_json::json!({"ticket_id": ticket.id}),
        })
        .await;

    Ok(Json(HelperSignupResponse {
        ticket_id: ticket.id,
        status: ticket.status,
        requires_verification: true,
        email_sent,
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
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // In a real deployment, we'd extract IP from X-Forwarded-For or ConnectInfo
    // For now, defaulting to 127.0.0.1 if not found
    let remote_ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| IpAddr::from_str(s.trim()).ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

    let network_input = NetworkInput {
        remote_ip,
        x_forwarded_for: headers
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string()),
        user_agent: user_agent.clone(),
        accept_language: headers
            .get("accept-language")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string()),
        timestamp: chrono::Utc::now(),
    };

    let request_context = RequestContext {
        network: network_input,
        device: payload.device_signals.clone(),
    };

    // 1. Get user by email (org-scoped when tenant_id is provided).
    //    If not found and a tenant_id is given, attempt on-demand LDAP import:
    //    search all enabled LDAP connections for a matching user, verify the
    //    supplied password via LDAP re-bind, and create the account on the fly.
    let (user, ldap_preauth_ok) = {
        let lookup_result = if let Some(ref tid) = payload.tenant_id {
            state
                .user_service
                .get_user_by_email_in_org(&payload.identifier, tid)
                .await
        } else {
            state
                .user_service
                .get_user_by_email(&payload.identifier)
                .await
        };

        match lookup_result {
            Ok(u) => (u, None),
            Err(AppError::NotFound(_)) if payload.tenant_id.is_some() => {
                let tid = payload.tenant_id.as_deref().unwrap();

                // Local struct for the LDAP connection fields we need.
                #[derive(sqlx::FromRow)]
                struct LdapConnForAuth {
                    id: String,
                    host: String,
                    bind_dn: String,
                    bind_password_ref: String,
                    use_ssl: bool,
                    start_tls: bool,
                    skip_tls_verify: bool,
                    connection_timeout_secs: i32,
                    read_timeout_secs: i32,
                    base_dn: String,
                    user_search_filter: String,
                    attr_map_email: String,
                    attr_map_name: String,
                    uuid_attr: String,
                    username_attr: String,
                    page_size: i32,
                    failover_hosts: String,
                    search_scope: String,
                }

                let conns: Vec<LdapConnForAuth> = sqlx::query_as(
                    "SELECT id, host, bind_dn, bind_password_ref, use_ssl, start_tls, skip_tls_verify, \
                            connection_timeout_secs, read_timeout_secs, base_dn, user_search_filter, \
                            attr_map_email, attr_map_name, uuid_attr, username_attr, page_size, \
                            failover_hosts, search_scope \
                     FROM ldap_connections \
                     WHERE tenant_id = $1 AND enabled = true \
                     ORDER BY created_at ASC",
                )
                .bind(tid)
                .fetch_all(&state.db)
                .await
                .unwrap_or_default();

                let mut imported_user = None;
                let mut preauth = false;

                'conn_loop: for cfg in conns {
                    let bind_pw = match state.ldap_encryption.decrypt(&cfg.bind_password_ref) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let port = if cfg.use_ssl { 636i32 } else { 389i32 };

                    let fallback_str = cfg.failover_hosts.clone();
                    let fallback_hosts: Vec<&str> = fallback_str
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .collect();
                    let scope = crate::services::ldap_client::parse_scope(&cfg.search_scope);

                    // Build a search filter that matches the identifier against the email attr.
                    let safe_ident = ldap_escape_filter_value(&payload.identifier);
                    let email_filter = format!(
                        "(&{}({}={safe_ident}))",
                        cfg.user_search_filter, cfg.attr_map_email
                    );
                    let attrs: Vec<&str> = vec![
                        cfg.attr_map_email.as_str(),
                        cfg.attr_map_name.as_str(),
                        cfg.uuid_attr.as_str(),
                        cfg.username_attr.as_str(),
                        "sAMAccountName",
                        "uid",
                        "entryUUID",
                    ];

                    let search = crate::services::ldap_client::search_users(
                        &cfg.host,
                        port,
                        cfg.use_ssl,
                        cfg.start_tls,
                        cfg.skip_tls_verify,
                        &cfg.bind_dn,
                        &bind_pw,
                        &cfg.base_dn,
                        &email_filter,
                        &attrs,
                        cfg.page_size,
                        cfg.connection_timeout_secs.max(3) as u64,
                        cfg.read_timeout_secs.max(5) as u64,
                        &fallback_hosts,
                        scope,
                    )
                    .await;

                    let entries = match search {
                        Ok(r) => r.entries,
                        Err(e) => {
                            tracing::warn!(conn_id = %cfg.id, error = e, "On-demand LDAP search failed");
                            continue;
                        }
                    };

                    for entry in entries {
                        let ok = crate::services::ldap_client::verify_user_password(
                            &cfg.host,
                            port,
                            cfg.use_ssl,
                            cfg.start_tls,
                            cfg.skip_tls_verify,
                            &entry.dn,
                            &payload.password,
                            cfg.connection_timeout_secs.max(3) as u64,
                            cfg.read_timeout_secs.max(5) as u64,
                            &fallback_hosts,
                        )
                        .await;

                        match ok {
                            Ok(true) => {}
                            Ok(false) => continue,
                            Err(e) => {
                                tracing::warn!(conn_id = %cfg.id, error = e, "LDAP on-demand verify failed");
                                continue;
                            }
                        }

                        let email_val = entry
                            .attrs
                            .get(&cfg.attr_map_email)
                            .and_then(|v| v.first())
                            .map(|s| s.to_lowercase())
                            .unwrap_or_else(|| payload.identifier.to_lowercase());
                        let display = entry
                            .attrs
                            .get(&cfg.attr_map_name)
                            .and_then(|v| v.first())
                            .cloned()
                            .unwrap_or_else(|| email_val.clone());
                        let parts: Vec<&str> = display.splitn(2, ' ').collect();
                        let first_name = parts.first().copied().unwrap_or("");
                        let last_name = parts.get(1).copied().unwrap_or("");
                        let ldap_uid = entry
                            .attrs
                            .get(&cfg.username_attr)
                            .or_else(|| entry.attrs.get("sAMAccountName"))
                            .or_else(|| entry.attrs.get("uid"))
                            .and_then(|v| v.first())
                            .cloned()
                            .unwrap_or_else(|| {
                                entry.dn.split(',').next().unwrap_or("").to_string()
                            });
                        let ldap_uuid = entry
                            .attrs
                            .get(&cfg.uuid_attr)
                            .or_else(|| entry.attrs.get("entryUUID"))
                            .and_then(|v| v.first())
                            .cloned();

                        let uid = shared_types::id_generator::generate_id("user");
                        if sqlx::query(
                            "INSERT INTO users \
                             (id, first_name, last_name, organization_id, enabled, created_at, updated_at) \
                             VALUES ($1, $2, $3, $4, true, NOW(), NOW()) ON CONFLICT DO NOTHING",
                        )
                        .bind(&uid).bind(first_name).bind(last_name).bind(tid)
                        .execute(&state.db)
                        .await
                        .is_err() { continue; }

                        let _ = sqlx::query(
                            "INSERT INTO identities \
                             (id, user_id, organization_id, type, identifier, verified, created_at, updated_at) \
                             VALUES ($1, $2, $3, 'email', $4, true, NOW(), NOW()) ON CONFLICT DO NOTHING",
                        )
                        .bind(shared_types::id_generator::generate_id("ident"))
                        .bind(&uid).bind(tid).bind(&email_val)
                        .execute(&state.db).await;

                        let _ = sqlx::query(
                            "INSERT INTO memberships \
                             (id, user_id, organization_id, role, created_at, updated_at) \
                             VALUES ($1, $2, $3, 'member', NOW(), NOW()) ON CONFLICT DO NOTHING",
                        )
                        .bind(shared_types::id_generator::generate_id("mem"))
                        .bind(&uid)
                        .bind(tid)
                        .execute(&state.db)
                        .await;

                        let _ = sqlx::query(
                            "INSERT INTO ldap_federated_users \
                             (id, tenant_id, connection_id, user_id, ldap_dn, ldap_uid, ldap_uuid, last_synced_at) \
                             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) ON CONFLICT DO NOTHING",
                        )
                        .bind(shared_types::id_generator::generate_id("lfu"))
                        .bind(tid).bind(&cfg.id).bind(&uid)
                        .bind(&entry.dn).bind(&ldap_uid).bind(&ldap_uuid)
                        .execute(&state.db).await;

                        state.audit_event_service.record(RecordEventParams {
                            tenant_id: tid.to_string(),
                            event_type: event_types::LDAP_USER_IMPORTED_ON_DEMAND,
                            actor_id: Some(uid.clone()),
                            actor_email: Some(email_val.clone()),
                            target_type: Some("user"),
                            target_id: Some(uid.clone()),
                            ip_address: Some(remote_ip),
                            user_agent: Some(user_agent.clone()),
                            metadata: serde_json::json!({"conn_id": &cfg.id, "ldap_dn": &entry.dn}),
                        }).await;

                        if let Ok(u) = state
                            .user_service
                            .get_user_by_email_in_org(&email_val, tid)
                            .await
                        {
                            imported_user = Some(u);
                            preauth = true;
                            break 'conn_loop;
                        }
                    }
                }

                match imported_user {
                    Some(u) => (u, if preauth { Some(true) } else { None }),
                    None => return Err(AppError::Unauthorized("Invalid credentials".to_string())),
                }
            }
            Err(e) => return Err(e),
        }
    };

    // 2. Determine Tenant ID
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
            .map_err(|e| AppError::Internal(format!("Membership check failed: {e}")))?;

            if !is_member {
                return Err(AppError::Unauthorized(
                    "Not a member of the requested organization".into(),
                ));
            }
            t.to_string()
        }
        None => {
            // Default to their first active organization
            let default_org: Option<String> = sqlx::query_scalar(
                r#"
                SELECT organization_id FROM memberships m
                JOIN organizations o ON m.organization_id = o.id
                WHERE m.user_id = $1 AND o.deleted_at IS NULL
                ORDER BY m.created_at ASC
                LIMIT 1
                "#,
            )
            .bind(&user.id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("Default org lookup failed: {e}")))?;

            default_org.unwrap_or_else(|| "platform".to_string())
        }
    };

    // 3. Run the pluggable authenticator flow. The default browser-login flow
    // currently contains a required password execution, but the route no
    // longer verifies credentials directly.
    //
    // LDAP federation: if the user has an ldap_federated_users record,
    // validate the password via an LDAP re-bind instead of the local hash.
    // The local hash may be empty (LDAP-only users have no stored password).
    //
    // `ldap_preauth_ok = Some(true)` means we already verified the password
    // during on-demand import above — skip the LDAP re-bind.
    state
        .credential_lockout_service
        .ensure_not_locked(
            &tenant_id,
            &user.id,
            crate::services::credential_lockout::FactorKind::Password,
        )
        .await?;

    let ldap_auth_outcome: Option<bool> = if ldap_preauth_ok == Some(true) {
        Some(true)
    } else {
        // Look up federation link for this user in this tenant
        let fed =
            sqlx::query_as::<_, (String, String, String, bool, bool, i32, bool, i32, String)>(
                "SELECT lc.host, lc.bind_password_ref, lfu.ldap_dn, \
                    lc.use_ssl, lc.start_tls, lc.connection_timeout_secs, lc.skip_tls_verify, \
                    lc.read_timeout_secs, lc.failover_hosts \
             FROM ldap_federated_users lfu \
             INNER JOIN ldap_connections lc ON lc.id = lfu.connection_id \
             WHERE lfu.user_id = $1 AND lfu.tenant_id = $2 AND lc.enabled = true \
             LIMIT 1",
            )
            .bind(&user.id)
            .bind(&tenant_id)
            .fetch_optional(&state.db)
            .await
            .unwrap_or(None);

        if let Some((
            host,
            enc_pw,
            user_dn,
            use_ssl,
            start_tls,
            timeout,
            skip_tls_verify,
            read_timeout,
            failover_str,
        )) = fed
        {
            let _ = enc_pw; // bind password not needed for user re-bind
            let port = if use_ssl { 636i32 } else { 389i32 };
            let fallback_hosts: Vec<&str> = failover_str
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            match crate::services::ldap_client::verify_user_password(
                &host,
                port,
                use_ssl,
                start_tls,
                skip_tls_verify,
                &user_dn,
                &payload.password,
                timeout.max(3) as u64,
                read_timeout.max(5) as u64,
                &fallback_hosts,
            )
            .await
            {
                Ok(ok) => Some(ok),
                Err(e) => {
                    // LDAP unreachable / timeout → fall through to local password check.
                    tracing::warn!(
                        user_id = user.id,
                        error = e,
                        "LDAP verify_user_password error — falling back to local auth"
                    );
                    None
                }
            }
        } else {
            None // not a federated user — fall through to local password check
        }
    };

    let auth_outcome = if let Some(ldap_ok) = ldap_auth_outcome {
        if !ldap_ok {
            let _ = state
                .credential_lockout_service
                .record_failure(
                    &tenant_id,
                    &user.id,
                    crate::services::credential_lockout::FactorKind::Password,
                )
                .await;
            state
                .audit_event_service
                .record(RecordEventParams {
                    tenant_id: tenant_id.clone(),
                    event_type: event_types::USER_LOGIN_FAILED,
                    actor_id: Some(user.id.clone()),
                    actor_email: Some(payload.identifier.clone()),
                    target_type: Some("user"),
                    target_id: Some(user.id.clone()),
                    ip_address: Some(remote_ip),
                    user_agent: Some(user_agent.clone()),
                    metadata: serde_json::json!({"reason": "ldap_invalid_credentials"}),
                })
                .await;
            return Err(AppError::Unauthorized("Invalid credentials".to_string()));
        }
        // Build a synthetic outcome equivalent to AAL1 password success
        use crate::services::authenticators::{AuthFlowOutcome, FactorEvidence};
        use crate::services::credential_lockout::FactorKind;
        let _ = state
            .credential_lockout_service
            .record_success(&tenant_id, &user.id, FactorKind::Password)
            .await;
        AuthFlowOutcome {
            evidence: vec![FactorEvidence {
                factor: FactorKind::Password,
                capability: "password".to_string(),
                aal: shared_types::AssuranceLevel::AAL1,
            }],
            verified_capabilities: vec!["password".to_string()],
            assurance_level: shared_types::AssuranceLevel::AAL1,
        }
    } else {
        match state
            .auth_flow_engine
            .run_password_login(&tenant_id, &user, &payload.password)
            .await
        {
            Ok(outcome) => outcome,
            Err(AppError::Unauthorized(reason)) => {
                state
                    .audit_event_service
                    .record(RecordEventParams {
                        tenant_id: tenant_id.clone(),
                        event_type: event_types::USER_LOGIN_FAILED,
                        actor_id: Some(user.id.clone()),
                        actor_email: Some(payload.identifier.clone()),
                        target_type: Some("user"),
                        target_id: Some(user.id.clone()),
                        ip_address: Some(remote_ip),
                        user_agent: Some(user_agent.clone()),
                        metadata: serde_json::json!({"reason": reason}),
                    })
                    .await;
                return Err(AppError::Unauthorized("Invalid credentials".to_string()));
            }
            Err(e) => return Err(e),
        }
    };

    let required_action_records = if tenant_id == "platform" {
        Vec::new()
    } else {
        state
            .required_action_service
            .evaluate_and_sync(&tenant_id, &user.id)
            .await?
    };
    let required_actions: Vec<String> = required_action_records
        .iter()
        .map(|a| a.code.clone())
        .collect();
    let credential_attempts = state
        .credential_lockout_service
        .snapshot(&tenant_id, &user.id)
        .await
        .unwrap_or_default();

    let factors_satisfied: Vec<i32> = auth_outcome
        .evidence
        .iter()
        .map(|e| match e.factor {
            FactorKind::Totp => 0,
            FactorKind::WebAuthn => 1,
            FactorKind::Hotp | FactorKind::RecoveryCode | FactorKind::Sms | FactorKind::Email => 0,
            FactorKind::Password => 4,
        })
        .collect();

    // 4 & 5. Resolve capsule: Redis cache -> compile fallback -> write-back
    let cache = &state.capsule_cache;
    let capsule_action = "auth:login";

    let (capsule, from_cache, policy_version) = if let Some(cached) =
        cache.get(&tenant_id, capsule_action).await
    {
        use prost::Message;
        match grpc_api::eiaa::runtime::CapsuleSigned::decode(cached.capsule_bytes.as_slice()) {
            Ok(c) => (c, true, cached.version),
            Err(_) => {
                tracing::warn!(
                    "Failed to decode cached capsule for {}, recompiling",
                    capsule_action
                );
                let (ast, ver) = load_login_policy(&tenant_id, &state.db)
                    .await
                    .map_err(|e| AppError::Internal(format!("Policy load failed: {e}")))?;
                let c = compile_login_capsule(&ast, &tenant_id, &state)
                    .await
                    .map_err(|e| AppError::Internal(format!("Capsule compilation failed: {e}")))?;
                (c, false, ver)
            }
        }
    } else {
        tracing::debug!(
            "No capsule cached for action '{}', compiling fallback policy",
            capsule_action
        );
        let (ast, ver) = load_login_policy(&tenant_id, &state.db)
            .await
            .map_err(|e| AppError::Internal(format!("Policy load failed: {e}")))?;
        let c = compile_login_capsule(&ast, &tenant_id, &state)
            .await
            .map_err(|e| AppError::Internal(format!("Capsule compilation failed: {e}")))?;
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
                not_after_unix: capsule.meta.as_ref().map_or(0, |m| m.not_after_unix),
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

    // 5.5. Evaluate Risk (user login — non-admin band)
    let risk_eval = state
        .risk_engine
        .evaluate(
            &request_context,
            Some(&SubjectContext {
                subject_id: user.id.clone(),
                org_id: tenant_id.clone(),
            }),
            Some("login"),
            false,
        )
        .await;

    // 6. Build input context
    let input = serde_json::json!({
        // RuntimeContext required fields
        "subject_id": 1,
        "risk_score": risk_eval.risk.total_score(),
        "factors_satisfied": factors_satisfied,
        "verified_capabilities": auth_outcome.verified_capabilities.clone(),
        "assurance_level": auth_outcome.assurance_level.as_i16(),
        "required_actions": required_actions.clone(),
        "credential_attempts": credential_attempts,
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
    let response = state
        .runtime_client
        .execute_capsule(capsule.clone(), input_json.clone(), nonce.clone())
        .await
        .map_err(|e| AppError::Internal(format!("Capsule execution failed: {e}")))?;

    // 8. Verify decision
    let decision = response
        .decision
        .ok_or_else(|| AppError::Internal("No decision returned from capsule".into()))?;

    if !decision.allow {
        return Err(AppError::Unauthorized(format!(
            "Login denied: {}",
            decision.reason
        )));
    }

    // 9. Generate decision reference and store attestation
    let decision_ref = shared_types::id_generator::generate_id("dec_login");

    if let Some(attestation) = response.attestation {
        state
            .audit_writer
            .store_attestation(StoreAttestationParams {
                decision_ref: &decision_ref,
                capsule: &capsule,
                decision: &decision,
                attestation,
                nonce: &nonce,
                action: "login",
                capsule_version: "login_capsule_v1",
                tenant_id: &tenant_id,
                user_id: Some(&user.id),
            })?;
    }

    // 10. Create session with decision_ref (EIAA-compliant)
    let session_id = shared_types::id_generator::generate_id("sess");

    // Determine AAL based on authentication flow
    // For password-only login, this is AAL1
    let achieved_aal = auth_outcome.assurance_level;
    let required_aal = risk_eval.constraints.required_assurance;
    let restricted = risk_eval.constraints.session_restrictions.iter().any(|r| {
        matches!(
            r,
            SessionRestriction::Provisional
                | SessionRestriction::EnrollmentOnly
                | SessionRestriction::ReadOnly
        )
    });
    let is_provisional = achieved_aal < required_aal || restricted;

    let aal_level: i16 = achieved_aal.as_i16();
    let verified_capabilities = serde_json::json!(auth_outcome.verified_capabilities.clone());

    // Extract device_id from risk evaluation if available (populated by signal collector)
    // Extract device_id from input signals
    let device_id_to_store = payload
        .device_signals
        .as_ref()
        .and_then(|ds| ds.device_cookie_id.clone());

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, expires_at, tenant_id, session_type, decision_ref, aal_level, verified_capabilities, is_provisional, device_id)
        VALUES ($1, $2, NOW() + INTERVAL '1 hour', $3, 'end_user', $4, $5, $6, $7, $8)
        "#
    )
    .bind(&session_id)
    .bind(&user.id)
    .bind(&tenant_id)
    .bind(&decision_ref)
    .bind(aal_level)
    .bind(&verified_capabilities)
    .bind(is_provisional)
    .bind(&device_id_to_store)
    .execute(&state.db)
    .await?;

    // 10.5. Record Successful Auth and Device Verification
    if let Some(did) = &device_id_to_store {
        if let Some(signals) = &payload.device_signals {
            state
                .risk_engine
                .on_device_verified(did, &user.id, signals)
                .await;
        }
    }
    // Record successful auth for risk stability
    // Assuming AAL1 for password
    state
        .risk_engine
        .on_successful_auth(&user.id, shared_types::AssuranceLevel::AAL1)
        .await;

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
        .same_site(if is_secure {
            SameSite::Strict
        } else {
            SameSite::Lax
        })
        .build();
    let jar = jar.add(refresh_cookie);

    let session_cookie = Cookie::build(("__session", access_token.clone()))
        .http_only(true)
        .secure(is_secure)
        .path("/")
        .same_site(if is_secure {
            SameSite::Strict
        } else {
            SameSite::Lax
        })
        // Access token expiry is short, let user rely on refresh token or extend
        .build();
    let jar = jar.add(session_cookie);

    // Also set CSRF token proactively on login
    let csrf_val = crate::middleware::csrf::generate_csrf_token();
    let csrf_cookie = Cookie::build(("__csrf", csrf_val))
        .secure(is_secure)
        .path("/")
        .same_site(if is_secure {
            SameSite::Strict
        } else {
            SameSite::Lax
        })
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

    // Audit: successful login
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: tenant_id.clone(),
            event_type: event_types::USER_LOGIN_SUCCESS,
            actor_id: Some(user.id.clone()),
            actor_email: Some(payload.identifier.clone()),
            target_type: Some("session"),
            target_id: Some(session_id.clone()),
            ip_address: Some(remote_ip),
            user_agent: Some(user_agent),
            metadata: serde_json::json!({
                "decision_ref": decision_ref,
                "session_type": "end_user",
            }),
        })
        .await;

    Ok((
        jar,
        Json(HelperSigninResponse {
            user: user_resp,
            session_id,
            jwt: access_token,
            decision_ref,
            required_actions,
        }),
    ))
}

async fn refresh_token(
    Extension(state): Extension<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<(CookieJar, Json<HelperRefreshResponse>)> {
    tracing::info!("Refresh token endpoint called");

    let token = jar.get("refresh_token").map(|c| c.value().to_string());

    if token.is_none() {
        tracing::warn!("No refresh token cookie found in request");
        return Err(AppError::Unauthorized("No refresh token found".into()));
    }
    let token = token.expect("checked Some above");

    // Verify the refresh token (check signature and expiry)
    let claims = state.jwt_service.verify_token(&token).map_err(|e| {
        tracing::warn!("Token verification failed: {}", e);
        e
    })?;

    tracing::info!("Token verified for user: {}", claims.sub);

    // Verify session in database (ensure not revoked) — scoped to tenant.
    // Also fetch the current `aal_level` so we can preserve it across refresh.
    // Without this, EIAA middleware reads aal=0 from a stale-looking session
    // and step-up-protected pages 403 immediately after a silent refresh.
    let session_row: Option<(bool, i16)> = sqlx::query_as(
        "SELECT (expires_at > NOW() AND revoked = FALSE) AS valid, aal_level \
         FROM sessions WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&claims.sid)
    .bind(&claims.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(format!("Session check failed: {e}")))?;

    let (session_valid, _session_aal) = session_row.unwrap_or((false, 0));

    if !session_valid {
        tracing::warn!("Session expired or revoked for sid: {}", claims.sid);
        return Err(AppError::Unauthorized("Session expired or revoked".into()));
    }

    // Risk re-evaluation guard.
    //
    // The refresh route intentionally bypasses `EiaaAuthzLayer` because that
    // layer requires a valid `__session` JWT — which by definition no longer
    // exists when a client is calling refresh. To avoid letting a stolen
    // refresh-token cookie outlive any subsequent risk escalation (new geo,
    // VPN/Tor turn-on, datacenter IP, impossible travel, etc.), we run the
    // risk engine here against the session's subject loaded from claims.
    //
    // Defensive: if evaluation itself fails or returns a low score, refresh
    // proceeds normally. We only deny on positive, high-confidence escalation.
    let is_admin = claims.session_type == auth_core::jwt::session_types::ADMIN;
    let request_ctx = RequestContext {
        network: NetworkInput {
            remote_ip: extract_ip(&headers),
            x_forwarded_for: headers
                .get("x-forwarded-for")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string()),
            user_agent: extract_ua(&headers),
            accept_language: headers
                .get("accept-language")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string()),
            timestamp: chrono::Utc::now(),
        },
        device: None,
    };
    let subject_ctx = SubjectContext {
        subject_id: claims.sub.clone(),
        org_id: claims.tenant_id.clone(),
    };
    let evaluation = state
        .risk_engine
        .evaluate(&request_ctx, Some(&subject_ctx), None, is_admin)
        .await;
    let score = evaluation.risk.total_score();

    // Threshold is the single source of truth from `state.config.eiaa.risk_threshold`
    // (env var `EIAA_RISK_THRESHOLD`, default 80.0). Mirrors what `EiaaAuthzLayer`
    // applies on regular protected routes — see router.rs `eiaa_config()`.
    // Refusing here forces the client through full re-login, which runs the
    // same risk engine and may require step-up to AAL2/AAL3.
    let threshold = state.config.eiaa.risk_threshold;
    if score >= threshold {
        // Observability: counter for SRE dashboards and alerting on stolen-cookie
        // exfiltration attempts. Labeled by session class so admin denials can
        // page on-call independently from end-user denials.
        metrics::counter!(
            "auth_refresh_denied_total",
            "reason" => "risk_threshold",
            "session_type" => if is_admin { "admin" } else { "user" }
        )
        .increment(1);

        tracing::warn!(
            user_id = %claims.sub,
            session_id = %claims.sid,
            tenant_id = %claims.tenant_id,
            risk_score = score,
            threshold,
            is_admin,
            "Refresh denied: risk score exceeds threshold — forcing full re-auth"
        );

        // Audit trail: SOC2 / ISO 27001 require an immutable record of every
        // security-relevant authn rejection. We use SESSION_REVOKED with a
        // structured `reason` so dashboards can filter risk-denied refreshes.
        state
            .audit_event_service
            .record(crate::services::audit_event_service::RecordEventParams {
                tenant_id: claims.tenant_id.clone(),
                event_type: crate::services::audit_event_service::event_types::SESSION_REVOKED,
                actor_id: Some(claims.sub.clone()),
                actor_email: None,
                target_type: Some("session"),
                target_id: Some(claims.sid.clone()),
                ip_address: Some(request_ctx.network.remote_ip),
                user_agent: Some(request_ctx.network.user_agent.clone()),
                metadata: serde_json::json!({
                    "reason": "refresh_risk_denied",
                    "risk_score": score,
                    "threshold": threshold,
                    "is_admin": is_admin,
                }),
            })
            .await;

        // Revoke the session so the same refresh cookie can't be replayed.
        // Failure to revoke is non-fatal — we still return Unauthorized below
        // and the client must re-login, but a healthy DB eliminates the
        // stolen-cookie window entirely.
        if let Err(e) = sqlx::query(
            "UPDATE sessions SET revoked = TRUE, revoked_at = NOW() \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&claims.sid)
        .bind(&claims.tenant_id)
        .execute(&state.db)
        .await
        {
            tracing::error!(
                session_id = %claims.sid,
                error = %e,
                "Failed to revoke session after risk-denied refresh"
            );
        }
        return Err(AppError::Unauthorized(
            "Session refresh denied due to elevated risk; please sign in again".into(),
        ));
    }

    // Touch the session row to keep aal_level immutable across refresh.
    // (sessions.aal_level is the source of truth for EIAA middleware checks;
    // we explicitly read-back above to verify the row exists with its AAL
    // intact — no UPDATE is needed because refresh shouldn't downgrade AAL.)

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
        .same_site(if is_secure {
            SameSite::Strict
        } else {
            SameSite::Lax
        })
        .build();
    let jar = jar.add(session_cookie);

    Ok((
        jar,
        Json(HelperRefreshResponse {
            jwt: new_access_token,
            user: user_resp,
        }),
    ))
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
    // Audit: logout
    state
        .audit_event_service
        .record(RecordEventParams {
            tenant_id: claims.tenant_id.clone(),
            event_type: event_types::USER_LOGOUT,
            actor_id: Some(claims.sub.clone()),
            actor_email: None,
            target_type: Some("session"),
            target_id: Some(claims.sid.clone()),
            ip_address: None,
            user_agent: None,
            metadata: serde_json::json!({}),
        })
        .await;

    // 1. Invalidate the server-side session — immediate revocation
    // RLS defense-in-depth: TenantConn sets app.current_org_id on the connection
    let result = match crate::middleware::tenant_conn::TenantConn::acquire(&state.db, &claims.tenant_id).await {
        Ok(mut conn) => {
            sqlx::query(
                "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(), expires_at = LEAST(expires_at, NOW()) WHERE id = $1 AND user_id = $2 AND tenant_id = $3"
            )
            .bind(&claims.sid)
            .bind(&claims.sub)
            .bind(&claims.tenant_id)
            .execute(&mut **conn)
            .await
        }
        Err(_) => {
            // Fallback to raw pool if TenantConn acquire fails (pool exhaustion)
            sqlx::query(
                "UPDATE sessions SET revoked = TRUE, revoked_at = NOW(), expires_at = LEAST(expires_at, NOW()) WHERE id = $1 AND user_id = $2 AND tenant_id = $3"
            )
            .bind(&claims.sid)
            .bind(&claims.sub)
            .bind(&claims.tenant_id)
            .execute(&state.db)
            .await
        }
    };

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

    let session_clear =
        format!("__session=; HttpOnly{secure_flag}; SameSite=Lax; Path=/; Max-Age=0");
    let refresh_clear =
        format!("refresh_token=; HttpOnly{secure_flag}; SameSite=Lax; Path=/; Max-Age=0");
    let csrf_clear = format!("__csrf=;{secure_flag}; SameSite=Lax; Path=/; Max-Age=0");

    headers.append(
        axum::http::header::SET_COOKIE,
        session_clear.parse().expect("valid cookie header"),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        refresh_clear.parse().expect("valid cookie header"),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        csrf_clear.parse().expect("valid cookie header"),
    );

    (headers, Json(serde_json::json!({"success": true})))
}

// --- Helper Functions ---

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

        let req: HelperSignupRequest =
            serde_json::from_value(json_input).expect("Failed to deserialize");

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
            org_slug: None,
        };
        assert!(invalid_email.validate().is_err());

        // Test short password
        let short_password = HelperSignupRequest {
            email: "test@example.com".to_string(),
            password: "short".to_string(),
            first_name: None,
            last_name: None,
            org_slug: None,
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
            email_sent: true,
        };

        let json_output = serde_json::to_value(&resp).expect("Failed to serialize");

        assert_eq!(json_output["ticketId"], "ticket_123");
        assert_eq!(json_output["status"], "pending");
        assert_eq!(json_output["requiresVerification"], true);
        assert_eq!(json_output["emailSent"], true);
    }
}
