use axum::{
    extract::{Path, State, ConnectInfo},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use std::net::{IpAddr, SocketAddr};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use crate::state::AppState;
use crate::services::flow_state_service::{FlowStateService, flow_steps, flow_purposes};
// GAP-1 FIX: Use SharedRuntimeClient from AppState instead of per-request connect
use capsule_compiler::ast::Program;
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use identity_engine::services::CreateSessionParams;

#[derive(Debug, Serialize)]
pub struct OrganizationHostedConfig {
    pub org_id: String,
    pub slug: String,
    pub display_name: String,
    pub branding: BrandingSafeConfig,
    pub login_methods: LoginMethodsConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BrandingSafeConfig {
    pub logo_url: Option<String>,
    pub primary_color: String,
    pub background_color: String,
    pub text_color: String,
    pub font_family: String,
}

#[derive(Debug, Serialize)]
pub struct LoginMethodsConfig {
    pub email_password: bool,
    pub passkey: bool,
    pub sso: bool,
}

// === EIAA Flow Intent & Purpose ===

/// Frontend-facing intent (UX terms)
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FlowIntent {
    Login,
    Signup,
    ResetPassword,
    CreateTenant,
}

/// Internal security semantics (backend-only)
#[derive(Clone, Debug, PartialEq)]
pub enum FlowPurpose {
    Authenticate,
    AdminLogin,
    EnrollIdentity,
    CreateTenant,

    /// EIAA: Credential recovery is distinct from authentication
    CredentialRecovery,
}

impl From<FlowIntent> for FlowPurpose {
    fn from(intent: FlowIntent) -> Self {
        match intent {
            FlowIntent::Login => FlowPurpose::Authenticate,
            FlowIntent::Signup => FlowPurpose::EnrollIdentity,
            FlowIntent::CreateTenant => FlowPurpose::CreateTenant,
            // EIAA: Password reset is credential recovery, not authentication
            FlowIntent::ResetPassword => FlowPurpose::CredentialRecovery,
        }
    }
}

impl FlowPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            FlowPurpose::Authenticate => flow_purposes::AUTHENTICATE,
            FlowPurpose::AdminLogin => flow_purposes::ADMIN_LOGIN,
            FlowPurpose::EnrollIdentity => flow_purposes::ENROLL_IDENTITY,
            FlowPurpose::CreateTenant => flow_purposes::CREATE_TENANT,

            FlowPurpose::CredentialRecovery => flow_purposes::CREDENTIAL_RECOVERY,
        }
    }
}

#[derive(Deserialize)]
pub struct InitFlowRequest {
    pub org_id: String,
    /// Frontend intent: "login" or "signup"
    pub intent: FlowIntent,
    pub app_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[derive(Serialize)]
pub struct InitFlowResponse {
    pub flow_id: String,
    pub ui_step: UiStep,
    /// EIAA: Acceptable authentication capabilities based on risk
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub acceptable_capabilities: Vec<String>,
    /// EIAA: Required assurance level (AAL0-AAL3)
    pub required_aal: String,
    /// EIAA: Current risk level (Low/Medium/High)
    pub risk_level: String,
    /// Display name of the organization
    pub org_name: String,
    /// Branding configuration
    pub branding: BrandingSafeConfig,
}

// ... (existing structs)



// === EIAA UI Step Types ===

/// Typed credential field for dynamic signup forms
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CredentialField {
    pub name: String,
    pub label: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
}

/// Factor choice option for multi-method selection
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FactorOption {
    #[serde(rename = "type")]
    pub factor_type: String,
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum UiStep {
    // === Login Steps ===
    #[serde(rename = "email")]
    Email { label: String, required: bool },
    #[serde(rename = "password")]
    Password { label: String },
    #[serde(rename = "otp")]
    Otp { label: String },
    
    // === Passkey Steps ===
    #[serde(rename = "passkey_challenge")]
    PasskeyChallenge {
        session_id: String,
        options: serde_json::Value,
        user_id: String,
    },
    
    // === Signup Steps ===
    #[serde(rename = "credentials")]
    Credentials { fields: Vec<CredentialField> },
    #[serde(rename = "email_verification")]
    EmailVerification { label: String, email: String },
    
    // === Credential Recovery Steps (EIAA) ===
    #[serde(rename = "reset_code_verification")]
    ResetCodeVerification { label: String, email: String },
    #[serde(rename = "new_password")]
    NewPassword { label: String, hint: Option<String> },
    
    // === Multi-Factor Choice ===
    #[serde(rename = "factor_choice")]
    FactorChoice { options: Vec<FactorOption> },
    
    // === Error ===
    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Deserialize)]
pub struct SubmitStepRequest {
    #[serde(rename = "type")]
    pub step_type: String,
    pub value: serde_json::Value,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum SubmitStepResponse {
    NextStep {
        flow_id: String,
        ui_step: UiStep,
        /// EIAA: Currently achieved assurance level
        #[serde(skip_serializing_if = "Option::is_none")]
        achieved_aal: Option<String>,
        /// EIAA: Remaining acceptable capabilities
        #[serde(skip_serializing_if = "Vec::is_empty")]
        acceptable_capabilities: Vec<String>,
    },
    Decision {
        status: String,
        decision_ref: String,
        /// EIAA: Final assurance level achieved
        #[serde(skip_serializing_if = "Option::is_none")]
        achieved_aal: Option<String>,
        /// JWT Session Token (if authentication successful)
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
}

/// Hosted routes for tenant-scoped login pages.
///
/// - `GET /organizations/:slug` — **Active.** Returns org branding/config for
///   the login page UI. Used by the frontend's AuthFlowPage.
/// - `POST /auth/flows` — **Deprecated.** Legacy flow init (replaced by
///   `/api/auth/flow/init`). Logs a deprecation warning on each call.
/// - `POST /auth/flows/:id/submit` — **Deprecated.** Legacy flow submit
///   (replaced by `/api/auth/flow/:id/submit`). Logs a deprecation warning.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/organizations/:slug", get(get_hosted_org))
        .route("/auth/flows", post(init_flow))
        .route("/auth/flows/:flow_id/submit", post(submit_step))
}

async fn get_hosted_org(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<OrganizationHostedConfig>, (axum::http::StatusCode, String)> {
    let row = sqlx::query(
        "SELECT id, name, branding FROM organizations WHERE slug = $1 AND deleted_at IS NULL"
    )
    .bind(&slug)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(row) = row {
        let branding_val: Option<serde_json::Value> = row.try_get("branding").ok();
        let branding: BrandingSafeConfig = branding_val
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or(default_branding());

        Ok(Json(OrganizationHostedConfig {
            org_id: row.try_get("id").unwrap_or_default(),
            slug,
            display_name: row.try_get("name").unwrap_or_default(),
            branding,
            login_methods: LoginMethodsConfig {
                email_password: true,
                passkey: false,
                sso: false,
            },
        }))
    } else {
        Ok(Json(OrganizationHostedConfig {
            org_id: "generic".to_string(),
            slug: slug.clone(),
            display_name: "Organization".to_string(),
            branding: default_branding(),
            login_methods: LoginMethodsConfig { email_password: true, passkey: false, sso: false },
        }))
    }
}

fn default_branding() -> BrandingSafeConfig {
    BrandingSafeConfig {
        logo_url: None,
        primary_color: "#3B82F6".to_string(),
        background_color: "#FFFFFF".to_string(),
        text_color: "#1F2937".to_string(),
        font_family: "Inter".to_string(),
    }
}



async fn init_flow(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<InitFlowRequest>,
) -> Result<Json<InitFlowResponse>, (axum::http::StatusCode, String)> {
    tracing::warn!(
        org_id = %payload.org_id,
        "DEPRECATED: /api/hosted/auth/flows called — migrate to /api/auth/flow/init"
    );

    let flow_service = FlowStateService::new(state.db.clone());
    
    // Extract client IP from X-Forwarded-For or socket address
    let remote_ip = extract_client_ip(&headers, addr);
    tracing::info!("INIT_FLOW: payload org_id='{}' intent='{:?}'", payload.org_id, payload.intent);
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Verify org exists and fetch details
    let (org_exists, org_name, branding): (bool, String, serde_json::Value) = sqlx::query_as(
        "SELECT 
            EXISTS(SELECT 1 FROM organizations WHERE id = $1 AND deleted_at IS NULL),
            COALESCE(name, slug),
            COALESCE(branding, '{}'::jsonb)
         FROM organizations 
         WHERE id = $1"
    )
    .bind(&payload.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .unwrap_or((false, "Unknown".to_string(), serde_json::json!({})));

    if !org_exists {
        return Err((axum::http::StatusCode::NOT_FOUND, format!("Organization '{}' not found", payload.org_id)));
    }
    
    let branding_config: BrandingSafeConfig = serde_json::from_value(branding).unwrap_or_else(|_| default_branding());

    // Map frontend intent to internal security semantics
    
    // Map frontend intent to internal security semantics
    let mut flow_purpose = FlowPurpose::from(payload.intent);

    // EIAA: Enforce distinct AdminLogin purpose for Provider Authority
    if payload.org_id == "system" && flow_purpose == FlowPurpose::Authenticate {
        flow_purpose = FlowPurpose::AdminLogin;
    }
    
    // Determine first step based on flow purpose
    let (first_step, initial_step_name) = match flow_purpose {
        FlowPurpose::Authenticate | FlowPurpose::AdminLogin => {
            // Login: Start with email input
            (
                UiStep::Email {
                    label: "Email Address".to_string(),
                    required: true,
                },
                flow_steps::EMAIL.to_string(),
            )
        }
        FlowPurpose::EnrollIdentity => {
            // Signup: Start with credentials form
            (
                UiStep::Credentials {
                    fields: default_signup_fields(),
                },
                flow_steps::CREDENTIALS.to_string(),
            )
        }
        FlowPurpose::CredentialRecovery => {
            // EIAA: Credential recovery starts with email input (for identity verification)
            (
                UiStep::Email {
                    label: "Email Address".to_string(),
                    required: true,
                },
                flow_steps::IDENTIFY.to_string(),
            )
        }
        FlowPurpose::CreateTenant => {
            // Tenant Bootstrap: Start with credentials form including Org Name
            let mut fields = default_signup_fields();
            fields.push(CredentialField {
                name: "org_name".to_string(),
                label: "Organization Name".to_string(),
                required: true,
                format: None,
                min_length: Some(3),
            });
            (
                UiStep::Credentials {
                    fields,
                },
                flow_steps::CREDENTIALS.to_string(),
            )
        }
    };
    
    let flow = flow_service
        .create_flow(
            payload.org_id.clone(),
            payload.app_id.clone(),
            payload.redirect_uri,
            payload.state,
            Some(flow_purpose.as_str().to_string()),
            Some(initial_step_name),
            Some(remote_ip),
            Some(user_agent.clone()),
        )
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // EIAA: Initialize risk evaluation for this flow
    let eiaa_ctx = state.eiaa_flow_service.init_flow(
        flow.flow_id.clone(),
        payload.org_id.clone(),
        payload.app_id,
        remote_ip,
        user_agent,
        None, // device_input - can be populated from JS fingerprint
    )
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, "EIAA flow init failed, using defaults");
        // Don't fail the request, use safe defaults
        e
    })
    .ok();
    
    // Build EIAA response fields (defaults if risk evaluation failed)
    let (acceptable_caps, required_aal, risk_level) = match eiaa_ctx {
        Some(ctx) => (
            ctx.0.acceptable_capabilities.iter().map(|c| c.as_str().to_string()).collect(),
            ctx.0.required_aal.as_str().to_string(),
            format!("{:?}", ctx.0.risk_context.overall),
        ),
        None => (
            vec!["password".to_string(), "totp".to_string()],
            "AAL1".to_string(),
            "Low".to_string(),
        ),
    };

    tracing::info!(
        flow_id = %flow.flow_id,
        purpose = %flow_purpose.as_str(),
        required_aal = %required_aal,
        risk_level = %risk_level,
        "Initialized EIAA auth flow"
    );

    Ok(Json(InitFlowResponse {
        flow_id: flow.flow_id,
        ui_step: first_step,
        acceptable_capabilities: acceptable_caps,
        required_aal,
        risk_level,
        org_name,
        branding: branding_config,
    }))
}

/// Extract client IP from headers or socket
fn extract_client_ip(headers: &HeaderMap, addr: SocketAddr) -> IpAddr {
    // Try X-Forwarded-For first (for proxied requests)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return ip;
                }
            }
        }
    }
    
    // Try X-Real-IP
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(xri_str) = xri.to_str() {
            if let Ok(ip) = xri_str.trim().parse() {
                return ip;
            }
        }
    }
    
    // Fallback to socket address
    addr.ip()
}

/// Default signup fields (can be customized via admin console later)
fn default_signup_fields() -> Vec<CredentialField> {
    vec![
        CredentialField {
            name: flow_steps::EMAIL.to_string(),
            label: "Email Address".to_string(),
            required: true,
            format: Some("email".to_string()),
            min_length: None,
        },
        CredentialField {
            name: "password".to_string(),
            label: "Password".to_string(),
            required: true,
            format: Some("password".to_string()),
            min_length: Some(8),
        },
        CredentialField {
            name: "first_name".to_string(),
            label: "First Name".to_string(),
            required: true,
            format: None,
            min_length: None,
        },
        CredentialField {
            name: "last_name".to_string(),
            label: "Last Name".to_string(),
            required: true,
            format: None,
            min_length: None,
        },
    ]
}

async fn submit_step(
    State(state): State<AppState>,
    Path(flow_id): Path<String>,
    Json(payload): Json<SubmitStepRequest>,
) -> Result<Json<SubmitStepResponse>, (axum::http::StatusCode, String)> {
    tracing::warn!(
        flow_id = %flow_id,
        "DEPRECATED: /api/hosted/auth/flows/:id/submit called — migrate to /api/auth/flow/:id/submit"
    );

    let flow_service = FlowStateService::new(state.db.clone());

    let flow = flow_service
        .get_flow(&flow_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((axum::http::StatusCode::NOT_FOUND, "Flow not found".to_string()))?;

    if flow_service.check_attempts(&flow_id).await.unwrap_or(true) {
        return Err((axum::http::StatusCode::TOO_MANY_REQUESTS, "Too many attempts".to_string()));
    }

    tracing::debug!("SUBMIT_STEP: Loaded flow execution_state = {:?}", flow.execution_state);

    // EIAA: Check flow purpose for signup handling
    let is_signup = flow.flow_purpose.as_deref() == Some(flow_purposes::ENROLL_IDENTITY);
    let is_create_tenant = flow.flow_purpose.as_deref() == Some(flow_purposes::CREATE_TENANT);
    
    // Handle signup credentials step specially
    if (is_signup || is_create_tenant) && payload.step_type == flow_steps::CREDENTIALS {
        if is_create_tenant {
             return handle_create_tenant_credentials(&state, &flow_service, &flow, &flow_id, &payload.value).await;
        }
        return handle_signup_credentials(&state, &flow_service, &flow, &flow_id, &payload.value).await;
    }
    
    // Handle email verification for signup/tenant creation
    if (is_signup || is_create_tenant) && payload.step_type == flow_steps::EMAIL_VERIFICATION {
        if is_create_tenant {
            return handle_create_tenant_verification(&state, &flow_service, &flow, &flow_id, &payload.value).await;
        }
        return handle_email_verification(&state, &flow_service, &flow, &flow_id, &payload.value).await;
    }

    // EIAA: Check flow purpose for credential recovery handling
    let is_credential_recovery = flow.flow_purpose.as_deref() == Some(flow_purposes::CREDENTIAL_RECOVERY);
    
    // Handle credential recovery email step (identity verification)
    if is_credential_recovery && payload.step_type == flow_steps::EMAIL {
        return handle_recovery_email(&state, &flow_service, &flow, &flow_id, &payload.value).await;
    }
    
    // Handle credential recovery code verification
    if is_credential_recovery && payload.step_type == flow_steps::RESET_CODE {
        return handle_recovery_code_verification(&flow_service, &flow, &flow_id, &payload.value).await;
    }
    
    // Handle credential recovery new password (with capsule authorization)
    if is_credential_recovery && payload.step_type == flow_steps::NEW_PASSWORD {
        return handle_recovery_new_password(&state, &flow_service, &flow, &flow_id, &payload.value).await;
    }

    // EIAA: Determine correct policy action based on flow purpose
    let policy_action = if flow.flow_purpose.as_deref() == Some(flow_purposes::ADMIN_LOGIN) {
        "admin_login"
    } else {
        "auth:login"
    };

    // EIAA: Handle Hosted Login Steps (Credential Verification)
    let mut current_state = flow.execution_state.clone();
    
    if policy_action == "auth:login" || policy_action == "admin_login" {
        // 1. Identify User (Email Step)
        if payload.step_type == flow_steps::EMAIL {
            if let Some(email) = payload.value.as_str() {
                // Lookup user
                match state.user_service.get_user_by_email(email).await {
                    Ok(user) => {
                         tracing::info!("Identified user: {} for flow {}", user.id, flow_id);
                         
                         // EIAA: Verify user belongs to the target organization
                         // The flow.org_id may be a slug, so we need to resolve it to the actual org ID
                         let org = match state.organization_service.get_organization_by_slug(&flow.org_id).await {
                             Ok(o) => o,
                             Err(_) => {
                                 // Try as direct ID if not found as slug
                                 match state.organization_service.get_organization(&flow.org_id).await {
                                     Ok(o) => o,
                                     Err(e) => {
                                         tracing::error!("Organization not found: {} - {}", flow.org_id, e);
                                         return Err((axum::http::StatusCode::NOT_FOUND, "Organization not found".to_string()));
                                     }
                                 }
                             }
                         };
                         
                         let membership = state.organization_service
                             .get_membership(&org.id, &user.id)
                             .await;
                         
                         match membership {
                             Ok(Some(_)) => {
                                 // User is a member of this organization - allow login
                                 tracing::info!("User {} is member of org {} ({})", user.id, org.id, flow.org_id);
                                 current_state["user_id"] = serde_json::json!(user.id);
                                 current_state["subject_id"] = serde_json::json!(1); 
                                 current_state["email"] = serde_json::json!(email);

                                 // Persist state
                                 flow_service.update_state(&flow_id, current_state.clone(), flow_steps::EMAIL.to_string())
                                     .await
                                     .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                             }
                             Ok(None) => {
                                 // User exists but is NOT a member of this organization
                                 tracing::warn!(
                                     "User {} attempted to login to org {} ({}) but is not a member",
                                     user.id, org.id, flow.org_id
                                 );
                                 return Ok(Json(SubmitStepResponse::NextStep {
                                     flow_id: flow_id.clone(),
                                     ui_step: UiStep::Error {
                                         message: "You are not a member of this organization. Please login at your organization's login page.".to_string(),
                                     },
                                     achieved_aal: None,
                                     acceptable_capabilities: Vec::new(),
                                 }));
                             }
                             Err(e) => {
                                 tracing::error!("Failed to check org membership: {}", e);
                                 return Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify organization membership".to_string()));
                             }
                         }
                    },
                    Err(_) => {
                        tracing::warn!("User not found for email: {}", email);
                    }
                }
            }
        }
        
        // 2. Verify Password (Password Step)
        // 2. Verify Password (Password Step)
        if payload.step_type == flow_steps::PASSWORD {
            let mut password_verified = false;
            
            tracing::debug!("PASSWORD_STEP: current_state = {:?}", current_state);
            if let Some(email) = current_state.get("email").and_then(|v| v.as_str()) {
                tracing::debug!("PASSWORD_STEP: Found email = {}", email);
            } else {
                tracing::debug!("PASSWORD_STEP: No email found in current_state");
            }

            // Standard check if not bypassed
            if !password_verified {
                if let Some(user_id) = current_state.get("user_id").and_then(|v| v.as_str()) {
                     if let Some(password) = payload.value.as_str() {
                         if let Ok(true) = state.user_service.verify_user_password(user_id, password).await {
                             password_verified = true;
                         }
                     }
                }
            }

            if password_verified {
                 tracing::info!("Password verified for flow {}", flow_id);
                 // Add Password Factor (ID=4)
                 let mut factors = current_state.get("factors_satisfied")
                     .and_then(|v| v.as_array())
                     .cloned()
                     .unwrap_or_default();
                 if !factors.contains(&serde_json::json!(4)) {
                     factors.push(serde_json::json!(4));
                 }
                 current_state["factors_satisfied"] = serde_json::json!(factors);
                 current_state["authz_decision"] = serde_json::json!(1); // Allow entry (Evidence verified)
            } else {
                 // Invalid password
                 tracing::warn!("Invalid password for flow {}", flow_id);
                 return Ok(Json(SubmitStepResponse::NextStep {
                    flow_id: flow_id.to_string(),
                    ui_step: UiStep::Error { message: "Invalid credentials".to_string() },
                    achieved_aal: None,
                    acceptable_capabilities: vec![],
                 }));
            }
        }
    }


    // Build policy AST for login flow
    tracing::info!("SUBMIT_STEP: Building policy AST for org='{}' action='{}'", flow.org_id, policy_action);

    // Resolve capsule: Redis cache -> compile fallback -> write-back
    let cache = &state.capsule_cache;
    let capsule_action = policy_action;
    let tenant_id = &flow.org_id;

    let (capsule, from_cache, policy_version) = if let Some(cached) = cache.get(tenant_id, capsule_action).await {
        use prost::Message;
        match grpc_api::eiaa::runtime::CapsuleSigned::decode(cached.capsule_bytes.as_slice()) {
            Ok(c) => (c, true, cached.version),
            Err(_) => {
                tracing::warn!("Failed to decode cached capsule for {}, recompiling", capsule_action);
                let (ast, ver) = build_auth_policy_ast(tenant_id, policy_action, &state.db).await
                    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                let c = compile_policy(&ast, tenant_id, &state).await
                    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                (c, false, ver)
            }
        }
    } else {
        tracing::debug!("No capsule cached for action '{}', compiling fallback policy", capsule_action);
        let (ast, ver) = build_auth_policy_ast(tenant_id, policy_action, &state.db).await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let c = compile_policy(&ast, tenant_id, &state).await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        (c, false, ver)
    };

    if !from_cache {
        use prost::Message;
        let mut capsule_bytes = Vec::new();
        if capsule.encode(&mut capsule_bytes).is_ok() {
            let cached = crate::services::capsule_cache::CachedCapsule {
                tenant_id: tenant_id.to_string(),
                action: capsule_action.to_string(),
                version: policy_version,
                ast_hash: capsule.ast_hash_b64.clone(),
                wasm_hash: capsule.wasm_hash_b64.clone(),
                capsule_bytes,
                cached_at: chrono::Utc::now().timestamp(),
            };
            if let Err(e) = cache.set(&cached).await {
                tracing::warn!(tenant_id = %tenant_id, action = %capsule_action, error = %e, "Failed to write compiled capsule to cache");
            }
        }
    }

    // Build input JSON
    let input = build_capsule_input(&payload.step_type, &payload.value, &current_state);

    // Generate nonce for attestation
    let nonce = crate::services::audit_writer::AuditWriter::generate_nonce();

    // Execute via gRPC — GAP-1 FIX: use shared singleton client
    let result = state.runtime_client
        .execute_capsule(capsule.clone(), input, nonce.clone())
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Execution failed: {}", e)))?;

    // Parse result and store attestation
    parse_execution_result(result, flow, flow_service, flow_id, capsule, nonce, &state, current_state).await
}

/// EIAA-Compliant Signup Credentials Handler
/// 
/// V2 Fix: Ticket is created and stored in execution_state (backend-only).
/// Frontend never sees the ticketId.
async fn handle_signup_credentials(
    state: &AppState,
    flow_service: &FlowStateService,
    flow: &crate::services::flow_state_service::HostedAuthFlow,
    flow_id: &str,
    credentials: &serde_json::Value,
) -> Result<Json<SubmitStepResponse>, (axum::http::StatusCode, String)> {
    // Extract credentials
    let email = credentials.get("email")
        .and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Email required".to_string()))?;
    let password = credentials.get("password")
        .and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Password required".to_string()))?;
    let first_name = credentials.get("first_name").and_then(|v| v.as_str());
    let last_name = credentials.get("last_name").and_then(|v| v.as_str());
    
    // Hash password
    let password_hash = auth_core::hash_password(password)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Create signup ticket (stored in DB, not exposed to frontend)
    let ticket = state.verification_service
        .create_signup_ticket(
            email, &password_hash, first_name, last_name,
            None, // decision_ref: populated by EIAA capsule execution path (MEDIUM-EIAA-9)
        )
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Send verification email
    let code = ticket.verification_code.as_deref().unwrap_or_default();
    state.verification_service
        .send_verification_email(email, code)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Store ticketId in execution_state (EIAA: backend-only, not exposed)
    let mut new_state = flow.execution_state.clone();
    new_state["_signup_ticket_id"] = serde_json::json!(ticket.id);
    new_state["email"] = serde_json::json!(email);
    // Note: We don't mark "verifications_satisfied" yet because we just sent the email.
    
    // EIAA Strict: Host verifies evidence (creates ticket), then executes Policy.
    // We do NOT manually dictate the next step.
    
    flow_service.update_state(flow_id, new_state.clone(), flow_steps::EMAIL_VERIFICATION.to_string()) 
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    tracing::info!(
        flow_id = %flow_id,
        email = %email,
        "Signup credentials collected, verification email sent. Awaiting email verification."
    );
    
    // EIAA: After collecting credentials and sending verification email,
    // return the email verification step directly. 
    // The capsule will be executed AFTER verification is complete in handle_email_verification.
    Ok(Json(SubmitStepResponse::NextStep {
        flow_id: flow_id.to_string(),
        ui_step: UiStep::EmailVerification {
            label: "Enter the verification code sent to your email".to_string(),
            email: email.to_string(),
        },
        achieved_aal: Some("AAL0".to_string()),
        acceptable_capabilities: vec!["email_otp".to_string()],
    }))
}

/// Handle email verification for signup
async fn handle_email_verification(
    state: &AppState,
    flow_service: &FlowStateService,
    flow: &crate::services::flow_state_service::HostedAuthFlow,
    flow_id: &str,
    value: &serde_json::Value,
) -> Result<Json<SubmitStepResponse>, (axum::http::StatusCode, String)> {
    // Get code from value
    let code = value.as_str()
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Verification code required".to_string()))?;
    
    // Get ticketId from execution_state (EIAA: backend-only)
    let ticket_id = flow.execution_state.get("_signup_ticket_id")
        .and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Invalid flow state".to_string()))?;
    
    // Verify the code and complete signup
    let user = state.verification_service
        .verify_and_create_user(ticket_id, code)
        .await
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    
    // CRITICAL FIX: Create organization membership for the user
    // Resolve slug to org ID first
    let org = match state.organization_service.get_organization_by_slug(&flow.org_id).await {
        Ok(o) => o,
        Err(_) => {
            // Try as direct ID if not found as slug
            state.organization_service.get_organization(&flow.org_id).await
                .map_err(|e| {
                    tracing::error!("Organization not found for signup: {} - {}", flow.org_id, e);
                    (axum::http::StatusCode::NOT_FOUND, "Organization not found".to_string())
                })?
        }
    };
    
    // Add user as member of the organization
    state.organization_service.add_member(&org.id, &user.id, "member")
        .await
        .map_err(|e| {
            tracing::error!("Failed to create membership for new user: {}", e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to create organization membership".to_string())
        })?;
    
    tracing::info!(
        "Created membership for new user {} in org {} ({})",
        user.id, org.id, flow.org_id
    );
    
    // Generate decision ref for signup
    let decision_ref = shared_types::id_generator::generate_id("dec_signup");
    
    // Complete the flow
    flow_service.complete_flow(flow_id, decision_ref.clone())
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    tracing::info!(
        flow_id = %flow_id,
        user_id = %user.id,
        decision_ref = %decision_ref,
        "Signup completed via EIAA flow"
    );
    
    Ok(Json(SubmitStepResponse::Decision {
        status: "decision_ready".to_string(),
        decision_ref,
        achieved_aal: Some("AAL1".to_string()),
        token: None,
    }))
}

// === EIAA Credential Recovery Handlers ===

/// Handle email step for credential recovery.
/// 
/// EIAA Requirements:
/// - No user enumeration (always return same response)
/// - OTP stored as hash, not raw
/// - Time-bounded with attempt limits
async fn handle_recovery_email(
    state: &AppState,
    flow_service: &FlowStateService,
    flow: &crate::services::flow_state_service::HostedAuthFlow,
    flow_id: &str,
    value: &serde_json::Value,
) -> Result<Json<SubmitStepResponse>, (axum::http::StatusCode, String)> {
    let email = value.as_str()
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Email required".to_string()))?;
    
    // Lookup user via identities table (email is stored there, not in users)
    let user_row = sqlx::query(
        "SELECT u.id FROM users u 
         INNER JOIN identities i ON i.user_id = u.id 
         WHERE i.type = 'email' AND i.identifier = $1 AND u.deleted_at IS NULL"
    )
    .bind(email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Generate OTP regardless of whether user exists (prevent enumeration)
    let otp_code = generate_otp_code();
    let otp_hash = hash_otp(&otp_code);
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
    
    // Store in flow state (backend-only)
    let mut new_state = flow.execution_state.clone();
    new_state["_recovery"] = serde_json::json!({
        "email": email,
        "code_hash": otp_hash,
        "expires_at": expires_at.to_rfc3339(),
        "attempts": 0,
        "verified": false,
        "user_id": user_row.as_ref().map(|r| r.try_get::<String, _>("id").ok()).flatten()
    });
    
    flow_service.update_state(flow_id, new_state, flow_steps::RESET_CODE.to_string())
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Only send email if user exists (but always return same response)
    if user_row.is_some() {
        if let Err(e) = state.email_service.send_verification_code(email, &otp_code).await {
            tracing::error!(error = %e, "Failed to send recovery email");
            // Don't fail the flow - continue with same response
        }
    }
    
    tracing::info!(
        flow_id = %flow_id,
        email = %email,
        user_exists = user_row.is_some(),
        "Credential recovery initiated"
    );
    
    // EIAA: Always return same response (no enumeration)
    Ok(Json(SubmitStepResponse::NextStep {
        flow_id: flow_id.to_string(),
        ui_step: UiStep::ResetCodeVerification {
            label: "Enter the verification code sent to your email".to_string(),
            email: email.to_string(),
        },
        achieved_aal: Some("AAL0".to_string()),
        acceptable_capabilities: vec!["email_otp".to_string()],
    }))
}

/// Handle code verification step for credential recovery.
/// 
/// EIAA Requirements:
/// - Constant-time comparison
/// - Attempt limiting (max 5)
/// - Time-bound expiry check
async fn handle_recovery_code_verification(
    flow_service: &FlowStateService,
    flow: &crate::services::flow_state_service::HostedAuthFlow,
    flow_id: &str,
    value: &serde_json::Value,
) -> Result<Json<SubmitStepResponse>, (axum::http::StatusCode, String)> {
    let submitted_code = value.as_str()
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Code required".to_string()))?;
    
    // Get recovery state
    let recovery = flow.execution_state.get("_recovery")
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Invalid flow state".to_string()))?;
    
    let stored_hash = recovery.get("code_hash")
        .and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Invalid flow state".to_string()))?;
    
    let expires_at = recovery.get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Invalid flow state".to_string()))?;
    
    let attempts: i64 = recovery.get("attempts")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    
    // Check expiry
    if chrono::Utc::now() > expires_at {
        return Err((axum::http::StatusCode::BAD_REQUEST, "Verification code expired".to_string()));
    }
    
    // Check attempts (max 5)
    if attempts >= 5 {
        return Err((axum::http::StatusCode::TOO_MANY_REQUESTS, "Too many verification attempts".to_string()));
    }
    
    // Verify code (constant-time comparison)
    let submitted_hash = hash_otp(submitted_code);
    let is_valid = constant_time_compare(&submitted_hash, stored_hash);
    
    // Update attempts
    let mut new_state = flow.execution_state.clone();
    if let Some(rec) = new_state.get_mut("_recovery") {
        rec["attempts"] = serde_json::json!(attempts + 1);
        if is_valid {
            rec["verified"] = serde_json::json!(true);
        }
    }
    
    if !is_valid {
        flow_service.update_state(flow_id, new_state, flow_steps::RESET_CODE.to_string())
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        return Err((axum::http::StatusCode::BAD_REQUEST, "Invalid verification code".to_string()));
    }
    
    flow_service.update_state(flow_id, new_state, flow_steps::NEW_PASSWORD.to_string())
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    tracing::info!(
        flow_id = %flow_id,
        "Recovery code verified, proceeding to password reset"
    );
    
    Ok(Json(SubmitStepResponse::NextStep {
        flow_id: flow_id.to_string(),
        ui_step: UiStep::NewPassword {
            label: "Create a new password".to_string(),
            hint: Some("Must be at least 8 characters".to_string()),
        },
        achieved_aal: Some("AAL1".to_string()),
        acceptable_capabilities: vec!["password".to_string()],
    }))
}

/// Handle new password step for credential recovery.
/// 
/// EIAA Requirements:
/// - MUST execute ResetPasswordCapsule before mutation
/// - Mark risk signal (reset_recent)
/// - Produce decision artifact
async fn handle_recovery_new_password(
    state: &AppState,
    flow_service: &FlowStateService,
    flow: &crate::services::flow_state_service::HostedAuthFlow,
    flow_id: &str,
    value: &serde_json::Value,
) -> Result<Json<SubmitStepResponse>, (axum::http::StatusCode, String)> {
    let new_password = value.as_str()
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Password required".to_string()))?;
    
    // Validate password policy (syntax only - capsule will authorize)
    if new_password.len() < 8 {
        return Err((axum::http::StatusCode::BAD_REQUEST, "Password must be at least 8 characters".to_string()));
    }
    
    // Get recovery state and verify code was validated
    let recovery = flow.execution_state.get("_recovery")
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Invalid flow state".to_string()))?;
    
    let verified = recovery.get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    
    if !verified {
        return Err((axum::http::StatusCode::BAD_REQUEST, "Code verification required".to_string()));
    }
    
    let user_id = recovery.get("user_id")
        .and_then(|v| v.as_str());
    
    // If no user_id, the email didn't exist - silently complete (no enumeration)
    if user_id.is_none() {
        let decision_ref = shared_types::id_generator::generate_id("dec_recovery");
        flow_service.complete_flow(flow_id, decision_ref.clone())
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
        return Ok(Json(SubmitStepResponse::Decision {
            status: "decision_ready".to_string(),
            decision_ref,
            achieved_aal: Some("AAL1".to_string()),
            token: None,
        }));
    }
    let user_id = user_id.unwrap();
    
    // EIAA: Build and execute ResetPasswordCapsule
    let capsule_input = serde_json::json!({
        // RuntimeContext (all required fields)
        "subject_id": 1,
        "risk_score": 0,
        "factors_satisfied": [],
        "verifications_satisfied": ["email"],  // Email was verified via OTP code
        "authz_decision": 1,

        "reset_code_verified": true,
        "password": {
            "valid": true,
            "length": new_password.len()
        },
        "user_id": user_id,
        "flow_id": flow_id
    });
    
    // Resolve capsule: cache -> compile
    let cache = &state.capsule_cache;
    let tenant_id = &flow.org_id;
    let capsule_action = "auth:reset_password";
    
    let (capsule, from_cache) = if let Some(cached) = cache.get(tenant_id, capsule_action).await {
        use prost::Message;
        match grpc_api::eiaa::runtime::CapsuleSigned::decode(cached.capsule_bytes.as_slice()) {
            Ok(c) => (c, true),
            Err(_) => {
                let ast = build_reset_password_policy();
                let c = compile_policy(&ast, tenant_id, state).await
                    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Capsule compile failed: {}", e)))?;
                (c, false)
            }
        }
    } else {
        let ast = build_reset_password_policy();
        let c = compile_policy(&ast, tenant_id, state).await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Capsule compile failed: {}", e)))?;
        (c, false)
    };

    if !from_cache {
        use prost::Message;
        let mut capsule_bytes = Vec::new();
        if capsule.encode(&mut capsule_bytes).is_ok() {
            let cached = crate::services::capsule_cache::CachedCapsule {
                tenant_id: tenant_id.to_string(),
                action: capsule_action.to_string(),
                version: 0,
                ast_hash: capsule.ast_hash_b64.clone(),
                wasm_hash: capsule.wasm_hash_b64.clone(),
                capsule_bytes,
                cached_at: chrono::Utc::now().timestamp(),
            };
            let _ = cache.set(&cached).await;
        }
    }
    
    // Generate nonce
    let nonce = crate::services::audit_writer::AuditWriter::generate_nonce();
    
    // Execute via gRPC
    let result = execute_capsule_with_client(state, capsule.clone(), capsule_input.to_string(), nonce.clone()).await;
    
    match result {
        Ok(exec_result) => {
            if let Some(decision) = exec_result.decision {
                if decision.allow {
                    // EIAA: Capsule allowed - now perform password update
                    let password_hash = auth_core::hash_password(new_password)
                        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                    
                    // Update password in DB (passwords table, not users)
                    sqlx::query("UPDATE passwords SET password_hash = $1 WHERE user_id = $2")
                        .bind(&password_hash)
                        .bind(user_id)
                        .execute(&state.db)
                        .await
                        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                    
                    // EIAA: Mark risk signal (reset_recent) - stored for step-up on next login
                    sqlx::query(
                        "INSERT INTO user_risk_signals (user_id, signal_type, created_at, expires_at) VALUES ($1, 'reset_recent', NOW(), NOW() + INTERVAL '24 hours') ON CONFLICT (user_id, signal_type) DO UPDATE SET created_at = NOW(), expires_at = NOW() + INTERVAL '24 hours'"
                    )
                    .bind(user_id)
                    .execute(&state.db)
                    .await
                    .ok(); // Don't fail if risk table doesn't exist
                    
                    // Generate decision ref
                    let decision_ref = shared_types::id_generator::generate_id("dec_recovery");
                    
                    // Store attestation if available
                    if let Some(attestation) = exec_result.attestation {
                        let _ = store_recovery_attestation(
                            &state.audit_writer,
                            &decision_ref,
                            &capsule,
                            &decision,
                            attestation,
                            &nonce,
                            &flow.org_id,
                            user_id,
                        );
                    }
                    
                    // Complete flow
                    flow_service.complete_flow(flow_id, decision_ref.clone())
                        .await
                        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                    
                    tracing::info!(
                        flow_id = %flow_id,
                        user_id = %user_id,
                        decision_ref = %decision_ref,
                        "Password reset completed via EIAA capsule"
                    );
                    
                    return Ok(Json(SubmitStepResponse::Decision {
                        status: "decision_ready".to_string(),
                        decision_ref,
                        achieved_aal: Some("AAL1".to_string()),
                        token: None,
                    }));
                } else {
                    // Capsule denied
                    return Err((axum::http::StatusCode::FORBIDDEN, format!("Reset denied: {}", decision.reason)));
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Capsule execution failed");
            return Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Authorization failed".to_string()));
        }
    }
    
    Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error".to_string()))
}

/// Build the default ResetPassword policy AST
fn build_reset_password_policy() -> Program {
    use capsule_compiler::ast::{Program, Step, IdentitySource};
    
    Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            // R10: VerifyIdentity must be first
            Step::VerifyIdentity { source: IdentitySource::Primary },
            // R17: AuthorizeAction required
            Step::AuthorizeAction { 
                action: "auth:reset_password".to_string(), 
                resource: "credential".to_string() 
            },
            // Terminal node
            Step::Allow(true),
        ],
    }
}

/// Execute capsule via gRPC client — GAP-1 FIX: use shared singleton client
async fn execute_capsule_with_client(
    state: &AppState,
    capsule: CapsuleSigned,
    input: String,
    nonce: String,
) -> Result<grpc_api::eiaa::runtime::ExecuteResponse, String> {
    state.runtime_client
        .execute_capsule(capsule, input, nonce)
        .await
        .map_err(|e| e.to_string())
}

/// Store attestation for password recovery
fn store_recovery_attestation(
    audit_writer: &crate::services::audit_writer::AuditWriter,
    decision_ref: &str,
    capsule: &CapsuleSigned,
    decision: &grpc_api::eiaa::runtime::Decision,
    attestation: grpc_api::eiaa::runtime::Attestation,
    nonce: &str,
    tenant_id: &str,
    user_id: &str,
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(capsule.capsule_hash_b64.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(b"credential_recovery");
    let input_digest = URL_SAFE_NO_PAD.encode(hasher.finalize());

    let attestation_body = attestation.body.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Attestation body missing"))?;

    let attestation_hash_b64 = {
        let body_json = serde_json::to_vec(attestation_body)?;
        let mut hasher = Sha256::new();
        hasher.update(&body_json);
        Some(URL_SAFE_NO_PAD.encode(hasher.finalize()))
    };

    audit_writer.record(crate::services::audit_writer::AuditRecord {
        decision_ref: decision_ref.to_string(),
        capsule_hash_b64: capsule.capsule_hash_b64.clone(),
        capsule_version: "credential_recovery_v1".to_string(),
        action: "credential_recovery".to_string(),
        tenant_id: tenant_id.to_string(),
        input_digest,
        input_context: None,
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

    Ok(())
}

// === Utility functions for credential recovery ===

/// Generate 6-digit OTP code
fn generate_otp_code() -> String {
    use rand::Rng;
    let code: u32 = rand::thread_rng().gen_range(100000..999999);
    code.to_string()
}

/// Hash OTP for storage (using SHA256)
fn hash_otp(code: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time string comparison
fn constant_time_compare(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

// --- Policy AST Construction ---

async fn build_auth_policy_ast(org_id: &str, action: &str, db: &sqlx::PgPool) -> anyhow::Result<(Program, i32)> {
    // Try to fetch custom policy
    let mut policy_row: Option<(i32, serde_json::Value)> = sqlx::query_as(
        "SELECT version, spec FROM eiaa_policies WHERE tenant_id = $1 AND action = $2 ORDER BY version DESC LIMIT 1"
    )
    .bind(org_id)
    .bind(action)
    .fetch_optional(db)
    .await?;
    
    // Fallback: If no custom policy, try to find system default for this action
    if policy_row.is_none() && action == "auth:login" {
        policy_row = sqlx::query_as(
            "SELECT version, spec FROM eiaa_policies WHERE tenant_id = 'system' AND action = 'auth:login_default' ORDER BY version DESC LIMIT 1"
        )
        .fetch_optional(db)
        .await?;
    }

    if let Some((version, json)) = policy_row {
        // Try to parse as AST
        if let Ok(program) = serde_json::from_value::<Program>(json) {
            return Ok((program, version));
        }
    }

    // Default policy: Use PolicyCompiler with default config (requires email + password)
    // This ensures proper password verification is enforced
    let config = capsule_compiler::policy_compiler::LoginMethodsConfig::default();
    Ok((capsule_compiler::policy_compiler::PolicyCompiler::compile_auth_policy(&config), 0))
}

async fn compile_policy(policy: &Program, tenant_id: &str, state: &AppState) -> anyhow::Result<CapsuleSigned> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
    
    let compiled = capsule_compiler::compile(
        policy.clone(),
        tenant_id.to_string(),
        "auth:login".to_string(),
        now,
        now + 86400, // 24 hours
        &state.ks,
        &state.compiler_kid,
    )?;

    // Convert to gRPC type
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
        wasm_hash_b64: compiled.wasm_hash.clone(),
        lowering_version: compiled.lowering_version,
        wasm_bytes: compiled.wasm_bytes,
    })
}

fn build_capsule_input(step_type: &str, value: &serde_json::Value, current_state: &serde_json::Value) -> String {
    let verifications_satisfied = if let Some(vs) = current_state.get("verifications_satisfied").and_then(|v| v.as_array()) {
        vs.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
    } else {
        Vec::with_capacity(0)
    };

    let mut input = serde_json::json!({
        // RuntimeContext required fields
        "subject_id": 0, // Default to anonymous
        "risk_score": 0,
        "factors_satisfied": [],
        "verifications_satisfied": verifications_satisfied,
        "authz_decision": 0, // Default to deny/unknown
        
        "step": step_type,
        "value": value,
    });

    if let Some(obj) = current_state.as_object() {
        for (k, v) in obj {
            input[k] = v.clone();
        }
    }
    
    // EIAA: Map user_id (string) to subject_id (i64) if present
    if let Some(uid_val) = current_state.get("user_id") {
       if let Some(uid_str) = uid_val.as_str() {
           if let Ok(uid_i64) = uid_str.parse::<i64>() {
               input["subject_id"] = serde_json::Value::Number(serde_json::Number::from(uid_i64));
           } else {
               // Fallback if not I64 parsable (e.g. UUID)
               // For now, force 1 if we have a user_id
               input["subject_id"] = serde_json::json!(1);
           }
       }
    }
    
    // Explicitly check subject_id from state if user_id mapping failed
    if let Some(sid) = current_state.get("subject_id") {
        input["subject_id"] = sid.clone();
    }

    let json_str = serde_json::to_string(&input).unwrap();
    tracing::debug!("Capsule Input: {}", json_str);
    json_str
}





async fn parse_execution_result(
    result: grpc_api::eiaa::runtime::ExecuteResponse,
    flow: crate::services::flow_state_service::HostedAuthFlow,
    flow_service: FlowStateService,
    flow_id: String,
    capsule: CapsuleSigned,
    nonce: String,
    state: &AppState,
    current_state: serde_json::Value,
) -> Result<Json<SubmitStepResponse>, (axum::http::StatusCode, String)> {
    let decision = result.decision.ok_or((axum::http::StatusCode::INTERNAL_SERVER_ERROR, "No decision".to_string()))?;

    // EIAA: Check for NeedInput via reason string (since proto uses bool allow + string reason)
    let reason = decision.reason.clone();
    if !decision.allow && reason == "identity" {
        // Need explicit identity input
        // Update state to track we are asking for identity
        let mut new_state = flow.execution_state.clone();
        new_state["step"] = serde_json::Value::String(flow_steps::IDENTIFY.to_string());
        
        flow_service.update_state(&flow_id, new_state, flow_steps::IDENTIFY.to_string())
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // Return UiStep::Email (or Identifier)
        return Ok(Json(SubmitStepResponse::NextStep {
            flow_id,
            ui_step: UiStep::Email {
                label: "Sign in".to_string(),
                required: true,
            },
            achieved_aal: Some("AAL0".to_string()),
            acceptable_capabilities: vec!["email".to_string()],
        }));
    }

    if decision.allow {
        // Success - generate decision ref
        let decision_ref = shared_types::id_generator::generate_id("dec_hosted");
        
        // Store attestation in eiaa_executions table
        if let Some(attestation) = result.attestation {
            if let Err(e) = state.audit_writer.store_attestation(
                &decision_ref,
                &capsule,
                &decision,
                attestation,
                &nonce,
                "hosted_login",
                "hosted_login_v1",
                &flow.org_id,
                None,
            ) {
                tracing::error!("Failed to store attestation: {}", e);
                // Don't fail the flow, but log the error
            }
        }

        // Update state to COMPLETE before finishing
        let _ = flow_service.update_state(&flow_id, serde_json::json!({"completed": true}), flow_steps::COMPLETE.to_string()).await;
        
        flow_service.complete_flow(&flow_id, decision_ref.clone())
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        // R-4.2 FIX: Write session row to DB before issuing JWT.
        //
        // CRITICAL BUG (pre-fix): A session_id was generated and embedded in the JWT
        // `sid` claim, but NO row was ever written to the `sessions` table. Every
        // subsequent request using this JWT would fail the auth middleware's
        // `SELECT ... FROM sessions WHERE id = $1` check → 401 Unauthorized.
        //
        // Fix: call create_session() which writes the row with decision_ref, then
        // use the returned session_id in the JWT.
        let token = if let Some(user_id_val) = current_state.get("user_id") {
            if let Some(user_id) = user_id_val.as_str() {
                // Determine assurance level from flow state
                let assurance_level = if current_state.get("mfa_verified")
                    .and_then(|v| v.as_bool()).unwrap_or(false) { "aal2" } else { "aal1" };

                // Build verified capabilities list from flow state
                let mut caps = vec!["password".to_string()];
                if assurance_level == "aal2" {
                    caps.push("totp".to_string());
                }
                let verified_caps = serde_json::to_value(&caps).unwrap_or_default();

                // R-4.2: Write session row with decision_ref before issuing JWT
                match state.user_service.create_session(CreateSessionParams {
                    user_id,
                    tenant_id: &flow.org_id,
                    decision_ref: Some(&decision_ref),
                    assurance_level,
                    verified_capabilities: verified_caps,
                    is_provisional: false,
                    session_type: auth_core::jwt::session_types::END_USER,
                    device_id: None,
                    expires_in_secs: Some(3600),
                }).await {
                    Ok(session) => {
                        // Generate JWT using the persisted session_id
                        match state.jwt_service.generate_token(
                            user_id,
                            &session.session_id,
                            &flow.org_id,
                            auth_core::jwt::session_types::END_USER,
                        ) {
                            Ok(t) => Some(t),
                            Err(e) => {
                                tracing::error!("Failed to generate token for flow {}: {}", flow_id, e);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to create session for flow {}: {}", flow_id, e);
                        None
                    }
                }
            } else { None }
        } else { None };

        Ok(Json(SubmitStepResponse::Decision {
            status: "decision_ready".to_string(),
            decision_ref,
            achieved_aal: Some("AAL1".to_string()),
            token,
        }))
    } else {
        // Parse reason for next step
        let reason = decision.reason;
        
        if reason.contains("NEED_PASSWORD") || reason.contains("password") {
            // EIAA: Use current_state which has email/user_id from email step, not stale flow.execution_state
            let mut new_state = current_state.clone();
            new_state["authenticated_email"] = serde_json::Value::Bool(true);
            
            flow_service.update_state(&flow_id, new_state, flow_steps::PASSWORD.to_string())
                .await
                .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            Ok(Json(SubmitStepResponse::NextStep {
                flow_id,
                ui_step: UiStep::Password {
                    label: "Password".to_string(),
                },
                achieved_aal: Some("AAL0".to_string()),
                acceptable_capabilities: vec!["password".to_string()],
            }))
        } else if reason.contains("NEED_OTP") || reason.contains(flow_steps::OTP) || reason.contains("MFA") {
            flow_service.update_state(&flow_id, current_state.clone(), flow_steps::MFA.to_string())
                .await
                .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            Ok(Json(SubmitStepResponse::NextStep {
                flow_id,
                ui_step: UiStep::Otp {
                    label: "Enter verification code".to_string(),
                },
                achieved_aal: Some("AAL1".to_string()),
                acceptable_capabilities: vec!["totp".to_string()],
            }))
        } else if reason.contains("NEED_VERIFICATION") || reason.contains(flow_steps::EMAIL_VERIFICATION) {
            // EIAA: Policy explicitly requires verification step
            flow_service.update_state(&flow_id, current_state.clone(), flow_steps::EMAIL_VERIFICATION.to_string())
                .await
                .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            Ok(Json(SubmitStepResponse::NextStep {
                flow_id,
                ui_step: UiStep::EmailVerification {
                    label: "Enter verification code".to_string(),
                    email: "".to_string(), // Frontend reads from state/local
                },
                achieved_aal: Some("AAL0".to_string()),
                acceptable_capabilities: vec!["email_otp".to_string()],
            }))
        } else {
            // Update state to ERROR before returning
            let _ = flow_service.update_state(&flow_id, current_state.clone(), flow_steps::ERROR.to_string()).await;
            
            // Ensure we have a meaningful error message
            let error_message = if reason.is_empty() {
                "Authentication failed. Please try again.".to_string()
            } else {
                reason.clone()
            };
            
            Ok(Json(SubmitStepResponse::NextStep {
                flow_id,
                ui_step: UiStep::Error {
                    message: error_message,
                },
                achieved_aal: None,
                acceptable_capabilities: vec![],
            }))
        }
    }
}



// === EIAA Create Tenant Handlers ===

async fn handle_create_tenant_credentials(
    state: &AppState,
    flow_service: &FlowStateService,
    flow: &crate::services::flow_state_service::HostedAuthFlow,
    flow_id: &str,
    credentials: &serde_json::Value,
) -> Result<Json<SubmitStepResponse>, (axum::http::StatusCode, String)> {
    // Extract credentials
    let email = credentials.get("email")
        .and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Email required".to_string()))?;
    let password = credentials.get("password")
        .and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Password required".to_string()))?;
    let org_name = credentials.get("org_name")
        .and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Organization Name required".to_string()))?;
    let first_name = credentials.get("first_name").and_then(|v| v.as_str());
    let last_name = credentials.get("last_name").and_then(|v| v.as_str());
    
    // Hash password
    let password_hash = auth_core::hash_password(password)
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Create signup ticket (reusing verification service logic)
    let ticket = state.verification_service
        .create_signup_ticket(
            email, &password_hash, first_name, last_name,
            None, // decision_ref: populated by EIAA capsule execution path (MEDIUM-EIAA-9)
        )
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Send verification email
    let code = ticket.verification_code.as_deref().unwrap_or_default();
    state.verification_service
        .send_verification_email(email, code)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Store ticketId AND org_name in execution_state
    let mut new_state = flow.execution_state.clone();
    new_state["_signup_ticket_id"] = serde_json::json!(ticket.id);
    new_state["email"] = serde_json::json!(email);
    new_state["_org_name"] = serde_json::json!(org_name); // Store proposed org name
    
    flow_service.update_state(flow_id, new_state, flow_steps::EMAIL_VERIFICATION.to_string())
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    tracing::info!(
        flow_id = %flow_id,
        email = %email,
        org_name = %org_name,
        "Tenant creation initiated, verification email sent"
    );
    
    Ok(Json(SubmitStepResponse::NextStep {
        flow_id: flow_id.to_string(),
        ui_step: UiStep::EmailVerification {
            label: "Enter verification code".to_string(),
            email: email.to_string(),
        },
        achieved_aal: Some("AAL0".to_string()),
        acceptable_capabilities: vec!["email_otp".to_string()],
    }))
}

async fn handle_create_tenant_verification(
    state: &AppState,
    flow_service: &FlowStateService,
    flow: &crate::services::flow_state_service::HostedAuthFlow,
    flow_id: &str,
    value: &serde_json::Value,
) -> Result<Json<SubmitStepResponse>, (axum::http::StatusCode, String)> {
    // 1. Verify Code
    let code = value.as_str()
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Verification code required".to_string()))?;
    
    let ticket_id = flow.execution_state.get("_signup_ticket_id")
        .and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Invalid flow state".to_string()))?;
        
    let org_name = flow.execution_state.get("_org_name")
        .and_then(|v| v.as_str())
        .ok_or((axum::http::StatusCode::BAD_REQUEST, "Invalid flow state: missing org name".to_string()))?;

    // Verify code
    let is_valid = state.verification_service.verify_signup_code(ticket_id, code)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !is_valid {
        return Err((axum::http::StatusCode::BAD_REQUEST, "Invalid verification code".to_string()));
    }

    // Get ticket data
    let ticket = state.verification_service.get_signup_ticket(ticket_id)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // Extract required fields
    let email = ticket.email.as_deref().unwrap_or("");
    let password_hash = ticket.password_hash.as_deref().unwrap_or("");


    // 2. Execute Atomic Transaction (Tenant + User + Link)
    let mut tx = state.db.begin().await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Create Organization
    let new_org_id = shared_types::id_generator::generate_id("org");
    let new_slug = slug::slugify(org_name);
    
    // Ensure slug uniqueness (simple suffix if needed could be added here, but relying on DB constraint for now)
    sqlx::query(
        "INSERT INTO organizations (id, slug, name) VALUES ($1, $2, $3)"
    )
    .bind(&new_org_id)
    .bind(&new_slug)
    .bind(org_name)
    .execute(&mut *tx)
    .await
    .map_err(|e| (axum::http::StatusCode::CONFLICT, format!("Organization creation failed (slug collision?): {}", e)))?;

    // Create User (Admin)
    let user_id = shared_types::id_generator::generate_id("usr");
    // Ticket stores password hash already
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, organization_id, first_name, last_name, email_verified) 
         VALUES ($1, $2, $3, $4, $5, $6, TRUE)"
    )
    .bind(&user_id)
    .bind(email)
    .bind(password_hash)
    .bind(&new_org_id)
    .bind(ticket.first_name.as_ref())
    .bind(ticket.last_name.as_ref())
    .execute(&mut *tx)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Create Membership (OWNER)
    sqlx::query(
        "INSERT INTO memberships (id, user_id, organization_id, role) VALUES ($1, $2, $3, 'OWNER')"
    )
    .bind(shared_types::id_generator::generate_id("mem"))
    .bind(&user_id)
    .bind(&new_org_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tx.commit().await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 3. Complete Flow & Return Decision 
    
    let decision_ref = shared_types::id_generator::generate_id("dec_tenant_bootstrap");
    
    flow_service.complete_flow(flow_id, decision_ref.clone())
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
    tracing::info!(
        flow_id = %flow_id,
        new_org_id = %new_org_id,
        user_id = %user_id,
        "Tenant bootstrap completed successfully"
    );

    Ok(Json(SubmitStepResponse::Decision {
        status: "decision_ready".to_string(),
        decision_ref,
        achieved_aal: Some("AAL1".to_string()),
        token: None,
    }))
}
