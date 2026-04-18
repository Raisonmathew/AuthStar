use crate::services::audit_event_service::{event_types, RecordEventParams};
use crate::services::StoreAttestationParams;
use crate::state::AppState;
use axum::{
    extract::State,
    http::{header, HeaderMap},
    routing::post,
    Json, Router,
};
// GAP-1 FIX: Use SharedRuntimeClient from AppState instead of per-request connect
use capsule_compiler::ast::{IdentitySource, Program, Step};
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};
use risk_engine::{
    rules::{derive_required_aal, AalRequirement},
    NetworkInput, RequestContext as RiskRequestContext, SubjectContext,
};
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

pub fn router() -> Router<AppState> {
    Router::new().route("/login", post(login))
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct StepUpRequirement {
    /// Required Authenticator Assurance Level (NIST SP 800-63B): 2 or 3
    required_aal: i16,
    /// Acceptable factor types for satisfying the step-up
    acceptable_factors: Vec<&'static str>,
    /// True if the issued token is provisional (no access until step-up satisfied)
    provisional: bool,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user: identity_engine::models::UserResponse,
    organization_id: String,
    #[serde(rename = "decisionRef")]
    decision_ref: String, // EIAA audit reference
    /// Step-up requirement — admin sessions always start provisional at AAL1
    /// and must satisfy this requirement before any privileged route is reachable.
    requirement: StepUpRequirement,
}

/// EIAA-Compliant Admin Login
///
/// Executes an admin login capsule to authenticate the administrator.
/// Steps:
/// 1. Authenticate user credentials
/// 2. Compile admin login capsule
/// 3. Execute capsule to verify admin authorization
/// 4. Store decision artifact
/// 5. Create admin session with decision_ref
/// 6. Issue EIAA-compliant admin JWT
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // 0. Extract network context for risk evaluation
    let ip_str = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("127.0.0.1")
        .trim();
    let remote_ip: std::net::IpAddr = ip_str
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // 1. Authenticate against DB (scoped to system org for admin login)
    let user = state
        .user_service
        .get_user_by_email_in_org(&req.email, "system")
        .await
        .map_err(|_| AppError::Unauthorized("Invalid credentials".into()))?;

    let valid = state
        .user_service
        .verify_user_password(&user.id, &req.password)
        .await?;
    if !valid {
        state
            .audit_event_service
            .record(RecordEventParams {
                tenant_id: "platform".into(),
                event_type: event_types::ADMIN_LOGIN_FAILED,
                actor_id: Some(user.id.clone()),
                actor_email: Some(req.email.clone()),
                target_type: Some("user"),
                target_id: Some(user.id.clone()),
                ip_address: Some(remote_ip),
                user_agent: Some(user_agent.clone()),
                metadata: serde_json::json!({"reason": "invalid_password"}),
            })
            .await;
        return Err(AppError::Unauthorized("Invalid credentials".into()));
    }

    // 2 & 3. Resolve capsule: Redis cache -> compile fallback -> write-back
    // Admin login is typically for the "platform" tenant or specific system tenant
    let tenant_id = "platform".to_string();
    let cache = &state.capsule_cache;
    let capsule_action = "auth:admin_login";

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
                let (ast, ver) = build_admin_login_policy_ast(&tenant_id, &state.db).await?;
                let c = compile_admin_policy(&ast, &tenant_id, &state)
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
        let (ast, ver) = build_admin_login_policy_ast(&tenant_id, &state.db).await?;
        let c = compile_admin_policy(&ast, &tenant_id, &state)
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
            };
            let _ = cache.set(&cached).await;
        }
    }

    // 4. Evaluate risk via Risk Engine (admin login is a high-value target)
    let risk_request = RiskRequestContext {
        network: NetworkInput {
            remote_ip,
            x_forwarded_for: None,
            user_agent: user_agent.clone(),
            accept_language: headers
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            timestamp: chrono::Utc::now(),
        },
        device: None,
    };
    let subject_ctx = SubjectContext {
        subject_id: user.id.clone(),
        org_id: tenant_id.clone(),
    };
    let risk_eval = state
        .risk_engine
        .evaluate(&risk_request, Some(&subject_ctx), Some("admin_login"), true)
        .await;
    let risk_score = risk_eval.risk.total_score();

    tracing::debug!(
        user_id = %user.id,
        risk_score = %risk_score,
        risk_level = ?risk_eval.risk.overall,
        "Admin login risk evaluation"
    );

    // Block admin login if risk is elevated (stricter threshold than user login)
    if risk_score > 60.0 {
        state
            .audit_event_service
            .record(RecordEventParams {
                tenant_id: tenant_id.clone(),
                event_type: event_types::ADMIN_LOGIN_FAILED,
                actor_id: Some(user.id.clone()),
                actor_email: Some(req.email.clone()),
                target_type: Some("user"),
                target_id: Some(user.id.clone()),
                ip_address: Some(remote_ip),
                user_agent: Some(user_agent.clone()),
                metadata: serde_json::json!({
                    "reason": "risk_threshold_exceeded",
                    "risk_score": risk_score,
                    "risk_level": format!("{:?}", risk_eval.risk.overall),
                }),
            })
            .await;
        return Err(AppError::Forbidden(
            "Admin login denied due to elevated risk".into(),
        ));
    }

    // 4.5. Build input context with real risk score
    let input = serde_json::json!({
        // RuntimeContext required fields
        "subject_id": 1, // Placeholder until ID is integer mapped
        "risk_score": risk_score,
        "factors_satisfied": [],
        "authz_decision": 1,

        "user_id": user.id,
        "email": req.email,
        "password_verified": true,
        "auth_method": "password",
        "tenant_id": tenant_id,
        "session_type": "admin",
    });
    let input_json = serde_json::to_string(&input)?;

    // 5. Execute via gRPC — GAP-1 FIX: use shared singleton client
    let nonce = crate::services::audit_writer::AuditWriter::generate_nonce();
    let response = state
        .runtime_client
        .execute_capsule(capsule.clone(), input_json.clone(), nonce.clone())
        .await
        .map_err(|e| AppError::Internal(format!("Capsule execution failed: {e}")))?;

    // 6. Verify decision
    let decision = response
        .decision
        .ok_or_else(|| AppError::Internal("No decision returned from capsule".into()))?;

    if !decision.allow {
        return Err(AppError::Forbidden(format!(
            "Admin login denied: {}",
            decision.reason
        )));
    }

    // 7. Generate decision reference and store attestation
    let decision_ref = shared_types::id_generator::generate_id("dec_admin");

    if let Some(attestation) = response.attestation {
        state
            .audit_writer
            .store_attestation(StoreAttestationParams {
                decision_ref: &decision_ref,
                capsule: &capsule,
                decision: &decision,
                attestation,
                nonce: &nonce,
                action: "admin_login",
                capsule_version: "admin_login_capsule_v1",
                tenant_id: &tenant_id,
                user_id: Some(&user.id),
            })?;
    }

    // 8. Create admin session with decision_ref (EIAA-compliant)
    let session_id = shared_types::id_generator::generate_id("sess_admin");

    // Admin sessions start at AAL1 with password verification (provisional —
    // step-up to AAL2 required before access is granted by EIAA middleware).
    let aal_level: i16 = 1;
    let verified_capabilities = serde_json::json!(["password"]);

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, expires_at, tenant_id, session_type, decision_ref, aal_level, verified_capabilities, is_provisional)
        VALUES ($1, $2, NOW() + INTERVAL '15 minutes', $3, 'admin', $4, $5, $6, true)
        "#
    )
    .bind(&session_id)
    .bind(&user.id)
    .bind(&tenant_id)
    .bind(&decision_ref)
    .bind(aal_level)
    .bind(&verified_capabilities)
    .execute(&state.db)
    .await?;

    // 9. Issue EIAA-compliant Admin JWT (identity only)
    let token = state.jwt_service.generate_token(
        &user.id,
        &session_id,
        &tenant_id,
        auth_core::jwt::session_types::ADMIN,
    )?;

    let user_res = state.user_service.to_user_response(&user).await?;

    tracing::info!(
        user_id = %user.id,
        decision_ref = %decision_ref,
        "Admin login successful via EIAA capsule"
    );

    // Risk Stabilization: Successful admin login (AAL1) feeds back into risk engine
    state
        .risk_engine
        .on_successful_auth(&user.id, shared_types::AssuranceLevel::AAL1)
        .await;

    // Audit: successful admin login
    state.audit_event_service.record(RecordEventParams {
        tenant_id: tenant_id.clone(),
        event_type: event_types::ADMIN_LOGIN_SUCCESS,
        actor_id: Some(user.id.clone()),
        actor_email: Some(req.email.clone()),
        target_type: Some("session"),
        target_id: Some(session_id.clone()),
        ip_address: Some(remote_ip),
        user_agent: Some(user_agent.clone()),
        metadata: serde_json::json!({"decision_ref": decision_ref, "session_type": "admin", "risk_score": risk_score}),
    }).await;

    // Compute step-up requirement from risk score (admin band).
    // Risk denial above threshold is already handled earlier; here we map
    // the residual score to AAL2 (default) or AAL3 (elevated).
    let required_aal = match derive_required_aal(risk_score, true) {
        AalRequirement::Required(level) => level.as_i16(),
        // Should be unreachable since risk > deny threshold returns early,
        // but fall back to AAL3 defensively.
        AalRequirement::Deny => shared_types::AssuranceLevel::AAL3.as_i16(),
    };

    Ok(Json(LoginResponse {
        token,
        user: user_res,
        organization_id: tenant_id,
        decision_ref,
        requirement: StepUpRequirement {
            required_aal,
            acceptable_factors: vec!["totp"],
            provisional: true,
        },
    }))
}

// --- Helper Functions ---

async fn build_admin_login_policy_ast(
    tenant_id: &str,
    db: &sqlx::PgPool,
) -> Result<(Program, i32)> {
    // Try to fetch custom admin policy for this tenant
    let row: Option<(i32, serde_json::Value)> = sqlx::query_as(
        "SELECT version, spec FROM eiaa_policies WHERE tenant_id = $1 AND action = 'auth:admin_login' ORDER BY version DESC LIMIT 1"
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await?;

    if let Some((version, json)) = row {
        if let Ok(program) = serde_json::from_value::<Program>(json) {
            return Ok((program, version));
        }
    }

    // Default admin policy: verify identity, allow (admin validation would be checked via role/membership in production)
    Ok((
        Program {
            version: "EIAA-AST-1.0".to_string(),
            sequence: vec![
                Step::VerifyIdentity {
                    source: IdentitySource::Primary,
                },
                Step::AuthorizeAction {
                    action: "auth:admin_login".to_string(),
                    resource: tenant_id.to_string(),
                },
                Step::Allow(true),
            ],
        },
        0,
    ))
}

async fn compile_admin_policy(
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
        "auth:admin_login".to_string(),
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
