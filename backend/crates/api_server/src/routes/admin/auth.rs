use axum::{Router, routing::post, extract::State, Json};
use crate::state::AppState;
// GAP-1 FIX: Use SharedRuntimeClient from AppState instead of per-request connect
use capsule_compiler::ast::{Program, Step, IdentitySource};
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};
use serde::{Deserialize, Serialize};
use shared_types::{AppError, Result};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user: identity_engine::models::UserResponse,
    organization_id: String,
    #[serde(rename = "decisionRef")]
    decision_ref: String, // EIAA audit reference
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
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // 1. Authenticate against DB
    let user = state.user_service.get_user_by_email(&req.email).await
        .map_err(|_| AppError::Unauthorized("Invalid credentials".into()))?;

    let valid = state.user_service.verify_user_password(&user.id, &req.password).await?;
    if !valid {
        return Err(AppError::Unauthorized("Invalid credentials".into()));
    }

    // 2 & 3. Resolve capsule: Redis cache -> compile fallback -> write-back
    // Admin login is typically for the "platform" tenant or specific system tenant
    let tenant_id = "platform".to_string(); 
    let cache = &state.capsule_cache;
    let capsule_action = "auth:admin_login";

    let (capsule, from_cache, policy_version) = if let Some(cached) = cache.get(&tenant_id, capsule_action).await {
        use prost::Message;
        match grpc_api::eiaa::runtime::CapsuleSigned::decode(cached.capsule_bytes.as_slice()) {
            Ok(c) => (c, true, cached.version),
            Err(_) => {
                tracing::warn!("Failed to decode cached capsule for {}, recompiling", capsule_action);
                let (ast, ver) = build_admin_login_policy_ast(&tenant_id, &state.db).await?;
                let c = compile_admin_policy(&ast, &tenant_id, &state).await
                    .map_err(|e| AppError::Internal(format!("Capsule compilation failed: {e}")))?;
                (c, false, ver)
            }
        }
    } else {
        tracing::debug!("No capsule cached for action '{}', compiling fallback policy", capsule_action);
        let (ast, ver) = build_admin_login_policy_ast(&tenant_id, &state.db).await?;
        let c = compile_admin_policy(&ast, &tenant_id, &state).await
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


    // 4. Build input context
    let input = serde_json::json!({
        // RuntimeContext required fields
        "subject_id": 1, // Placeholder until ID is integer mapped
        "risk_score": 0,
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
    let response = state.runtime_client
        .execute_capsule(capsule.clone(), input_json.clone(), nonce.clone())
        .await
        .map_err(|e| AppError::Internal(format!("Capsule execution failed: {e}")))?;

    // 6. Verify decision
    let decision = response.decision
        .ok_or_else(|| AppError::Internal("No decision returned from capsule".into()))?;

    if !decision.allow {
        return Err(AppError::Forbidden(format!("Admin login denied: {}", decision.reason)));
    }

    // 7. Generate decision reference and store attestation
    let decision_ref = shared_types::id_generator::generate_id("dec_admin");
    
    if let Some(attestation) = response.attestation {
        state.audit_writer.store_attestation(
            &decision_ref,
            &capsule,
            &decision,
            attestation,
            &nonce,
            "admin_login",
            "admin_login_capsule_v1",
            &tenant_id,
            Some(&user.id),
        )?;
    }

    // 8. Create admin session with decision_ref (EIAA-compliant)
    let session_id = shared_types::id_generator::generate_id("sess_admin");
    
    // Admin sessions start at AAL1 with password verification
    let assurance_level = "aal1";
    let verified_capabilities = serde_json::json!(["password"]);
    
    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, expires_at, tenant_id, session_type, decision_ref, assurance_level, verified_capabilities, is_provisional)
        VALUES ($1, $2, NOW() + INTERVAL '15 minutes', $3, 'admin', $4, $5, $6, false)
        "#
    )
    .bind(&session_id)
    .bind(&user.id)
    .bind(&tenant_id)
    .bind(&decision_ref)
    .bind(assurance_level)
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

    Ok(Json(LoginResponse {
        token,
        user: user_res,
        organization_id: tenant_id,
        decision_ref,
    }))
}

// --- Helper Functions ---

async fn build_admin_login_policy_ast(tenant_id: &str, db: &sqlx::PgPool) -> Result<(Program, i32)> {
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
    Ok((Program {
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
    }, 0))
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



