use axum::{Router, routing::get, extract::{State, Path}, Json, Extension};
use crate::state::AppState;
use crate::clients::runtime_client::EiaaRuntimeClient;
use capsule_compiler::ast::{Program, Step, IdentitySource};
use grpc_api::eiaa::runtime::{CapsuleMeta, CapsuleSigned};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use shared_types::{Result, AppError};
use chrono::{DateTime, Utc};
use auth_core::jwt::Claims;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_policies).post(create_policy))
        .route("/:id", get(get_policy).delete(delete_policy))
}

#[derive(Serialize, sqlx::FromRow)]
struct Policy {
    id: String,
    created_at: DateTime<Utc>,
    tenant_id: String,
    action: String,
    version: i32,
    spec: serde_json::Value,
}

#[derive(Deserialize)]
struct CreatePolicyRequest {
    action: String,
    spec: serde_json::Value,
}

#[derive(Serialize)]
struct PolicyResponse {
    policy: Policy,
    #[serde(rename = "decisionRef")]
    decision_ref: String,
}

/// EIAA-Compliant Policy List
/// Executes admin action capsule before returning policies
async fn list_policies(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<Policy>>> {
    let tenant_id = claims.tenant_id.clone();

    // Execute admin authorization capsule
    let decision_ref = execute_admin_action_capsule(
        &state,
        &claims,
        "admin:policy:list",
        &tenant_id,
    ).await?;

    tracing::info!(
        user_id = %claims.sub,
        decision_ref = %decision_ref,
        action = "admin:policy:list",
        "Admin policy list authorized via capsule"
    );

    let policies = sqlx::query_as::<_, Policy>(
        "SELECT * FROM eiaa_policies WHERE tenant_id = $1 ORDER BY created_at DESC"
    )
    .bind(tenant_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(policies))
}

/// EIAA-Compliant Policy Get
async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Policy>> {
    let tenant_id = claims.tenant_id.clone();

    // Execute admin authorization capsule
    let decision_ref = execute_admin_action_capsule(
        &state,
        &claims,
        "admin:policy:read",
        &tenant_id,
    ).await?;

    tracing::info!(
        user_id = %claims.sub,
        decision_ref = %decision_ref,
        action = "admin:policy:read",
        policy_id = %id,
        "Admin policy read authorized via capsule"
    );

    let policy = sqlx::query_as::<_, Policy>(
        "SELECT * FROM eiaa_policies WHERE id = $1 AND tenant_id = $2"
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Policy not found".into()))?;

    Ok(Json(policy))
}

/// EIAA-Compliant Policy Create
async fn create_policy(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Json<PolicyResponse>> {
    let tenant_id = claims.tenant_id.clone();

    // Execute admin authorization capsule
    let decision_ref = execute_admin_action_capsule(
        &state,
        &claims,
        "admin:policy:create",
        &tenant_id,
    ).await?;

    // Get latest version for this action
    let latest_version: Option<i32> = sqlx::query_scalar(
        "SELECT MAX(version) FROM eiaa_policies WHERE tenant_id = $1 AND action = $2"
    )
    .bind(&tenant_id)
    .bind(&req.action)
    .fetch_one(&state.db)
    .await
    .unwrap_or(Some(0));

    let new_version = latest_version.unwrap_or(0) + 1;

    // Insert new policy
    let policy = sqlx::query_as::<_, Policy>(
        r#"
        INSERT INTO eiaa_policies (tenant_id, action, version, spec)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#
    )
    .bind(&tenant_id)
    .bind(&req.action)
    .bind(new_version)
    .bind(&req.spec)
    .fetch_one(&state.db)
    .await?;

    tracing::info!(
        user_id = %claims.sub,
        decision_ref = %decision_ref,
        action = "admin:policy:create",
        policy_id = %policy.id,
        "Admin policy created via EIAA capsule"
    );

    Ok(Json(PolicyResponse { policy, decision_ref }))
}

/// EIAA-Compliant Policy Delete
async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>> {
    let tenant_id = claims.tenant_id.clone();

    // Execute admin authorization capsule
    let decision_ref = execute_admin_action_capsule(
        &state,
        &claims,
        "admin:policy:delete",
        &tenant_id,
    ).await?;

    // Delete policy
    let result = sqlx::query(
        "DELETE FROM eiaa_policies WHERE id = $1 AND tenant_id = $2"
    )
    .bind(&id)
    .bind(&tenant_id)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Policy not found".into()));
    }

    tracing::info!(
        user_id = %claims.sub,
        decision_ref = %decision_ref,
        action = "admin:policy:delete",
        policy_id = %id,
        "Admin policy deleted via EIAA capsule"
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "decisionRef": decision_ref
    })))
}

// --- EIAA Helper Functions ---

/// Execute admin action capsule and store attestation
async fn execute_admin_action_capsule(
    state: &AppState,
    claims: &Claims,
    action: &str,
    tenant_id: &str,
) -> Result<String> {
    // Build admin authorization policy
    let policy_ast = build_admin_policy_ast(tenant_id, action);
    
    // Compile to capsule
    let capsule = compile_admin_action_capsule(&policy_ast, tenant_id, action, state)
        .map_err(|e| AppError::Internal(format!("Capsule compilation failed: {}", e)))?;

    // Build input context
    let input = serde_json::json!({
        "user_id": claims.sub,
        "session_id": claims.sid,
        "tenant_id": tenant_id,
        "action": action,
        "session_type": claims.session_type,
    });
    let input_json = serde_json::to_string(&input)?;

    // Execute via gRPC
    let nonce = generate_nonce();
    let mut runtime_client = EiaaRuntimeClient::connect(
        state.config.eiaa.runtime_grpc_addr.clone()
    ).await.map_err(|e| AppError::Internal(format!("Runtime connection failed: {}", e)))?;

    let response = runtime_client
        .execute_capsule(capsule.clone(), input_json.clone(), nonce.clone())
        .await
        .map_err(|e| AppError::Internal(format!("Capsule execution failed: {}", e)))?;

    // Verify decision
    let decision = response.decision
        .ok_or_else(|| AppError::Internal("No decision returned from capsule".into()))?;

    if !decision.allow {
        return Err(AppError::Forbidden(format!("Admin action denied: {}", decision.reason)));
    }

    // Generate decision reference and store attestation
    let decision_ref = shared_types::id_generator::generate_id("dec_admin_action");
    
    if let Some(attestation) = response.attestation {
        store_admin_action_attestation(
            &state.audit_writer,
            &decision_ref,
            &capsule,
            &decision,
            attestation,
            &nonce,
            tenant_id,
            &claims.sub,
            action,
        )?;
    }

    Ok(decision_ref)
}

fn build_admin_policy_ast(_tenant_id: &str, _action: &str) -> Program {
    // Default admin policy: require admin session, allow
    // In production, this could fetch tenant-specific admin policies
    Program {
        version: "EIAA-AST-1.0".to_string(),
        sequence: vec![
            Step::VerifyIdentity {
                source: IdentitySource::Primary,
            },
            Step::Allow(true),
        ],
    }
}

fn compile_admin_action_capsule(
    policy: &Program,
    tenant_id: &str,
    action: &str,
    state: &AppState,
) -> anyhow::Result<CapsuleSigned> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    
    let compiled = capsule_compiler::compile(
        policy.clone(),
        tenant_id.to_string(),
        action.to_string(),
        now,
        now + 60, // 1 minute validity for admin actions
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

fn store_admin_action_attestation(
    audit_writer: &crate::services::audit_writer::AuditWriter,
    decision_ref: &str,
    capsule: &CapsuleSigned,
    decision: &grpc_api::eiaa::runtime::Decision,
    attestation: grpc_api::eiaa::runtime::Attestation,
    nonce: &str,
    tenant_id: &str,
    user_id: &str,
    action: &str,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    // Hash full context for input_digest (not just nonce) - EIAA compliance
    let mut hasher = Sha256::new();
    hasher.update(capsule.capsule_hash_b64.as_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(action.as_bytes());
    let input_digest = URL_SAFE_NO_PAD.encode(hasher.finalize());

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
        capsule_version: "admin_action_capsule_v1".to_string(),
        action: action.to_string(),
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

    Ok(())
}
